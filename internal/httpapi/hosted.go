package httpapi

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/usareur-af/saltlick/internal/pkgv1"
	"github.com/usareur-af/saltlick/internal/store"
	"github.com/usareur-af/saltlick/internal/writeauth"
)

// Hosted files. A party with no public host of its own keeps its signed
// federation package, its CA certificate and its SPIFFE trust bundle here,
// beside its entry, so that it can federate from behind NAT without sending
// files to anyone. A party holding several peerings also keeps one package per
// counterparty at packages/<counterparty>: each peering's package carries its
// own transport offer (endpoint, WireGuard key, link subnet), so one peering's
// upload never replaces another's. A counterparty package is checked exactly
// as the single package is, and its upload signature names the counterparty in
// its resource line.
//
// The rules, in the order they are applied:
//
//  1. The body is read under the same 64 KiB cap as an entry, and checked for
//     what it is: a package is a federation-package/v1 document in canonical
//     form whose sovereign_id is the path's; a CA upload is PEM CERTIFICATE
//     blocks, each an X.509 CA certificate; a SPIFFE bundle is a JWKS document
//     whose keys are x509-svid keys with a parseable x5c certificate or
//     jwt-svid keys.
//  2. An entry must already exist. The entry's first publish is what binds the
//     key; a file never claims a name.
//  3. The presented key must be the entry's bound key, and the request
//     signature must verify under it. A key is rotated through the entry, never
//     through a file.
//  4. A package's own signature must verify under the bound key, so the package
//     served here and the key advertised for it go together.
//  5. A counterparty package's upload must not be one that was withdrawn: the
//     signature of every withdrawn counterparty upload is kept and refused.
//
// A hosted package is not compared with the entry's package_sha256. The pointer
// and the package are written in two requests, and the reader recomputes the
// digest whatever the directory did. A hosted CA is not compared with the
// package's ca_fingerprint, for the same reason: the reader makes that check.
//
// Each file is stored with the X-Saltlick-Key value and the request signature
// that wrote it, and GET serves both as headers. The request statement is
// rebuilt by a reader from the method (PUT), the resource (<id>/<kind>), the
// SHA-256 of the bytes served and that key, so a reader can check any hosted
// file against the key the two parties read aloud, including the SPIFFE bundle,
// which nothing in the signed package names.
//
// No file is read into the listing or the home page beyond a link. A
// package hosted here carries whatever its party chose to put in it, offers
// included; it is served as the party's own host would serve it, and the
// directory takes nothing from it.

// contentType is what each kind of hosted file is served as.
var contentType = map[string]string{
	store.KindPackage:      "application/json",
	store.KindCA:           "application/pem-certificate-chain",
	store.KindSPIFFEBundle: "application/json",
}

// Headers a GET of a hosted file carries, beside X-Saltlick-Bound-Key.
const (
	// HeaderWriterKey is the X-Saltlick-Key value the upload presented, exactly
	// as presented. It is the bound key at the time of the upload; after a
	// rotation it differs from X-Saltlick-Bound-Key until the file is uploaded
	// again.
	HeaderWriterKey = HeaderKey
	// HeaderWriterSignature is the upload's request signature, base64.
	HeaderWriterSignature = HeaderSignature
	// HeaderResource is the resource line of the request statement the
	// signature covers: <sovereign_id>/<kind>, where a counterparty package's
	// kind is packages/<counterparty>.
	HeaderResource = "X-Saltlick-Resource"
)

// kindOf names the hosted kind a request addresses, or refuses the path. The
// three single kinds are fixed per route; a counterparty package's kind comes
// from the path.
type kindOf func(r *http.Request) (kind string, err error)

func fixedKind(kind string) kindOf {
	return func(*http.Request) (string, error) { return kind, nil }
}

// packageForCounterparty is the kind of /v1/parties/{sovereign_id}/packages/{counterparty}.
// The counterparty has the form of a sovereign_id and is not the party itself:
// composition refuses two packages with one sovereign_id, so a slot for oneself
// can only ever hold a mistake. The directory does not interpret the name
// further, does not check that the counterparty has an entry, and does not list
// the slots in its catalogue.
func packageForCounterparty(r *http.Request) (string, error) {
	id, cp := r.PathValue("sovereign_id"), r.PathValue("counterparty")
	if !pkgv1.ValidSovereignID(cp) {
		return "", fmt.Errorf("counterparty %q is not 2-16 characters of lowercase a-z0-9-", cp)
	}
	if cp == id {
		return "", fmt.Errorf("counterparty %q is the party itself; a package is never composed with its own party", cp)
	}
	return store.KindPackageFor(cp), nil
}

// isPackage reports whether kind holds a signed federation package: the single
// package or one counterparty's.
func isPackage(kind string) bool {
	return kind == store.KindPackage || strings.HasPrefix(kind, "packages/")
}

func contentTypeOf(kind string) string {
	if isPackage(kind) {
		return contentType[store.KindPackage]
	}
	return contentType[kind]
}

func (s *Server) getHosted(kindFor kindOf) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("sovereign_id")
		kind, err := kindFor(r)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, "%v", err)
			return
		}
		e, err := s.store.Get(r.Context(), id)
		if errors.Is(err, store.ErrNotFound) {
			s.writeError(w, http.StatusNotFound, "no entry for sovereign_id %q", id)
			return
		}
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "reading entry: %v", err)
			return
		}
		f, err := s.store.GetFile(r.Context(), id, kind)
		if errors.Is(err, store.ErrNoFile) {
			s.writeError(w, http.StatusNotFound, "%q hosts no %s here", id, kind)
			return
		}
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "reading %s: %v", kind, err)
			return
		}
		w.Header().Set("Content-Type", contentTypeOf(kind))
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set(HeaderBoundKey, e.BoundKey)
		if f.Signature != "" {
			w.Header().Set(HeaderWriterKey, f.WriterKey)
			w.Header().Set(HeaderWriterSignature, f.Signature)
			w.Header().Set(HeaderResource, id+"/"+kind)
		}
		w.Header().Set(HeaderAdvisory, Advisory)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(f.Body) // byte-for-byte
	}
}

// deleteCounterpartyPackage withdraws one counterparty's package, so a party can
// withdraw a peering's offer when the peering ends without deleting its entry,
// its other packages, its CA or its key binding. The request is signed by the
// bound key over DELETE <sovereign_id>/packages/<counterparty>, the sha256 of
// the package being withdrawn (not of the empty request body), and no key line.
// Binding the withdrawn bytes keeps the statement from being replayed against a
// later package in the same slot. The withdrawn upload's signature is kept, and
// putHosted refuses it, so a saved GET (body, key and signature) cannot be
// replayed as a PUT to restore the package: a withdrawal is final.
func (s *Server) deleteCounterpartyPackage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("sovereign_id")
	kind, err := packageForCounterparty(r)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "%v", err)
		return
	}
	requestSig, err := decodeSig(r.Header.Get(HeaderSignature))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "%s: %v", HeaderSignature, err)
		return
	}

	s.store.Lock()
	defer s.store.Unlock()

	e, err := s.store.Get(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.writeError(w, http.StatusNotFound, "no entry for sovereign_id %q", id)
		return
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "reading entry: %v", err)
		return
	}
	f, err := s.store.GetFile(r.Context(), id, kind)
	if errors.Is(err, store.ErrNoFile) {
		s.writeError(w, http.StatusNotFound, "%q hosts no %s here", id, kind)
		return
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "reading %s: %v", kind, err)
		return
	}
	statement := writeauth.Statement(http.MethodDelete, id+"/"+kind, f.Body, "")
	if err := writeauth.AuthoriseDelete(e.BoundKey, statement, requestSig); err != nil {
		var refusal *writeauth.Refusal
		if errors.As(err, &refusal) {
			s.writeError(w, http.StatusForbidden, "%s", refusal.Reason)
			return
		}
		s.writeError(w, http.StatusBadRequest, "%v", err)
		return
	}
	if err := s.store.WithdrawFile(r.Context(), id, kind, s.now()); errors.Is(err, store.ErrNoFile) {
		s.writeError(w, http.StatusNotFound, "%q hosts no %s here", id, kind)
		return
	} else if err != nil {
		s.writeError(w, http.StatusInternalServerError, "deleting %s: %v", kind, err)
		return
	}
	w.Header().Set(HeaderAdvisory, Advisory)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) putHosted(kindFor kindOf) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("sovereign_id")
		kind, err := kindFor(r)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, "%v", err)
			return
		}

		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				s.writeError(w, http.StatusRequestEntityTooLarge, "body exceeds %d bytes", tooLarge.Limit)
				return
			}
			s.writeError(w, http.StatusBadRequest, "reading body: %v", err)
			return
		}

		presentedKeyB64 := r.Header.Get(HeaderKey)
		presentedKey, err := pkgv1.DecodeVerifyingKey(presentedKeyB64)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, "%s: %v", HeaderKey, err)
			return
		}
		requestSig, err := decodeSig(r.Header.Get(HeaderSignature))
		if err != nil {
			s.writeError(w, http.StatusBadRequest, "%s: %v", HeaderSignature, err)
			return
		}

		// 1. What the body is.
		var pkg *pkgv1.Package
		resp := map[string]any{"sovereign_id": id, "kind": kind}
		switch {
		case isPackage(kind):
			pkg, err = pkgv1.ParseHostedPackage(body)
			if err != nil {
				s.writeError(w, http.StatusUnprocessableEntity, "%v", err)
				return
			}
			if pkg.SovereignID != id {
				s.writeError(w, http.StatusUnprocessableEntity,
					"package sovereign_id %q does not match the path %q", pkg.SovereignID, id)
				return
			}
		case kind == store.KindCA:
			fps, err := pkgv1.ParseCA(body)
			if err != nil {
				s.writeError(w, http.StatusUnprocessableEntity, "%v", err)
				return
			}
			resp["certificates"] = fps
		case kind == store.KindSPIFFEBundle:
			b, err := pkgv1.ParseSPIFFEBundle(body)
			if err != nil {
				s.writeError(w, http.StatusUnprocessableEntity, "%v", err)
				return
			}
			resp["x509_authorities"] = b.X509Authorities
			resp["jwt_authorities"] = b.JWTAuthorities
		}

		s.store.Lock()
		defer s.store.Unlock()

		// 2. An entry exists.
		e, err := s.store.Get(r.Context(), id)
		if errors.Is(err, store.ErrNotFound) {
			s.writeError(w, http.StatusConflict,
				"no entry for sovereign_id %q: publish the entry first, which binds the key that signs this upload", id)
			return
		}
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "reading entry: %v", err)
			return
		}

		// 3. Signed by the bound key.
		statement := writeauth.Statement(http.MethodPut, id+"/"+kind, body, presentedKeyB64)
		if err := writeauth.AuthoriseHosted(e.BoundKey, presentedKey, statement, requestSig); err != nil {
			var refusal *writeauth.Refusal
			if errors.As(err, &refusal) {
				s.writeError(w, http.StatusForbidden, "%s", refusal.Reason)
				return
			}
			s.writeError(w, http.StatusBadRequest, "%v", err)
			return
		}

		// 4. A package verifies under the key advertised for it.
		if pkg != nil {
			if err := pkg.VerifySignature(presentedKey); err != nil {
				s.writeError(w, http.StatusForbidden, "package signature: %v", err)
				return
			}
		}

		// 5. A counterparty package that was withdrawn stays withdrawn: the upload
		// that stored it, replayed, is refused.
		if strings.HasPrefix(kind, "packages/") {
			gone, err := s.store.IsWithdrawn(r.Context(), base64.StdEncoding.EncodeToString(requestSig))
			if err != nil {
				s.writeError(w, http.StatusInternalServerError, "reading withdrawals: %v", err)
				return
			}
			if gone {
				s.writeError(w, http.StatusConflict,
					"this upload was withdrawn from %s/%s and is never stored again; sign and upload a new package", id, kind)
				return
			}
		}

		replaced, err := s.store.PutFile(r.Context(), id, kind, &store.HostedFile{
			Body:      body,
			WriterKey: presentedKeyB64,
			Signature: base64.StdEncoding.EncodeToString(requestSig),
		}, s.now())
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "storing %s: %v", kind, err)
			return
		}
		sum := sha256.Sum256(body)
		resp["sha256"] = "sha256:" + hex.EncodeToString(sum[:])
		resp["bytes"] = len(body)
		resp["replaced"] = replaced
		status := http.StatusCreated
		if replaced {
			status = http.StatusOK
		}
		s.writeJSON(w, status, resp)
	}
}
