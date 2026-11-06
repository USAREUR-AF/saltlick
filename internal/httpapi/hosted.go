package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"

	"github.com/usareur-af/saltlick/internal/pkgv1"
	"github.com/usareur-af/saltlick/internal/store"
	"github.com/usareur-af/saltlick/internal/writeauth"
)

// Hosted files. A party with no public host of its own keeps its signed
// federation package and its CA certificate here, beside its entry, so that it
// can federate from behind NAT without sending files to anyone.
//
// The rules, in the order they are applied:
//
//  1. The body is read under the same 64 KiB cap as an entry, and checked for
//     what it is: a package is a federation-package/v1 document in canonical
//     form whose sovereign_id is the path's; a CA upload is PEM CERTIFICATE
//     blocks, each an X.509 CA certificate.
//  2. An entry must already exist. The entry's first publish is what binds the
//     key; a file never claims a name.
//  3. The presented key must be the entry's bound key, and the request
//     signature must verify under it. A key is rotated through the entry, never
//     through a file.
//  4. A package's own signature must verify under the bound key, so the package
//     served here and the key advertised for it go together.
//
// A hosted package is not compared with the entry's package_sha256. The pointer
// and the package are written in two requests, and the reader recomputes the
// digest whatever the directory did. A hosted CA is not compared with the
// package's ca_fingerprint, for the same reason: the reader makes that check.
//
// Neither file is read into the listing or the home page beyond a link. A
// package hosted here carries whatever its party chose to put in it, offers
// included; it is served as the party's own host would serve it, and the
// directory takes nothing from it.

// contentType is what each kind of hosted file is served as.
var contentType = map[string]string{
	store.KindPackage: "application/json",
	store.KindCA:      "application/pem-certificate-chain",
}

func (s *Server) getHosted(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("sovereign_id")
		e, err := s.store.Get(r.Context(), id)
		if errors.Is(err, store.ErrNotFound) {
			s.writeError(w, http.StatusNotFound, "no entry for sovereign_id %q", id)
			return
		}
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "reading entry: %v", err)
			return
		}
		b, err := s.store.GetFile(r.Context(), id, kind)
		if errors.Is(err, store.ErrNoFile) {
			s.writeError(w, http.StatusNotFound, "%q hosts no %s here", id, kind)
			return
		}
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "reading %s: %v", kind, err)
			return
		}
		w.Header().Set("Content-Type", contentType[kind])
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set(HeaderBoundKey, e.BoundKey)
		w.Header().Set(HeaderAdvisory, Advisory)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(b) // byte-for-byte
	}
}

func (s *Server) putHosted(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("sovereign_id")

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
		switch kind {
		case store.KindPackage:
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
		case store.KindCA:
			fps, err := pkgv1.ParseCA(body)
			if err != nil {
				s.writeError(w, http.StatusUnprocessableEntity, "%v", err)
				return
			}
			resp["certificates"] = fps
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

		replaced, err := s.store.PutFile(r.Context(), id, kind, body, s.now())
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
