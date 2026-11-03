// Package httpapi serves the directory over HTTP.
//
// # The invariant, which governs every handler below
//
// Advisory, never authoritative. Being listed grants access to nothing.
//
// This service's only job is to stop two competent parties from misconfiguring
// each other before they build a link. It is not a trust root, not an
// authorisation source, and not a party to any agreement.
//
// # Before you add an endpoint
//
// Two shapes of feature are permanently out of scope here, and the reason is
// the same for both: each would make some party's decision depend on this
// server being right, and federation must work with this server switched off.
//
//  1. Anything that RANKS, MATCHES, SCORES or RECOMMENDS parties. No
//     /compatible, no /suggested-peers, no "these two could federate" filter,
//     no sort by capability. The directory never knows who peers with whom, and
//     must not learn: a query that returns "parties compatible with xaa" makes
//     the operator of this box a broker, and the answer it gives becomes an
//     input to somebody's decision. Two parties decide to federate by talking to
//     each other. They then compose independently, with the same versioned tool,
//     and compare one digest -- a mechanism that needs no server at all and
//     works with an entirely offline partner.
//
//  2. Anything that ENFORCES, GATES or ATTESTS. No refusing to serve an expired
//     package, no "verified" flag, no approval workflow, no accounts or roles,
//     no federation between directory instances. Every feature request of the
//     form "could the directory also check X" is a request to make it
//     load-bearing, and the answer is no.
//
// If you are here because a user asked for one of those, the thing they want is
// a conversation between two parties, or a check inside the composing tool. It
// is not an endpoint on this server.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/usareur-af/saltlick/internal/pkgv1"
	"github.com/usareur-af/saltlick/internal/store"
	"github.com/usareur-af/saltlick/internal/writeauth"
)

// Advisory is repeated on every response this server sends. It is in the wire
// format and not only in the documentation, because documentation is what gets
// dropped when an integrator copies a response into their own system.
const Advisory = "advisory only: being listed in this directory grants access to nothing, " +
	"and this service does not establish that any party is who it claims to be"

// Headers the API defines.
const (
	HeaderKey       = "X-Saltlick-Key"       // base64 raw Ed25519 verifying key, 44 chars
	HeaderSignature = "X-Saltlick-Signature" // base64 Ed25519 signature over the request statement, 88 chars
	HeaderExpired   = "X-Saltlick-Expired"   // reported on GET, never enforced
	HeaderBoundKey  = "X-Saltlick-Bound-Key"
	HeaderIssued    = "X-Saltlick-Issued"
	HeaderExpires   = "X-Saltlick-Expires"
	HeaderAdvisory  = "X-Saltlick-Advisory"
)

// maxBodyBytes bounds a submission. A directory entry is on the order of a
// kilobyte; this is generous by two orders of magnitude.
const maxBodyBytes = 64 << 10

// Server is the directory's HTTP surface.
type Server struct {
	store *store.Store
	log   *slog.Logger
	// now is injected so tests can serve an expired entry without waiting.
	now func() time.Time
}

// New builds a Server. now may be nil, in which case time.Now is used.
func New(st *store.Store, log *slog.Logger, now func() time.Time) *Server {
	if now == nil {
		now = time.Now
	}
	if log == nil {
		log = slog.Default()
	}
	return &Server{store: st, log: log, now: now}
}

// Handler returns the routed handler.
//
// This is the whole API. If you are adding a route, read the package comment
// above first -- in particular the two shapes of endpoint that are permanently
// out of scope.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /v1/spec", s.spec)
	mux.HandleFunc("GET /v1/parties", s.list)
	mux.HandleFunc("GET /v1/parties/{sovereign_id}", s.get)
	mux.HandleFunc("PUT /v1/parties/{sovereign_id}", s.put)
	mux.HandleFunc("DELETE /v1/parties/{sovereign_id}", s.delete)
	return mux
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

// spec reports which package spec version this instance accepts. A package
// written for another lineage is refused unread, in either direction.
func (s *Server) spec(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]any{
		"spec":            pkgv1.SpecVersion,
		"request_version": writeauth.StatementVersion,
	})
}

type listItem struct {
	SovereignID string `json:"sovereign_id"`
	Issued      string `json:"issued"`
	Expires     string `json:"expires"`
	Expired     bool   `json:"expired"`
	BoundKey    string `json:"bound_key"`
}

// list is a catalogue and nothing more. It has no filters, no sort parameter
// and no query by capability, because each of those is a step towards answering
// "who should I federate with", which is not this server's question to answer.
func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	entries, err := s.store.List(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "listing entries: %v", err)
		return
	}
	today := s.today()
	items := make([]listItem, 0, len(entries))
	for _, e := range entries {
		items = append(items, listItem{
			SovereignID: e.SovereignID,
			Issued:      e.Issued,
			Expires:     e.Expires,
			Expired:     e.Expires < today,
			BoundKey:    e.BoundKey,
		})
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"spec":    pkgv1.SpecVersion,
		"parties": items,
	})
}

// get returns the stored package bytes unaltered.
//
// The body is the submitted bytes and nothing else: not re-serialised, not
// re-ordered, not pretty-printed, not wrapped in an envelope. A consumer must be
// able to verify a signature over exactly what was signed, and every one of
// those transformations would break that. All directory metadata -- expiry, the
// bound key -- travels in headers for that reason.
func (s *Server) get(w http.ResponseWriter, r *http.Request) {
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

	// Expiry is reported, not enforced. An expired package is still served,
	// flagged. Refusing to serve it would be the directory deciding something
	// for the consumer, and advisory means the consumer decides.
	expired := e.Expires < s.today()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(HeaderExpired, fmt.Sprintf("%t", expired))
	w.Header().Set(HeaderBoundKey, e.BoundKey)
	w.Header().Set(HeaderIssued, e.Issued)
	w.Header().Set(HeaderExpires, e.Expires)
	w.Header().Set(HeaderAdvisory, Advisory)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(e.Package) // byte-for-byte
}

func (s *Server) put(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("sovereign_id")

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
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

	// Parse before authorising, so a submission carrying an offer block is
	// refused as what it is rather than as a signature problem.
	pkg, err := pkgv1.Parse(body)
	if err != nil {
		s.writeError(w, http.StatusUnprocessableEntity, "%v", err)
		return
	}
	if pkg.SovereignID != id {
		s.writeError(w, http.StatusUnprocessableEntity,
			"package sovereign_id %q does not match the path %q", pkg.SovereignID, id)
		return
	}

	statement := writeauth.Statement(http.MethodPut, id, body, presentedKeyB64)

	// The read, the decision and the write are one critical section: the
	// trust-on-first-use rule is only a rule if two concurrent first publishes
	// for the same sovereign_id cannot both see an unbound entry.
	s.store.Lock()
	defer s.store.Unlock()

	existing, err := s.store.Get(r.Context(), id)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.writeError(w, http.StatusInternalServerError, "reading entry: %v", err)
		return
	}
	boundKey := ""
	if existing != nil {
		boundKey = existing.BoundKey
	}

	decision, err := writeauth.AuthorisePut(boundKey, presentedKey, statement, requestSig)
	if err != nil {
		var refusal *writeauth.Refusal
		if errors.As(err, &refusal) {
			s.writeError(w, http.StatusForbidden, "%s", refusal.Reason)
			return
		}
		s.writeError(w, http.StatusBadRequest, "%v", err)
		return
	}

	// The stored entry must verify under the key the directory will advertise
	// for it, or a reader who fetches both gets a package and a key that do not
	// go together.
	if err := pkg.VerifySignature(decision.KeyToBind); err != nil {
		s.writeError(w, http.StatusForbidden, "package signature: %v", err)
		return
	}

	now := s.now()
	entry := &store.Entry{
		SovereignID: pkg.SovereignID,
		Package:     body, // stored exactly as received
		BoundKey:    pkgv1.EncodeVerifyingKey(decision.KeyToBind),
		Issued:      pkg.Issued,
		Expires:     pkg.Expires,
	}
	if err := s.store.Put(r.Context(), entry, now); err != nil {
		s.writeError(w, http.StatusInternalServerError, "storing entry: %v", err)
		return
	}

	status := http.StatusOK
	switch {
	case decision.FirstUse:
		status = http.StatusCreated
		_ = s.store.AppendLog(r.Context(), "bind", id,
			"first publish bound key "+entry.BoundKey+" (trust on first use; authenticates nobody)", now)
	case decision.Rotation:
		// Logged so that a directory compromise is detectable after the fact.
		// This does not make the directory the source of the binding.
		_ = s.store.AppendLog(r.Context(), "rotate", id,
			"bound key replaced "+boundKey+" -> "+entry.BoundKey+", authorised by a signature under the key replaced", now)
	}

	s.writeJSON(w, status, map[string]any{
		"sovereign_id": pkg.SovereignID,
		"issued":       pkg.Issued,
		"expires":      pkg.Expires,
		"expired":      pkg.IsExpired(now),
		"bound_key":    entry.BoundKey,
		"first_use":    decision.FirstUse,
		"rotated":      decision.Rotation,
	})
}

func (s *Server) delete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("sovereign_id")
	requestSig, err := decodeSig(r.Header.Get(HeaderSignature))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "%s: %v", HeaderSignature, err)
		return
	}

	s.store.Lock()
	defer s.store.Unlock()

	existing, err := s.store.Get(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.writeError(w, http.StatusNotFound, "no entry for sovereign_id %q", id)
		return
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "reading entry: %v", err)
		return
	}

	statement := writeauth.Statement(http.MethodDelete, id, nil, "")
	if err := writeauth.AuthoriseDelete(existing.BoundKey, statement, requestSig); err != nil {
		var refusal *writeauth.Refusal
		if errors.As(err, &refusal) {
			s.writeError(w, http.StatusForbidden, "%s", refusal.Reason)
			return
		}
		s.writeError(w, http.StatusBadRequest, "%v", err)
		return
	}
	if err := s.store.Delete(r.Context(), id); err != nil {
		s.writeError(w, http.StatusInternalServerError, "deleting entry: %v", err)
		return
	}
	w.Header().Set(HeaderAdvisory, Advisory)
	w.WriteHeader(http.StatusNoContent)
}

// today is the current date in UTC. Never the local date of whoever happens to
// be running this server: the packages carry dates and no times precisely to
// take clock skew out, and a local date would put it back.
func (s *Server) today() string { return s.now().UTC().Format("2006-01-02") }

func decodeSig(h string) ([]byte, error) {
	if h == "" {
		return nil, fmt.Errorf("header is required on a write")
	}
	return pkgv1.DecodeSignature(h)
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, body map[string]any) {
	body["advisory"] = Advisory
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(HeaderAdvisory, Advisory)
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(body); err != nil {
		s.log.Error("writing response", "err", err)
	}
}

func (s *Server) writeError(w http.ResponseWriter, status int, format string, args ...any) {
	s.writeJSON(w, status, map[string]any{"error": fmt.Sprintf(format, args...)})
}

// Serve runs the server until ctx is cancelled.
func Serve(ctx context.Context, addr string, h http.Handler, log *slog.Logger) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	errc := make(chan error, 1)
	go func() {
		log.Info("saltlick listening", "addr", addr, "spec", pkgv1.SpecVersion)
		errc <- srv.ListenAndServe()
	}()
	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}
