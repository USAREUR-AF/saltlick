package httpapi_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/usareur-af/saltlick/internal/httpapi"
	"github.com/usareur-af/saltlick/internal/store"
	"github.com/usareur-af/saltlick/internal/testsupport"
	"github.com/usareur-af/saltlick/internal/writeauth"
)

// fixedNow keeps the tests off the wall clock: an entry is expired or not
// because the test said so, not because enough time passed.
var fixedNow = time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)

type harness struct {
	t     *testing.T
	srv   *httptest.Server
	store *store.Store
	now   time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "saltlick.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	h := &harness{t: t, store: st, now: fixedNow}
	api := httpapi.New(st, nil, func() time.Time { return h.now })
	h.srv = httptest.NewServer(api.Handler())
	t.Cleanup(h.srv.Close)
	return h
}

// put publishes body for sovereignID, signing the request statement with
// signingKey and presenting presentedKey. Splitting the two is what makes the
// rotation and overwrite cases expressible.
func (h *harness) put(sovereignID string, body []byte, presentedKey ed25519.PublicKey, signingKey ed25519.PrivateKey) *http.Response {
	h.t.Helper()
	presented := base64.StdEncoding.EncodeToString(presentedKey)
	stmt := statement(http.MethodPut, sovereignID, body, presented)
	req, err := http.NewRequest(http.MethodPut, h.srv.URL+"/v1/parties/"+sovereignID, bytes.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set(httpapi.HeaderKey, presented)
	req.Header.Set(httpapi.HeaderSignature, base64.StdEncoding.EncodeToString(ed25519.Sign(signingKey, stmt)))
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp
}

func (h *harness) publish(sovereignID string, k testsupport.Key, body []byte) *http.Response {
	h.t.Helper()
	return h.put(sovereignID, body, k.Pub, k.Priv)
}

func (h *harness) get(path string) *http.Response {
	h.t.Helper()
	resp, err := h.srv.Client().Get(h.srv.URL + path)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp
}

func (h *harness) delete(sovereignID string, signingKey ed25519.PrivateKey) *http.Response {
	h.t.Helper()
	stmt := statement(http.MethodDelete, sovereignID, nil, "")
	req, err := http.NewRequest(http.MethodDelete, h.srv.URL+"/v1/parties/"+sovereignID, nil)
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set(httpapi.HeaderSignature, base64.StdEncoding.EncodeToString(ed25519.Sign(signingKey, stmt)))
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp
}

// statement is writeauth.Statement, called rather than reimplemented, so a
// change to the format breaks compilation instead of leaving these tests
// exercising a format nobody uses.
func statement(method, id string, body []byte, presentedKey string) []byte {
	return writeauth.Statement(method, id, body, presentedKey)
}

func body(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func decode(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body(t, resp), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func mustStatus(t *testing.T, resp *http.Response, want int) {
	t.Helper()
	if resp.StatusCode != want {
		t.Fatalf("status = %d, want %d; body: %s", resp.StatusCode, want, body(t, resp))
	}
}

// ---------------------------------------------------------------------------
// 1. GET returns the submitted bytes byte-for-byte.
// ---------------------------------------------------------------------------

// TestGetReturnsSubmittedBytesByteForByte is the correctness point everything
// else rests on. A consumer verifies a signature over exactly what was signed,
// so re-serialising, re-ordering or pretty-printing the stored bytes destroys
// the entry's only useful property -- and does it silently, since the result is
// still valid JSON with the same members.
func TestGetReturnsSubmittedBytesByteForByte(t *testing.T) {
	h := newHarness(t)
	k := testsupport.NewKey(t, "byte-exact")

	// Deliberately not in canonical form: members in an order JCS would change,
	// and whitespace JCS would remove. The signature is over the canonical form
	// as the spec requires, but what is STORED and RETURNED is the submitted
	// document. A server that quietly canonicalised on the way in would pass a
	// test that submitted canonical bytes, and fail here.
	unsigned := `{
        "sovereign_id": "xaa",
        "spec": "federation-package/v1",
        "capabilities": {
            "transports": ["ipsec-fips", "wireguard"],
            "pqc_capable": true,
            "fabric_fips_image": true,
            "fabric_version": "1.9.0"
        },
        "expires": "2026-12-05",
        "issued": "2026-09-05",
        "identity": {
            "trust_domain": "spiffe://xaa.example",
            "ca_fingerprint": "sha256:d49211cac3357142f3cf9c2ee216cdd452793ce89428d5ea856f9f62e71efe55"
        }
    }`
	canonicalSigned := testsupport.Sign(t, k, unsigned)

	// Rebuild the submission in the awkward original order, with the signature
	// appended, so the stored bytes differ from the canonical form.
	var sig struct {
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(canonicalSigned, &sig); err != nil {
		t.Fatal(err)
	}
	submitted := []byte(strings.TrimSuffix(strings.TrimSpace(unsigned), "}") +
		",\n        \"signature\": \"" + sig.Signature + "\"\n    }")

	resp := h.publish("xaa", k, submitted)
	mustStatus(t, resp, http.StatusCreated)
	resp.Body.Close()

	got := body(t, h.get("/v1/parties/xaa"))
	if !bytes.Equal(got, submitted) {
		t.Fatalf("GET did not return the submitted bytes.\n got (%d bytes): %s\nwant (%d bytes): %s",
			len(got), got, len(submitted), submitted)
	}
	if bytes.Equal(got, canonicalSigned) {
		t.Fatal("GET returned the canonical form; the server re-serialised the stored bytes")
	}
}

// ---------------------------------------------------------------------------
// 2. TOFU: a second key must not overwrite another party's entry.
// ---------------------------------------------------------------------------

func TestFirstPublishBindsTheSuppliedKey(t *testing.T) {
	h := newHarness(t)
	k := testsupport.NewKey(t, "first-publish")
	raw := testsupport.SignedEntry(t, k, "xaa", "2026-09-05", "2026-12-05")

	resp := h.publish("xaa", k, raw)
	mustStatus(t, resp, http.StatusCreated)
	got := decode(t, resp)
	if got["bound_key"] != k.PubB64 {
		t.Fatalf("bound_key = %v, want %s", got["bound_key"], k.PubB64)
	}
	if got["first_use"] != true {
		t.Fatalf("first_use = %v, want true", got["first_use"])
	}

	// Binding is recorded, and recorded as what it is.
	logs, err := h.store.Log(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 1 || logs[0].Action != "bind" {
		t.Fatalf("admin log = %+v; want one bind entry", logs)
	}
	if !strings.Contains(logs[0].Detail, "authenticates nobody") {
		t.Errorf("the bind log entry must not read as a verification: %q", logs[0].Detail)
	}
}

// TestSecondKeyCannotOverwriteAnotherPartysEntry is the reason write control
// exists at all. Both packages here are internally valid and correctly signed;
// what makes the second a refusal is only that a different key is already bound
// to xaa.
func TestSecondKeyCannotOverwriteAnotherPartysEntry(t *testing.T) {
	h := newHarness(t)
	incumbent := testsupport.NewKey(t, "incumbent")
	impostor := testsupport.NewKey(t, "impostor")

	first := testsupport.SignedEntry(t, incumbent, "xaa", "2026-09-05", "2026-12-05")
	resp := h.publish("xaa", incumbent, first)
	mustStatus(t, resp, http.StatusCreated)
	resp.Body.Close()

	// A perfectly valid package for xaa, signed by a key nobody bound. It
	// carries a correct signature under its own key -- which is exactly the
	// attack, since a package carrying its own key authenticates nothing.
	second := testsupport.SignedEntry(t, impostor, "xaa", "2026-09-06", "2027-01-01")
	resp = h.publish("xaa", impostor, second)
	mustStatus(t, resp, http.StatusForbidden)
	msg, _ := decode(t, resp)["error"].(string)
	if !strings.Contains(msg, "already bound") {
		t.Fatalf("refusal was %q; it must say a different key is already bound", msg)
	}

	// And the incumbent's entry is untouched.
	got := body(t, h.get("/v1/parties/xaa"))
	if !bytes.Equal(got, first) {
		t.Fatal("the refused write changed the stored entry")
	}
}

func TestBoundKeyMayReplaceItsOwnEntry(t *testing.T) {
	h := newHarness(t)
	k := testsupport.NewKey(t, "replace-own")

	first := testsupport.SignedEntry(t, k, "xaa", "2026-09-05", "2026-12-05")
	resp := h.publish("xaa", k, first)
	mustStatus(t, resp, http.StatusCreated)
	resp.Body.Close()

	second := testsupport.SignedEntry(t, k, "xaa", "2026-09-06", "2027-03-01")
	resp = h.publish("xaa", k, second)
	mustStatus(t, resp, http.StatusOK)
	if got := decode(t, resp); got["first_use"] != false || got["rotated"] != false {
		t.Fatalf("an ordinary replace reported first_use=%v rotated=%v", got["first_use"], got["rotated"])
	}
	if got := body(t, h.get("/v1/parties/xaa")); !bytes.Equal(got, second) {
		t.Fatal("the replacement was not stored")
	}
}

// TestPublishWithoutHoldingTheKeyIsRefused covers the first-use step itself:
// presenting a key you do not hold binds nothing, because the request statement
// must verify under it.
func TestPublishWithoutHoldingTheKeyIsRefused(t *testing.T) {
	h := newHarness(t)
	victim := testsupport.NewKey(t, "victim")
	attacker := testsupport.NewKey(t, "attacker")

	raw := testsupport.SignedEntry(t, victim, "xaa", "2026-09-05", "2026-12-05")
	// Present the victim's key; sign the request with the attacker's.
	resp := h.put("xaa", raw, victim.Pub, attacker.Priv)
	mustStatus(t, resp, http.StatusForbidden)
	resp.Body.Close()

	if resp := h.get("/v1/parties/xaa"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("an entry was created; status = %d", resp.StatusCode)
	}
}

func TestSovereignIDMustMatchThePath(t *testing.T) {
	h := newHarness(t)
	k := testsupport.NewKey(t, "path-mismatch")
	raw := testsupport.SignedEntry(t, k, "xab", "2026-09-05", "2026-12-05")
	resp := h.put("xaa", raw, k.Pub, k.Priv)
	mustStatus(t, resp, http.StatusUnprocessableEntity)
	if msg, _ := decode(t, resp)["error"].(string); !strings.Contains(msg, "does not match the path") {
		t.Fatalf("refusal was %q", msg)
	}
}

// ---------------------------------------------------------------------------
// 3. Offer blocks are refused, with a message saying why.
// ---------------------------------------------------------------------------

func TestSubmissionCarryingAnOfferIsRefusedWithAReason(t *testing.T) {
	h := newHarness(t)
	k := testsupport.NewKey(t, "offers")

	blocks := map[string]string{
		"transport_offer": `"transport_offer": {"endpoint":"_fed._udp.xaa.example","listener":true,"public_key":"oHV+Ce6IBJRv7MI5Vq8VXANwAOtSadjrGx+8SB28IVE=","proposed_link_subnet":"169.254.10.0/31","measured_mtu":1380}`,
		"data_offer":      `"data_offer": {"release":["release/weather/**"],"accept_hz":100,"accept_bytes_per_message":1048576,"accept_distinct_keys":5000}`,
		"cut":             `"cut": {"contact":"fed-ops@xaa.example"}`,
	}
	for member, block := range blocks {
		t.Run(member, func(t *testing.T) {
			entry := testsupport.DirectoryEntry("xaa", "2026-09-05", "2026-12-05")
			withOffer := strings.TrimSuffix(strings.TrimSpace(entry), "}") + ",\n  " + block + "\n}"
			raw := testsupport.Sign(t, k, withOffer)

			resp := h.publish("xaa", k, raw)
			mustStatus(t, resp, http.StatusUnprocessableEntity)
			msg, _ := decode(t, resp)["error"].(string)
			if !strings.Contains(msg, member) {
				t.Fatalf("refusal %q does not name %s", msg, member)
			}
			// The message has to carry the reason, not just the rule.
			// "Reachability and limits move directly between two parties" is
			// actionable; "invalid package" sends someone to read the source.
			if !strings.Contains(msg, "directly between the two parties") {
				t.Fatalf("refusal %q does not say why the block is refused", msg)
			}
			if resp := h.get("/v1/parties/xaa"); resp.StatusCode != http.StatusNotFound {
				t.Fatal("a refused submission created an entry")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 4. An expired package is still served, flagged.
// ---------------------------------------------------------------------------

// TestExpiredPackageIsStillServedAndFlagged: refusing to serve an expired entry
// would be the directory making a decision on the consumer's behalf. Advisory
// means the consumer decides -- it may well want the expired entry, to see what
// a party last published and whom to chase.
func TestExpiredPackageIsStillServedAndFlagged(t *testing.T) {
	h := newHarness(t)
	k := testsupport.NewKey(t, "expired")
	raw := testsupport.SignedEntry(t, k, "xaa", "2026-01-01", "2026-03-01")

	// Publishing an already-expired package is allowed too. The directory is
	// not a validity gate.
	h.now = fixedNow
	resp := h.publish("xaa", k, raw)
	mustStatus(t, resp, http.StatusCreated)
	if got := decode(t, resp); got["expired"] != true {
		t.Fatalf("publish reported expired=%v for a package that expired 2026-03-01", got["expired"])
	}

	resp = h.get("/v1/parties/xaa")
	mustStatus(t, resp, http.StatusOK)
	if got := resp.Header.Get(httpapi.HeaderExpired); got != "true" {
		t.Fatalf("%s = %q, want \"true\"", httpapi.HeaderExpired, got)
	}
	if got := body(t, resp); !bytes.Equal(got, raw) {
		t.Fatal("the expired entry was not served byte-for-byte")
	}

	// And the list says so as well.
	listed := decode(t, h.get("/v1/parties"))
	parties := listed["parties"].([]any)
	if len(parties) != 1 {
		t.Fatalf("list returned %d parties; an expired entry must still be listed", len(parties))
	}
	if p := parties[0].(map[string]any); p["expired"] != true {
		t.Fatalf("list reported expired=%v", p["expired"])
	}
}

func TestUnexpiredEntryIsFlaggedFalse(t *testing.T) {
	h := newHarness(t)
	k := testsupport.NewKey(t, "unexpired")
	raw := testsupport.SignedEntry(t, k, "xaa", "2026-09-05", "2026-12-05")
	h.publish("xaa", k, raw).Body.Close()

	resp := h.get("/v1/parties/xaa")
	if got := resp.Header.Get(httpapi.HeaderExpired); got != "false" {
		t.Fatalf("%s = %q, want \"false\"", httpapi.HeaderExpired, got)
	}
	resp.Body.Close()

	// The boundary: expiry is not enforced, but it is reported on the right
	// day. An entry expiring 2026-12-05 is not expired on 2026-12-05.
	h.now = time.Date(2026, 12, 5, 23, 59, 0, 0, time.UTC)
	resp = h.get("/v1/parties/xaa")
	if got := resp.Header.Get(httpapi.HeaderExpired); got != "false" {
		t.Fatalf("on the expiry date %s = %q, want \"false\"", httpapi.HeaderExpired, got)
	}
	resp.Body.Close()

	h.now = time.Date(2026, 12, 6, 0, 1, 0, 0, time.UTC)
	resp = h.get("/v1/parties/xaa")
	if got := resp.Header.Get(httpapi.HeaderExpired); got != "true" {
		t.Fatalf("the day after expiry %s = %q, want \"true\"", httpapi.HeaderExpired, got)
	}
	resp.Body.Close()
}

// ---------------------------------------------------------------------------
// 5. Key rotation, authorised by the key being replaced.
// ---------------------------------------------------------------------------

func TestRotationBySignatureUnderTheCurrentKey(t *testing.T) {
	h := newHarness(t)
	oldKey := testsupport.NewKey(t, "rotate-old")
	newKey := testsupport.NewKey(t, "rotate-new")

	first := testsupport.SignedEntry(t, oldKey, "xaa", "2026-09-05", "2026-12-05")
	resp := h.publish("xaa", oldKey, first)
	mustStatus(t, resp, http.StatusCreated)
	resp.Body.Close()

	// The package is re-signed under the new key, so the stored entry verifies
	// under the key the directory will advertise for it. The REQUEST is signed
	// by the old key, which is what authorises the replacement.
	rotated := testsupport.SignedEntry(t, newKey, "xaa", "2026-09-06", "2027-01-01")
	resp = h.put("xaa", rotated, newKey.Pub, oldKey.Priv)
	mustStatus(t, resp, http.StatusOK)
	got := decode(t, resp)
	if got["rotated"] != true {
		t.Fatalf("rotated = %v, want true", got["rotated"])
	}
	if got["bound_key"] != newKey.PubB64 {
		t.Fatalf("bound_key = %v, want the new key %s", got["bound_key"], newKey.PubB64)
	}

	// The old key no longer writes.
	stale := testsupport.SignedEntry(t, oldKey, "xaa", "2026-09-07", "2027-02-01")
	resp = h.put("xaa", stale, oldKey.Pub, oldKey.Priv)
	mustStatus(t, resp, http.StatusForbidden)
	resp.Body.Close()

	// The new key does.
	next := testsupport.SignedEntry(t, newKey, "xaa", "2026-09-08", "2027-04-01")
	resp = h.publish("xaa", newKey, next)
	mustStatus(t, resp, http.StatusOK)
	resp.Body.Close()

	// The rotation is logged, so a directory compromise is detectable after
	// the fact.
	logs, err := h.store.Log(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var rotations int
	for _, l := range logs {
		if l.Action == "rotate" {
			rotations++
			if !strings.Contains(l.Detail, oldKey.PubB64) || !strings.Contains(l.Detail, newKey.PubB64) {
				t.Errorf("the rotation log must name both keys: %q", l.Detail)
			}
		}
	}
	if rotations != 1 {
		t.Fatalf("admin log holds %d rotations, want 1", rotations)
	}
}

// TestRotationNeedsThePackageResignedUnderTheNewKey: a rotation authorised by
// the current key still must not store a package the new bound key cannot
// verify, or a reader who fetches the entry and the advertised key gets two
// things that do not go together.
func TestRotationNeedsThePackageResignedUnderTheNewKey(t *testing.T) {
	h := newHarness(t)
	oldKey := testsupport.NewKey(t, "resign-old")
	newKey := testsupport.NewKey(t, "resign-new")

	h.publish("xaa", oldKey, testsupport.SignedEntry(t, oldKey, "xaa", "2026-09-05", "2026-12-05")).Body.Close()

	stillOldSig := testsupport.SignedEntry(t, oldKey, "xaa", "2026-09-06", "2027-01-01")
	resp := h.put("xaa", stillOldSig, newKey.Pub, oldKey.Priv)
	mustStatus(t, resp, http.StatusForbidden)
	if msg, _ := decode(t, resp)["error"].(string); !strings.Contains(msg, "package signature") {
		t.Fatalf("refusal was %q; it must point at the package signature", msg)
	}
}

// ---------------------------------------------------------------------------
// Deletion, clearing, and the surface as a whole.
// ---------------------------------------------------------------------------

func TestDeleteNeedsTheBoundKey(t *testing.T) {
	h := newHarness(t)
	owner := testsupport.NewKey(t, "delete-owner")
	other := testsupport.NewKey(t, "delete-other")
	h.publish("xaa", owner, testsupport.SignedEntry(t, owner, "xaa", "2026-09-05", "2026-12-05")).Body.Close()

	resp := h.delete("xaa", other.Priv)
	mustStatus(t, resp, http.StatusForbidden)
	resp.Body.Close()

	resp = h.delete("xaa", owner.Priv)
	mustStatus(t, resp, http.StatusNoContent)
	resp.Body.Close()

	if resp := h.get("/v1/parties/xaa"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status after delete = %d", resp.StatusCode)
	}
}

// TestOperatorClearReleasesTheBinding covers the answer to a lost key: the
// binding cannot be replaced without the key it replaces, so an operator clears
// the entry. It is deliberately not an HTTP endpoint.
func TestOperatorClearReleasesTheBinding(t *testing.T) {
	h := newHarness(t)
	lost := testsupport.NewKey(t, "lost-key")
	fresh := testsupport.NewKey(t, "fresh-key")
	h.publish("xaa", lost, testsupport.SignedEntry(t, lost, "xaa", "2026-09-05", "2026-12-05")).Body.Close()

	// While the entry stands, a new key is refused.
	resp := h.publish("xaa", fresh, testsupport.SignedEntry(t, fresh, "xaa", "2026-09-06", "2027-01-01"))
	mustStatus(t, resp, http.StatusForbidden)
	resp.Body.Close()

	ctx := t.Context()
	h.store.Lock()
	if err := h.store.Delete(ctx, "xaa"); err != nil {
		t.Fatal(err)
	}
	if err := h.store.AppendLog(ctx, "clear", "xaa", "cleared by operator: key lost", fixedNow); err != nil {
		t.Fatal(err)
	}
	h.store.Unlock()

	resp = h.publish("xaa", fresh, testsupport.SignedEntry(t, fresh, "xaa", "2026-09-06", "2027-01-01"))
	mustStatus(t, resp, http.StatusCreated)
	if got := decode(t, resp); got["first_use"] != true {
		t.Fatalf("after a clear the next publish must be a first use; got %v", got["first_use"])
	}
}

func TestListAndSpecAndHealth(t *testing.T) {
	h := newHarness(t)
	for _, id := range []string{"xab", "xaa"} {
		k := testsupport.NewKey(t, "list-"+id)
		h.publish(id, k, testsupport.SignedEntry(t, k, id, "2026-09-05", "2026-12-05")).Body.Close()
	}

	listed := decode(t, h.get("/v1/parties"))
	parties := listed["parties"].([]any)
	if len(parties) != 2 {
		t.Fatalf("list returned %d parties, want 2", len(parties))
	}
	if parties[0].(map[string]any)["sovereign_id"] != "xaa" {
		t.Fatal("list is not ordered by sovereign_id")
	}

	spec := decode(t, h.get("/v1/spec"))
	if spec["spec"] != "federation-package/v1" {
		t.Fatalf("spec = %v", spec["spec"])
	}

	resp := h.get("/healthz")
	mustStatus(t, resp, http.StatusOK)
	resp.Body.Close()
}

// TestEveryResponseCarriesTheAdvisory: the invariant travels in the wire
// format, not only in the README, because the README is what gets dropped when
// an integrator copies a response into their own system.
func TestEveryResponseCarriesTheAdvisory(t *testing.T) {
	h := newHarness(t)
	k := testsupport.NewKey(t, "advisory")
	h.publish("xaa", k, testsupport.SignedEntry(t, k, "xaa", "2026-09-05", "2026-12-05")).Body.Close()

	for _, path := range []string{"/healthz", "/v1/spec", "/v1/parties", "/v1/parties/xaa", "/v1/parties/nope"} {
		resp := h.get(path)
		if got := resp.Header.Get(httpapi.HeaderAdvisory); !strings.Contains(got, "grants access to nothing") {
			t.Errorf("GET %s: %s = %q", path, httpapi.HeaderAdvisory, got)
		}
		resp.Body.Close()
	}
}

// TestNoRankingOrMatchingEndpointExists guards the non-goal that would be
// easiest to add by accident. If you are here because you added one of these
// paths, read the package comment on httpapi: a directory that answers "who
// should I federate with" has made its operator a broker, and has become
// load-bearing for a decision that belongs to two parties talking to each other.
func TestNoRankingOrMatchingEndpointExists(t *testing.T) {
	h := newHarness(t)
	for _, path := range []string{
		"/v1/compatible",
		"/v1/parties/xaa/compatible",
		"/v1/match",
		"/v1/parties?sort=pqc_capable",
		"/v1/parties?compatible_with=xaa",
	} {
		resp := h.get(path)
		defer resp.Body.Close()
		switch {
		case strings.Contains(path, "?"):
			// A query parameter must be ignored, not honoured: an unrecognised
			// filter that silently narrowed the list would be a matching
			// feature nobody documented.
			if resp.StatusCode != http.StatusOK {
				t.Errorf("GET %s = %d; the list must ignore unknown parameters", path, resp.StatusCode)
			}
		default:
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("GET %s = %d; there must be no ranking or matching endpoint", path, resp.StatusCode)
			}
		}
	}
}

func TestMalformedWriteHeadersAreRefusedAsSuch(t *testing.T) {
	h := newHarness(t)
	k := testsupport.NewKey(t, "headers")
	raw := testsupport.SignedEntry(t, k, "xaa", "2026-09-05", "2026-12-05")

	// No signature header at all.
	req, _ := http.NewRequest(http.MethodPut, h.srv.URL+"/v1/parties/xaa", bytes.NewReader(raw))
	req.Header.Set(httpapi.HeaderKey, k.PubB64)
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	mustStatus(t, resp, http.StatusBadRequest)
	resp.Body.Close()

	// A key in the wrong encoding fails as a malformed value, not as a bad
	// signature -- two different findings that would otherwise look alike.
	req, _ = http.NewRequest(http.MethodPut, h.srv.URL+"/v1/parties/xaa", bytes.NewReader(raw))
	req.Header.Set(httpapi.HeaderKey, "MCowBQYDK2VwAyEAoHV+Ce6IBJRv7MI5Vq8VXANwAOtSadjrGx+8SB28IVE=")
	req.Header.Set(httpapi.HeaderSignature, strings.Repeat("A", 86)+"==")
	resp, err = h.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	mustStatus(t, resp, http.StatusBadRequest)
	if msg, _ := decode(t, resp)["error"].(string); !strings.Contains(msg, "SubjectPublicKeyInfo") {
		t.Fatalf("refusal was %q; it should name what was actually sent", msg)
	}
}

func TestGetUnknownPartyIs404(t *testing.T) {
	h := newHarness(t)
	resp := h.get("/v1/parties/xzz")
	mustStatus(t, resp, http.StatusNotFound)
	resp.Body.Close()
}

// TestOversizedBodyIs413 checks the body cap answers as what it is, before the
// body is parsed or any signature is looked at.
func TestOversizedBodyIs413(t *testing.T) {
	h := newHarness(t)
	k := testsupport.NewKey(t, "oversized")
	big := bytes.Repeat([]byte(" "), httpapi.MaxBodyBytes+1)
	resp := h.put("xaa", big, k.Pub, k.Priv)
	mustStatus(t, resp, http.StatusRequestEntityTooLarge)
	resp.Body.Close()

	// At the cap exactly, the body is read and judged on its content instead.
	resp = h.put("xaa", big[:httpapi.MaxBodyBytes], k.Pub, k.Priv)
	if resp.StatusCode == http.StatusRequestEntityTooLarge {
		t.Fatal("a body of exactly MaxBodyBytes was refused as too large")
	}
	resp.Body.Close()
}
