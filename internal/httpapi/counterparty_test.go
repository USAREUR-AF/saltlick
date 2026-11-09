package httpapi_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"github.com/usareur-af/saltlick/internal/httpapi"
	"github.com/usareur-af/saltlick/internal/testsupport"
)

// peeringPackage is a complete signed package for one peering: the transport
// offer carries that peering's own endpoint and link subnet, which is why a
// party with two peerings signs two packages.
func peeringPackage(t *testing.T, k testsupport.Key, id, endpoint, subnet string) []byte {
	t.Helper()
	unsigned := strings.TrimSuffix(strings.TrimSpace(testsupport.DirectoryEntry(id, "2026-09-05", "2026-12-05")), "}") +
		`, "transport_offer": {"endpoint": "` + endpoint + `", "listener": true, "proposed_link_subnet": "` + subnet + `"}}`
	return testsupport.Sign(t, k, unsigned)
}

func TestTwoCounterpartyPackagesAreKeptApart(t *testing.T) {
	h := newHarness(t)
	k := testsupport.NewKey(t, "two-peerings")
	withEntry(t, h, k, "xaa")
	entryBefore := body(t, h.get("/v1/parties/xaa"))
	single := fullPackage(t, k, "xaa")
	forXab := peeringPackage(t, k, "xaa", "192.0.2.10:51821", "169.254.10.0/31")
	forXac := peeringPackage(t, k, "xaa", "192.0.2.10:51822", "169.254.10.2/31")

	for _, up := range []struct {
		kind string
		body []byte
	}{{"package", single}, {"packages/xab", forXab}, {"packages/xac", forXac}} {
		resp := h.host("xaa", up.kind, k, up.body)
		mustStatus(t, resp, http.StatusCreated)
		if m := decode(t, resp); m["replaced"] != false {
			t.Fatalf("%s: first upload reported replaced: %v", up.kind, m)
		}
	}

	for path, want := range map[string][]byte{
		"/v1/parties/xaa/package":      single,
		"/v1/parties/xaa/packages/xab": forXab,
		"/v1/parties/xaa/packages/xac": forXac,
	} {
		got := h.get(path)
		mustStatus(t, got, http.StatusOK)
		if ct := got.Header.Get("Content-Type"); ct != "application/json" {
			t.Fatalf("%s: Content-Type = %q", path, ct)
		}
		if b := body(t, got); !bytes.Equal(b, want) {
			t.Fatalf("%s: not served byte for byte, or replaced by another peering's package:\n got %s\nwant %s", path, b, want)
		}
	}

	// Replacing one counterparty's package leaves the other and the single one alone.
	forXab2 := peeringPackage(t, k, "xaa", "192.0.2.10:51823", "169.254.10.4/31")
	resp := h.host("xaa", "packages/xab", k, forXab2)
	mustStatus(t, resp, http.StatusOK)
	resp.Body.Close()
	if b := body(t, h.get("/v1/parties/xaa/packages/xac")); !bytes.Equal(b, forXac) {
		t.Fatal("replacing xab's package changed xac's")
	}
	if b := body(t, h.get("/v1/parties/xaa/package")); !bytes.Equal(b, single) {
		t.Fatal("replacing xab's package changed the single package")
	}
	if b := body(t, h.get("/v1/parties/xaa/packages/xab")); !bytes.Equal(b, forXab2) {
		t.Fatal("xab's package was not replaced")
	}

	// The entry an existing reader starts from is untouched by slot uploads.
	if b := body(t, h.get("/v1/parties/xaa")); !bytes.Equal(b, entryBefore) {
		t.Fatal("a counterparty upload changed the entry")
	}

	// The catalogue is unchanged: it links the single package and lists no slots.
	list := decode(t, h.get("/v1/parties"))
	party := list["parties"].([]any)[0].(map[string]any)
	if party["package"] != "/v1/parties/xaa/package" {
		t.Fatalf("list does not link the single package: %v", party)
	}
	for key := range party {
		if strings.Contains(key, "xab") || strings.Contains(key, "packages") {
			t.Fatalf("list names a counterparty slot: %v", party)
		}
	}
	if page := string(body(t, h.get("/"))); strings.Contains(page, "/v1/parties/xaa/packages/") {
		t.Fatal("home page links a counterparty slot")
	}
}

// The upload signature served with a counterparty package names the
// counterparty, so a reader checks under the key read aloud that the party
// signed this package for this counterparty.
func TestCounterpartyPackageServesTheUploadSignatureNamingTheCounterparty(t *testing.T) {
	h := newHarness(t)
	k := testsupport.NewKey(t, "slot-signature")
	withEntry(t, h, k, "xaa")
	pkg := peeringPackage(t, k, "xaa", "192.0.2.10:51821", "169.254.10.0/31")
	resp := h.host("xaa", "packages/xab", k, pkg)
	mustStatus(t, resp, http.StatusCreated)
	resp.Body.Close()

	got := h.get("/v1/parties/xaa/packages/xab")
	mustStatus(t, got, http.StatusOK)
	b := body(t, got)
	if r := got.Header.Get(httpapi.HeaderResource); r != "xaa/packages/xab" {
		t.Fatalf("X-Saltlick-Resource = %q, want xaa/packages/xab", r)
	}
	if got.Header.Get(httpapi.HeaderWriterKey) != k.PubB64 || got.Header.Get(httpapi.HeaderBoundKey) != k.PubB64 {
		t.Fatal("GET of a counterparty package must carry the writer key and the bound key")
	}
	sig, err := base64.StdEncoding.DecodeString(got.Header.Get(httpapi.HeaderWriterSignature))
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(k.Pub, statement(http.MethodPut, "xaa/packages/xab", b, k.PubB64), sig) {
		t.Fatal("the served signature does not verify over PUT xaa/packages/xab")
	}
	if ed25519.Verify(k.Pub, statement(http.MethodPut, "xaa/packages/xac", b, k.PubB64), sig) {
		t.Fatal("the served signature also verifies for another counterparty")
	}
}

func TestCounterpartyPackageRefusals(t *testing.T) {
	h := newHarness(t)
	k := testsupport.NewKey(t, "slot-refusals")
	withEntry(t, h, k, "xaa")
	withEntry(t, h, k, "xab")
	pkg := peeringPackage(t, k, "xaa", "192.0.2.10:51821", "169.254.10.0/31")

	// The counterparty is not the party itself, and has the form of a sovereign_id.
	for _, cp := range []string{"xaa", "XAB", "x", "a-name-longer-than-16"} {
		resp := h.host("xaa", "packages/"+cp, k, pkg)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("counterparty %q: status %d, want 400; %s", cp, resp.StatusCode, body(t, resp))
			continue
		}
		resp.Body.Close()
		mustStatus(t, h.get("/v1/parties/xaa/packages/"+cp), http.StatusBadRequest)
	}

	// The body is the party's own package, as for the single package.
	resp := h.host("xaa", "packages/xac", k, peeringPackage(t, k, "xab", "192.0.2.11:51821", "169.254.10.0/31"))
	mustStatus(t, resp, http.StatusUnprocessableEntity)
	resp.Body.Close()
	resp = h.host("xaa", "packages/xac", k, certPEM(t, true))
	mustStatus(t, resp, http.StatusUnprocessableEntity)
	resp.Body.Close()

	// A signature for one slot, or for the single package, is not replayable onto another slot.
	for _, resource := range []string{"xaa/package", "xaa/packages/xad", "xaa"} {
		resp := h.putFile("xaa", "packages/xac", resource, pkg, k.Pub, k.Priv)
		mustStatus(t, resp, http.StatusForbidden)
		resp.Body.Close()
	}

	// Another key cannot write a slot of a bound entry.
	other := testsupport.NewKey(t, "slot-intruder")
	resp = h.putFile("xaa", "packages/xac", "xaa/packages/xac", pkg, other.Pub, other.Priv)
	mustStatus(t, resp, http.StatusForbidden)
	resp.Body.Close()

	// No entry, no slot.
	stranger := testsupport.NewKey(t, "slot-stranger")
	resp = h.host("xzz", "packages/xaa", stranger, peeringPackage(t, stranger, "xzz", "192.0.2.12:51821", "169.254.10.0/31"))
	mustStatus(t, resp, http.StatusConflict)
	resp.Body.Close()

	// A slot never uploaded is 404, and so is a party with no entry.
	mustStatus(t, h.get("/v1/parties/xaa/packages/xae"), http.StatusNotFound)
	mustStatus(t, h.get("/v1/parties/xzz/packages/xaa"), http.StatusNotFound)
}

func TestDeletingTheEntryDeletesItsCounterpartyPackages(t *testing.T) {
	h := newHarness(t)
	k := testsupport.NewKey(t, "slot-delete")
	withEntry(t, h, k, "xaa")
	resp := h.host("xaa", "packages/xab", k, peeringPackage(t, k, "xaa", "192.0.2.10:51821", "169.254.10.0/31"))
	mustStatus(t, resp, http.StatusCreated)
	resp.Body.Close()
	resp = h.delete("xaa", k.Priv)
	mustStatus(t, resp, http.StatusNoContent)
	resp.Body.Close()
	mustStatus(t, h.get("/v1/parties/xaa/packages/xab"), http.StatusNotFound)
}

// deleteSlot sends DELETE /v1/parties/<id>/packages/<cp>, signing the statement
// for resource.
func (h *harness) deleteSlot(id, cp, resource string, signingKey ed25519.PrivateKey) *http.Response {
	h.t.Helper()
	stmt := statement(http.MethodDelete, resource, nil, "")
	req, err := http.NewRequest(http.MethodDelete, h.srv.URL+"/v1/parties/"+id+"/packages/"+cp, nil)
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

func TestOneCounterpartyPackageIsWithdrawnAlone(t *testing.T) {
	h := newHarness(t)
	k := testsupport.NewKey(t, "slot-withdraw")
	withEntry(t, h, k, "xaa")
	single := fullPackage(t, k, "xaa")
	forXac := peeringPackage(t, k, "xaa", "192.0.2.10:51822", "169.254.10.2/31")
	for kind, b := range map[string][]byte{
		"package":      single,
		"packages/xab": peeringPackage(t, k, "xaa", "192.0.2.10:51821", "169.254.10.0/31"),
		"packages/xac": forXac,
	} {
		resp := h.host("xaa", kind, k, b)
		mustStatus(t, resp, http.StatusCreated)
		resp.Body.Close()
	}

	// Another key, the entry's own DELETE signature, or another slot's, is refused.
	other := testsupport.NewKey(t, "slot-withdraw-other")
	for _, c := range []struct {
		resource string
		key      ed25519.PrivateKey
	}{{"xaa/packages/xab", other.Priv}, {"xaa", k.Priv}, {"xaa/packages/xac", k.Priv}} {
		resp := h.deleteSlot("xaa", "xab", c.resource, c.key)
		mustStatus(t, resp, http.StatusForbidden)
		resp.Body.Close()
	}

	resp := h.deleteSlot("xaa", "xab", "xaa/packages/xab", k.Priv)
	mustStatus(t, resp, http.StatusNoContent)
	resp.Body.Close()
	mustStatus(t, h.get("/v1/parties/xaa/packages/xab"), http.StatusNotFound)
	if b := body(t, h.get("/v1/parties/xaa/packages/xac")); !bytes.Equal(b, forXac) {
		t.Fatal("withdrawing xab's package changed xac's")
	}
	if b := body(t, h.get("/v1/parties/xaa/package")); !bytes.Equal(b, single) {
		t.Fatal("withdrawing xab's package changed the single package")
	}
	mustStatus(t, h.get("/v1/parties/xaa"), http.StatusOK)

	// Gone already, or a slot name that cannot exist.
	resp = h.deleteSlot("xaa", "xab", "xaa/packages/xab", k.Priv)
	mustStatus(t, resp, http.StatusNotFound)
	resp.Body.Close()
	resp = h.deleteSlot("xaa", "xaa", "xaa/packages/xaa", k.Priv)
	mustStatus(t, resp, http.StatusBadRequest)
	resp.Body.Close()
}
