package httpapi_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/usareur-af/saltlick/internal/httpapi"
	"github.com/usareur-af/saltlick/internal/testsupport"
)

// putFile uploads body to /v1/parties/<id>/<kind>, presenting presentedKey and
// signing the request statement for resource with signingKey. resource is
// normally "<id>/<kind>"; a test passes another to try a replay.
func (h *harness) putFile(id, kind, resource string, body []byte, presentedKey ed25519.PublicKey, signingKey ed25519.PrivateKey) *http.Response {
	h.t.Helper()
	presented := base64.StdEncoding.EncodeToString(presentedKey)
	stmt := statement(http.MethodPut, resource, body, presented)
	req, err := http.NewRequest(http.MethodPut, h.srv.URL+"/v1/parties/"+id+"/"+kind, bytes.NewReader(body))
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

func (h *harness) host(id, kind string, k testsupport.Key, body []byte) *http.Response {
	h.t.Helper()
	return h.putFile(id, kind, id+"/"+kind, body, k.Pub, k.Priv)
}

// fullPackage is a complete signed package, offers included: what a party
// hosts here and would otherwise put on its own public host.
func fullPackage(t *testing.T, k testsupport.Key, id string) []byte {
	t.Helper()
	unsigned := strings.TrimSuffix(strings.TrimSpace(testsupport.DirectoryEntry(id, "2026-09-05", "2026-12-05")), "}") +
		`, "transport_offer": {"kind": "wireguard", "listener": false}}`
	return testsupport.Sign(t, k, unsigned)
}

func certPEM(t *testing.T, isCA bool) []byte {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "xaa test CA"},
		NotBefore:             fixedNow.Add(-time.Hour),
		NotAfter:              fixedNow.Add(365 * 24 * time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// withEntry publishes a pointer entry for id under k, naming this instance's
// own package URL.
func withEntry(t *testing.T, h *harness, k testsupport.Key, id string) {
	t.Helper()
	ptr := testsupport.Sign(t, k, testsupport.Pointer(id, "https://dir.example/v1/parties/"+id+"/package", "2026-12-05"))
	resp := h.publish(id, k, ptr)
	mustStatus(t, resp, http.StatusCreated)
	resp.Body.Close()
}

func TestHostedPackageRoundTripsByteForByteAndIsListed(t *testing.T) {
	h := newHarness(t)
	k := testsupport.NewKey(t, "hosted-package")
	withEntry(t, h, k, "xaa")
	pkg := fullPackage(t, k, "xaa")

	resp := h.host("xaa", "package", k, pkg)
	mustStatus(t, resp, http.StatusCreated)
	if m := decode(t, resp); m["replaced"] != false {
		t.Fatalf("first upload reported replaced: %v", m)
	}

	got := h.get("/v1/parties/xaa/package")
	mustStatus(t, got, http.StatusOK)
	if ct := got.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q", ct)
	}
	if got.Header.Get(httpapi.HeaderBoundKey) != k.PubB64 {
		t.Fatal("GET of a hosted package must carry the entry's bound key")
	}
	if b := body(t, got); !bytes.Equal(b, pkg) {
		t.Fatalf("hosted package not returned byte for byte:\n got %s\nwant %s", b, pkg)
	}

	// A replacement answers 200.
	resp = h.host("xaa", "package", k, pkg)
	mustStatus(t, resp, http.StatusOK)
	resp.Body.Close()

	list := decode(t, h.get("/v1/parties"))
	party := list["parties"].([]any)[0].(map[string]any)
	if party["package"] != "/v1/parties/xaa/package" {
		t.Fatalf("list does not link the hosted package: %v", party)
	}
	if _, ok := party["ca"]; ok {
		t.Fatalf("list links a CA that is not hosted: %v", party)
	}
	page := string(body(t, h.get("/")))
	if !strings.Contains(page, `href="/v1/parties/xaa/package">package</a>`) {
		t.Fatal("home page does not link the hosted package")
	}
}

func TestHostedCARoundTripsByteForByteAndIsListed(t *testing.T) {
	h := newHarness(t)
	k := testsupport.NewKey(t, "hosted-ca")
	withEntry(t, h, k, "xaa")
	ca := append(certPEM(t, true), certPEM(t, true)...)

	resp := h.host("xaa", "ca", k, ca)
	mustStatus(t, resp, http.StatusCreated)
	if m := decode(t, resp); len(m["certificates"].([]any)) != 2 {
		t.Fatalf("want two certificate fingerprints: %v", m)
	}
	got := h.get("/v1/parties/xaa/ca")
	mustStatus(t, got, http.StatusOK)
	if ct := got.Header.Get("Content-Type"); ct != "application/pem-certificate-chain" {
		t.Fatalf("Content-Type = %q", ct)
	}
	if b := body(t, got); !bytes.Equal(b, ca) {
		t.Fatal("hosted CA not returned byte for byte")
	}
	party := decode(t, h.get("/v1/parties"))["parties"].([]any)[0].(map[string]any)
	if party["ca"] != "/v1/parties/xaa/ca" {
		t.Fatalf("list does not link the hosted CA: %v", party)
	}
	if !strings.Contains(string(body(t, h.get("/"))), `href="/v1/parties/xaa/ca">CA</a>`) {
		t.Fatal("home page does not link the hosted CA")
	}
}

func TestHostedFileWithoutAnEntryIsRefused(t *testing.T) {
	h := newHarness(t)
	k := testsupport.NewKey(t, "no-entry")
	for kind, b := range map[string][]byte{
		"package": fullPackage(t, k, "xaa"), "ca": certPEM(t, true), "spiffe-bundle": spiffeBundle(t),
	} {
		resp := h.host("xaa", kind, k, b)
		mustStatus(t, resp, http.StatusConflict)
		resp.Body.Close()
	}
	mustStatus(t, h.get("/v1/parties/xaa/package"), http.StatusNotFound)
}

func TestHostedFileUnderAnotherKeyIsRefused(t *testing.T) {
	h := newHarness(t)
	owner := testsupport.NewKey(t, "owner")
	other := testsupport.NewKey(t, "other")
	withEntry(t, h, owner, "xaa")

	// Another key, presented and signing.
	resp := h.host("xaa", "ca", other, certPEM(t, true))
	mustStatus(t, resp, http.StatusForbidden)
	resp.Body.Close()

	// The bound key presented, the request signed by another.
	resp = h.putFile("xaa", "ca", "xaa/ca", certPEM(t, true), owner.Pub, other.Priv)
	mustStatus(t, resp, http.StatusForbidden)
	resp.Body.Close()

	// A package signed by another key, uploaded under the bound key.
	resp = h.host("xaa", "package", owner, fullPackage(t, other, "xaa"))
	mustStatus(t, resp, http.StatusForbidden)
	resp.Body.Close()
}

func TestHostedFileSignatureIsBoundToItsResource(t *testing.T) {
	h := newHarness(t)
	k := testsupport.NewKey(t, "replay")
	withEntry(t, h, k, "xaa")
	ca := certPEM(t, true)
	for _, resource := range []string{"xaa", "xaa/package"} {
		resp := h.putFile("xaa", "ca", resource, ca, k.Pub, k.Priv)
		mustStatus(t, resp, http.StatusForbidden)
		resp.Body.Close()
	}
}

func TestHostedPackageRefusals(t *testing.T) {
	h := newHarness(t)
	k := testsupport.NewKey(t, "package-refusals")
	withEntry(t, h, k, "xaa")
	withEntry(t, h, k, "xab")

	canonicalPkg := fullPackage(t, k, "xaa")
	cases := map[string][]byte{
		"another party's package": fullPackage(t, k, "xab"),
		"not canonical":           append([]byte(" "), canonicalPkg...),
		"wrong spec": testsupport.Sign(t, k, strings.Replace(
			testsupport.DirectoryEntry("xaa", "2026-09-05", "2026-12-05"), "federation-package/v1", "federation-package/v3", 1)),
		"not a package": []byte(`"xaa"`),
		"unsigned":      []byte(`{"sovereign_id":"xaa","spec":"federation-package/v1"}`),
	}
	for name, b := range cases {
		resp := h.host("xaa", "package", k, b)
		if resp.StatusCode != http.StatusUnprocessableEntity {
			t.Errorf("%s: status %d, want 422; %s", name, resp.StatusCode, body(t, resp))
			continue
		}
		resp.Body.Close()
	}
}

func TestHostedCARefusals(t *testing.T) {
	h := newHarness(t)
	k := testsupport.NewKey(t, "ca-refusals")
	withEntry(t, h, k, "xaa")
	good := certPEM(t, true)
	cases := map[string][]byte{
		"empty":             nil,
		"not PEM":           []byte("hello"),
		"a private key":     pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}}),
		"not X.509":         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}}),
		"not a CA":          certPEM(t, false),
		"text after":        append(append([]byte{}, good...), []byte("trailing")...),
		"text before":       append([]byte("leading\n"), good...),
		"a non-CA in a set": append(append([]byte{}, good...), certPEM(t, false)...),
	}
	for name, b := range cases {
		resp := h.host("xaa", "ca", k, b)
		if resp.StatusCode != http.StatusUnprocessableEntity {
			t.Errorf("%s: status %d, want 422; %s", name, resp.StatusCode, body(t, resp))
			continue
		}
		resp.Body.Close()
	}
	mustStatus(t, h.get("/v1/parties/xaa/ca"), http.StatusNotFound)
}

func TestHostedFileMalformedHeadersAndOversizeBody(t *testing.T) {
	h := newHarness(t)
	k := testsupport.NewKey(t, "headers")
	withEntry(t, h, k, "xaa")

	req, _ := http.NewRequest(http.MethodPut, h.srv.URL+"/v1/parties/xaa/ca", bytes.NewReader(certPEM(t, true)))
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	mustStatus(t, resp, http.StatusBadRequest)
	resp.Body.Close()

	resp = h.host("xaa", "ca", k, bytes.Repeat([]byte("a"), httpapi.MaxBodyBytes+1))
	mustStatus(t, resp, http.StatusRequestEntityTooLarge)
	resp.Body.Close()
}

func TestDeletingTheEntryDeletesItsHostedFiles(t *testing.T) {
	h := newHarness(t)
	k := testsupport.NewKey(t, "delete-hosted")
	withEntry(t, h, k, "xaa")
	for kind, b := range map[string][]byte{
		"package": fullPackage(t, k, "xaa"), "ca": certPEM(t, true), "spiffe-bundle": spiffeBundle(t),
	} {
		resp := h.host("xaa", kind, k, b)
		mustStatus(t, resp, http.StatusCreated)
		resp.Body.Close()
	}
	resp := h.delete("xaa", k.Priv)
	mustStatus(t, resp, http.StatusNoContent)
	resp.Body.Close()
	for _, p := range []string{"/v1/parties/xaa/package", "/v1/parties/xaa/ca", "/v1/parties/xaa/spiffe-bundle"} {
		mustStatus(t, h.get(p), http.StatusNotFound)
	}

	// A new claimant of the name starts with no files.
	other := testsupport.NewKey(t, "new-claimant")
	withEntry(t, h, other, "xaa")
	mustStatus(t, h.get("/v1/parties/xaa/package"), http.StatusNotFound)
}

func TestHostedUploadsSpendTheWriteBudget(t *testing.T) {
	h, _, _ := limited(t, defaults(t))
	for i := 0; i < 2; i++ {
		if rec := do(h, "PUT", "/v1/parties/xaa/ca", "192.0.2.9:4000", nil); rec.Code == http.StatusTooManyRequests {
			t.Fatalf("upload %d within the burst was limited", i)
		}
	}
	if rec := do(h, "PUT", "/v1/parties/xaa/package", "192.0.2.9:4000", nil); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("upload past the write burst = %d, want 429", rec.Code)
	}
}

// packageV2 is fullPackage as federation-package/v2 (goat ADR 1242): v1 with
// spec changed and identity.ca_fingerprint_next, the next CA the party announces.
func packageV2(t *testing.T, k testsupport.Key, id string) []byte {
	t.Helper()
	unsigned := strings.TrimSuffix(strings.TrimSpace(testsupport.DirectoryEntry(id, "2026-09-05", "2026-12-05")), "}") +
		`, "transport_offer": {"kind": "wireguard", "listener": false}}`
	unsigned = strings.Replace(unsigned, `"federation-package/v1"`, `"federation-package/v2"`, 1)
	unsigned = strings.Replace(unsigned, `"ca_fingerprint":`,
		`"ca_fingerprint_next": "sha256:`+strings.Repeat("ab", 32)+`", "ca_fingerprint":`, 1)
	return testsupport.Sign(t, k, unsigned)
}

// A v2 package is hosted and served byte for byte, in the single slot and in a
// counterparty slot, as a v1 package is; the directory reads neither's identity.
func TestHostedPackageV2RoundTripsByteForByteInBothSlots(t *testing.T) {
	h := newHarness(t)
	k := testsupport.NewKey(t, "hosted-package-v2")
	withEntry(t, h, k, "xaa")
	pkg := packageV2(t, k, "xaa")
	if !bytes.Contains(pkg, []byte(`"federation-package/v2"`)) || !bytes.Contains(pkg, []byte("ca_fingerprint_next")) {
		t.Fatalf("not a v2 package: %s", pkg)
	}
	for _, kind := range []string{"package", "packages/xab"} {
		resp := h.host("xaa", kind, k, pkg)
		mustStatus(t, resp, http.StatusCreated)
		resp.Body.Close()
		got := h.get("/v1/parties/xaa/" + kind)
		mustStatus(t, got, http.StatusOK)
		if b := body(t, got); !bytes.Equal(b, pkg) {
			t.Fatalf("%s: v2 package not served byte for byte:\n got %s\nwant %s", kind, b, pkg)
		}
	}
}

// A package of a version no goat release defines is still refused, in both slots.
func TestHostedPackageOfAnotherVersionIsRefused(t *testing.T) {
	h := newHarness(t)
	k := testsupport.NewKey(t, "hosted-package-v3")
	withEntry(t, h, k, "xaa")
	for _, spec := range []string{"federation-package/v3", "federation-package/v0", "saltlick-pointer/v1"} {
		b := testsupport.Sign(t, k, strings.Replace(strings.TrimSuffix(strings.TrimSpace(
			testsupport.DirectoryEntry("xaa", "2026-09-05", "2026-12-05")), "}")+`}`, "federation-package/v1", spec, 1))
		for _, kind := range []string{"package", "packages/xab"} {
			resp := h.host("xaa", kind, k, b)
			if resp.StatusCode != http.StatusUnprocessableEntity {
				t.Errorf("%s in %s: status %d, want 422; %s", spec, kind, resp.StatusCode, body(t, resp))
				continue
			}
			if msg := string(body(t, resp)); !strings.Contains(msg, "federation-package/v2") {
				t.Errorf("%s in %s: the refusal does not name what is hosted: %s", spec, kind, msg)
			}
		}
	}
}

// A v2 package is checked to the same standard as a v1 package, through the
// same checks: canonical form, the package's own signature under the entry's
// bound key, the sovereign_id of the path. Hosting byte for byte never means a
// v2 package goes unchecked; each refusal answers v1 and v2 alike.
func TestHostedPackageV2IsCheckedAsV1Is(t *testing.T) {
	h := newHarness(t)
	k := testsupport.NewKey(t, "hosted-v2-checks")
	other := testsupport.NewKey(t, "hosted-v2-other-signer")
	withEntry(t, h, k, "xaa")
	withEntry(t, h, k, "xab")
	for name, build := range map[string]func(testsupport.Key, string) []byte{
		"v1": func(sk testsupport.Key, id string) []byte { return fullPackage(t, sk, id) },
		"v2": func(sk testsupport.Key, id string) []byte { return packageV2(t, sk, id) },
	} {
		// The package signed by another key than the entry's: the upload itself is
		// signed by the bound key, so only the package's own signature is wrong.
		forged := build(other, "xaa")
		for _, kind := range []string{"package", "packages/xab"} {
			resp := h.host("xaa", kind, k, forged)
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("%s in %s, signed by another key: status %d, want 403; %s", name, kind, resp.StatusCode, body(t, resp))
				continue
			}
			if msg := string(body(t, resp)); !strings.Contains(msg, "package signature") {
				t.Errorf("%s in %s: the refusal does not name the package signature: %s", name, kind, msg)
			}
			if got := h.get("/v1/parties/xaa/" + kind); got.StatusCode != http.StatusNotFound {
				t.Errorf("%s in %s: a refused package is served (status %d)", name, kind, got.StatusCode)
			} else {
				got.Body.Close()
			}
		}
		// Not in canonical form: refused before anything else, as v1 is.
		resp := h.host("xaa", "package", k, append([]byte(" "), build(k, "xaa")...))
		if resp.StatusCode != http.StatusUnprocessableEntity {
			t.Errorf("%s not canonical: status %d, want 422", name, resp.StatusCode)
		}
		resp.Body.Close()
		// Another party's package in this party's slot.
		resp = h.host("xaa", "package", k, build(k, "xab"))
		if resp.StatusCode != http.StatusUnprocessableEntity {
			t.Errorf("%s naming another party: status %d, want 422", name, resp.StatusCode)
		}
		resp.Body.Close()
	}
}
