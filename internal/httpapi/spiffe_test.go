package httpapi_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"

	"github.com/usareur-af/saltlick/internal/httpapi"
	"github.com/usareur-af/saltlick/internal/testsupport"
)

// x5c is the standard base64 of a fresh CA certificate's DER, as an x5c
// element carries it.
func x5c(t *testing.T) string {
	t.Helper()
	block, _ := pem.Decode(certPEM(t, true))
	return base64.StdEncoding.EncodeToString(block.Bytes)
}

// spiffeBundle is a trust bundle in the shape `spire-server bundle show
// -format spiffe` prints: one x509-svid key, one jwt-svid key, the sequence
// and the refresh hint, indented as SPIRE indents it.
func spiffeBundle(t *testing.T) []byte {
	t.Helper()
	return []byte(`{
    "keys": [
        {
            "use": "x509-svid",
            "kty": "EC",
            "crv": "P-256",
            "x": "fK-wKTnKL7KFLM27lqq5DC-bxrVaH6rDV-IcCSEOeL4",
            "y": "wq-g3TQWxYlV51TCPH030yXsRxvujD4hUUaIQrXk4KI",
            "x5c": ["` + x5c(t) + `"]
        },
        {
            "use": "jwt-svid",
            "kty": "EC",
            "kid": "C6vs25welZOx6WksNYfbMfiw9l96pMnD",
            "crv": "P-256",
            "x": "ngLYQnlfF6GsojUwqtcEE3WgTNG2RUlsGhK73RNEl5k",
            "y": "tKbiDSUSsQ3F1P7wteeHNXIcU-cx6CgSbroeQrQHTLM"
        }
    ],
    "spiffe_sequence": 1,
    "spiffe_refresh_hint": 300
}
`)
}

func TestHostedSPIFFEBundleRoundTripsByteForByteAndIsListed(t *testing.T) {
	h := newHarness(t)
	k := testsupport.NewKey(t, "hosted-bundle")
	withEntry(t, h, k, "xaa")
	bundle := spiffeBundle(t)

	resp := h.host("xaa", "spiffe-bundle", k, bundle)
	mustStatus(t, resp, http.StatusCreated)
	m := decode(t, resp)
	if m["replaced"] != false || len(m["x509_authorities"].([]any)) != 1 || m["jwt_authorities"] != float64(1) {
		t.Fatalf("first upload answered %v", m)
	}

	got := h.get("/v1/parties/xaa/spiffe-bundle")
	mustStatus(t, got, http.StatusOK)
	if ct := got.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q", ct)
	}
	if got.Header.Get(httpapi.HeaderBoundKey) != k.PubB64 {
		t.Fatal("GET of a hosted bundle must carry the entry's bound key")
	}
	if b := body(t, got); !bytes.Equal(b, bundle) {
		t.Fatalf("hosted bundle not returned byte for byte:\n got %s\nwant %s", b, bundle)
	}

	resp = h.host("xaa", "spiffe-bundle", k, bundle)
	mustStatus(t, resp, http.StatusOK)
	resp.Body.Close()

	party := decode(t, h.get("/v1/parties"))["parties"].([]any)[0].(map[string]any)
	if party["spiffe_bundle"] != "/v1/parties/xaa/spiffe-bundle" {
		t.Fatalf("list does not link the hosted bundle: %v", party)
	}
	if _, ok := party["ca"]; ok {
		t.Fatalf("list links a CA that is not hosted: %v", party)
	}
	page := string(body(t, h.get("/")))
	for _, want := range []string{
		`href="/v1/parties/xaa/spiffe-bundle">SPIFFE bundle</a>`,
		"GET /v1/parties/&lt;id&gt;/spiffe-bundle",
		"PUT /v1/parties/&lt;id&gt;/spiffe-bundle",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("home page lacks %q", want)
		}
	}
}

func TestHomePageSeparatesEveryHostedLink(t *testing.T) {
	h := newHarness(t)
	k := testsupport.NewKey(t, "all-three")
	withEntry(t, h, k, "xaa")
	for kind, b := range map[string][]byte{
		"package": fullPackage(t, k, "xaa"), "ca": certPEM(t, true), "spiffe-bundle": spiffeBundle(t),
	} {
		resp := h.host("xaa", kind, k, b)
		mustStatus(t, resp, http.StatusCreated)
		resp.Body.Close()
	}
	page := string(body(t, h.get("/")))
	want := `<a href="/v1/parties/xaa/package">package</a> · <a href="/v1/parties/xaa/ca">CA</a> · ` +
		`<a href="/v1/parties/xaa/spiffe-bundle">SPIFFE bundle</a>`
	if !strings.Contains(page, want) {
		t.Fatalf("home page does not list the three hosted files as %q", want)
	}

	// Only the bundle: no stray separator.
	h2 := newHarness(t)
	withEntry(t, h2, k, "xab")
	resp := h2.host("xab", "spiffe-bundle", k, spiffeBundle(t))
	mustStatus(t, resp, http.StatusCreated)
	resp.Body.Close()
	if page := string(body(t, h2.get("/"))); !strings.Contains(page, `<td><a href="/v1/parties/xab/spiffe-bundle">`) {
		t.Fatal("a lone bundle link is preceded by something")
	}
}

func TestHostedSPIFFEBundleWriteRefusals(t *testing.T) {
	h := newHarness(t)
	owner := testsupport.NewKey(t, "bundle-owner")
	other := testsupport.NewKey(t, "bundle-other")

	resp := h.host("xaa", "spiffe-bundle", owner, spiffeBundle(t))
	mustStatus(t, resp, http.StatusConflict)
	resp.Body.Close()

	withEntry(t, h, owner, "xaa")

	resp = h.host("xaa", "spiffe-bundle", other, spiffeBundle(t))
	mustStatus(t, resp, http.StatusForbidden)
	resp.Body.Close()

	resp = h.putFile("xaa", "spiffe-bundle", "xaa/spiffe-bundle", spiffeBundle(t), owner.Pub, other.Priv)
	mustStatus(t, resp, http.StatusForbidden)
	resp.Body.Close()

	// A signature made for the CA is not one for the bundle.
	resp = h.putFile("xaa", "spiffe-bundle", "xaa/ca", spiffeBundle(t), owner.Pub, owner.Priv)
	mustStatus(t, resp, http.StatusForbidden)
	resp.Body.Close()

	resp = h.host("xaa", "spiffe-bundle", owner, bytes.Repeat([]byte("a"), httpapi.MaxBodyBytes+1))
	mustStatus(t, resp, http.StatusRequestEntityTooLarge)
	resp.Body.Close()

	mustStatus(t, h.get("/v1/parties/xaa/spiffe-bundle"), http.StatusNotFound)
}

func TestHostedSPIFFEBundleRefusals(t *testing.T) {
	h := newHarness(t)
	k := testsupport.NewKey(t, "bundle-refusals")
	withEntry(t, h, k, "xaa")
	cert := x5c(t)
	key := func(member string) string { return `{"keys":[` + member + `]}` }
	cases := map[string]string{
		"empty":                       ``,
		"not JSON":                    `hello`,
		"an array":                    `[]`,
		"null":                        `null`,
		"no keys":                     `{"spiffe_sequence":1}`,
		"keys not an array":           `{"keys":{}}`,
		"keys empty":                  `{"keys":[]}`,
		"a key not an object":         key(`"x509-svid"`),
		"a key with no use":           key(`{"kty":"EC"}`),
		"use not a string":            key(`{"use":1}`),
		"use unknown":                 key(`{"use":"sig","x5c":["` + cert + `"]}`),
		"x509 with no x5c":            key(`{"use":"x509-svid"}`),
		"x509 with empty x5c":         key(`{"use":"x509-svid","x5c":[]}`),
		"x5c not an array":            key(`{"use":"x509-svid","x5c":"` + cert + `"}`),
		"x5c[0] not a string":         key(`{"use":"x509-svid","x5c":[1]}`),
		"x5c[0] not base64":           key(`{"use":"x509-svid","x5c":["not base64!"]}`),
		"x5c[0] url-safe base64":      key(`{"use":"x509-svid","x5c":["` + strings.NewReplacer("+", "-", "/", "_").Replace(cert) + `x"]}`),
		"x5c[0] not a certificate":    key(`{"use":"x509-svid","x5c":["AQID"]}`),
		"x5c[0] is PEM":               key(`{"use":"x509-svid","x5c":["-----BEGIN CERTIFICATE-----"]}`),
		"one good key, one bad":       `{"keys":[{"use":"x509-svid","x5c":["` + cert + `"]},{"use":"x509-svid"}]}`,
		"duplicate keys member":       `{"keys":[{"use":"jwt-svid"}],"keys":[]}`,
		"trailing data":               key(`{"use":"jwt-svid"}`) + `{}`,
		"sequence negative":           `{"keys":[{"use":"jwt-svid"}],"spiffe_sequence":-1}`,
		"sequence a string":           `{"keys":[{"use":"jwt-svid"}],"spiffe_sequence":"1"}`,
		"refresh hint not an integer": `{"keys":[{"use":"jwt-svid"}],"spiffe_refresh_hint":1.5}`,
		"a CA PEM":                    string(certPEM(t, true)),
	}
	for name, b := range cases {
		resp := h.host("xaa", "spiffe-bundle", k, []byte(b))
		if resp.StatusCode != http.StatusUnprocessableEntity {
			t.Errorf("%s: status %d, want 422; %s", name, resp.StatusCode, body(t, resp))
			continue
		}
		resp.Body.Close()
	}
	mustStatus(t, h.get("/v1/parties/xaa/spiffe-bundle"), http.StatusNotFound)

	// Accepted: a bundle of jwt-svid keys alone, and an x5c chain whose later
	// elements are not read.
	for name, b := range map[string]string{
		"jwt-svid only":  key(`{"use":"jwt-svid","kty":"EC"}`),
		"x5c with chain": key(`{"use":"x509-svid","x5c":["` + cert + `","` + x5c(t) + `"]}`),
	} {
		resp := h.host("xaa", "spiffe-bundle", k, []byte(b))
		if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
			t.Errorf("%s: status %d; %s", name, resp.StatusCode, body(t, resp))
			continue
		}
		resp.Body.Close()
	}
}

// readerStatement builds the request statement from what a GET returned, the
// way SPEC.md tells a reader to, without calling the server's own code.
func readerStatement(resp *http.Response, served []byte) []byte {
	sum := sha256.Sum256(served)
	return []byte("saltlick-request/v1\n" +
		"PUT\n" +
		resp.Header.Get("X-Saltlick-Resource") + "\n" +
		"sha256:" + hex.EncodeToString(sum[:]) + "\n" +
		resp.Header.Get("X-Saltlick-Key") + "\n")
}

// A reader checks every hosted file against the key the two parties read
// aloud, using only what the GET returned.
func TestServedSignatureVerifiesUnderTheWriterKey(t *testing.T) {
	h := newHarness(t)
	k := testsupport.NewKey(t, "served-signature")
	withEntry(t, h, k, "xaa")
	files := map[string][]byte{
		"package":       fullPackage(t, k, "xaa"),
		"ca":            certPEM(t, true),
		"spiffe-bundle": spiffeBundle(t),
	}
	for kind, b := range files {
		resp := h.host("xaa", kind, k, b)
		mustStatus(t, resp, http.StatusCreated)
		resp.Body.Close()

		got := h.get("/v1/parties/xaa/" + kind)
		mustStatus(t, got, http.StatusOK)
		served := body(t, got)

		if got.Header.Get("X-Saltlick-Key") != k.PubB64 {
			t.Fatalf("%s: X-Saltlick-Key = %q, want the bound key", kind, got.Header.Get("X-Saltlick-Key"))
		}
		if r := got.Header.Get("X-Saltlick-Resource"); r != "xaa/"+kind {
			t.Fatalf("%s: X-Saltlick-Resource = %q", kind, r)
		}
		sig, err := base64.StdEncoding.DecodeString(got.Header.Get("X-Saltlick-Signature"))
		if err != nil || len(sig) != ed25519.SignatureSize {
			t.Fatalf("%s: X-Saltlick-Signature is not a base64 Ed25519 signature: %v", kind, err)
		}
		// The key read aloud, not the key the response names.
		if !ed25519.Verify(k.Pub, readerStatement(got, served), sig) {
			t.Fatalf("%s: served signature does not verify under the writer's key", kind)
		}

		altered := append([]byte{}, served...)
		altered[len(altered)/2] ^= 0x01
		if ed25519.Verify(k.Pub, readerStatement(got, altered), sig) {
			t.Fatalf("%s: served signature verifies over altered bytes", kind)
		}
		other := testsupport.NewKey(t, "not-the-writer")
		if ed25519.Verify(other.Pub, readerStatement(got, served), sig) {
			t.Fatalf("%s: served signature verifies under another key", kind)
		}
		// Moved to another resource, the signature does not verify.
		got.Header.Set("X-Saltlick-Resource", "xaa/other")
		if ed25519.Verify(k.Pub, readerStatement(got, served), sig) {
			t.Fatalf("%s: served signature verifies for another resource", kind)
		}
	}
}

// After the entry's key rotates, a file keeps the key that wrote it until it is
// uploaded again under the new one.
func TestServedSignatureNamesTheKeyThatWroteTheFile(t *testing.T) {
	h := newHarness(t)
	oldKey := testsupport.NewKey(t, "before-rotation")
	newKey := testsupport.NewKey(t, "after-rotation")
	withEntry(t, h, oldKey, "xaa")
	resp := h.host("xaa", "spiffe-bundle", oldKey, spiffeBundle(t))
	mustStatus(t, resp, http.StatusCreated)
	resp.Body.Close()

	ptr := testsupport.Sign(t, newKey, testsupport.Pointer("xaa", "https://dir.example/v1/parties/xaa/package", "2026-12-05"))
	resp = h.put("xaa", ptr, newKey.Pub, oldKey.Priv)
	mustStatus(t, resp, http.StatusOK)
	resp.Body.Close()

	got := h.get("/v1/parties/xaa/spiffe-bundle")
	mustStatus(t, got, http.StatusOK)
	body(t, got)
	if got.Header.Get(httpapi.HeaderBoundKey) != newKey.PubB64 || got.Header.Get("X-Saltlick-Key") != oldKey.PubB64 {
		t.Fatalf("bound %q writer %q", got.Header.Get(httpapi.HeaderBoundKey), got.Header.Get("X-Saltlick-Key"))
	}

	bundle := spiffeBundle(t)
	resp = h.host("xaa", "spiffe-bundle", newKey, bundle)
	mustStatus(t, resp, http.StatusOK)
	resp.Body.Close()
	got = h.get("/v1/parties/xaa/spiffe-bundle")
	served := body(t, got)
	sig, _ := base64.StdEncoding.DecodeString(got.Header.Get("X-Saltlick-Signature"))
	if got.Header.Get("X-Saltlick-Key") != newKey.PubB64 || !ed25519.Verify(newKey.Pub, readerStatement(got, served), sig) {
		t.Fatal("a file uploaded again after rotation is not served under the new key")
	}
}
