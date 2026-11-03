package pkgv1_test

import (
	"crypto/ed25519"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/usareur-af/saltlick/internal/canonical"
	"github.com/usareur-af/saltlick/internal/pkgv1"
	"github.com/usareur-af/saltlick/internal/testsupport"
)

func read(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestConformanceVectorRoundTripsAndVerifies checks this repository's
// canonicalisation and signature verification against bytes and a signature
// produced by a different implementation. Homegrown canonicalisation is where
// formats like this die, and a test that only checks our writer against our own
// reader would not notice.
func TestConformanceVectorRoundTripsAndVerifies(t *testing.T) {
	raw := []byte(strings.TrimSpace(read(t, "full-offer-xaa.json")))
	doc, err := canonical.Parse(raw)
	if err != nil {
		t.Fatalf("parsing the conformance vector: %v", err)
	}

	// The vector file is in canonical form, so writing it back must reproduce
	// it byte for byte.
	out, err := canonical.Write(doc)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(raw) {
		t.Fatalf("canonical round trip differs from the vector\n got: %s\nwant: %s", out, raw)
	}

	key, err := pkgv1.DecodeVerifyingKey(strings.TrimSpace(read(t, "xaa.public.b64")))
	if err != nil {
		t.Fatal(err)
	}
	input, err := canonical.Write(doc.Without("signature"))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := pkgv1.DecodeSignature(doc.Get("signature").Str)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(key, input, sig) {
		t.Fatal("the conformance vector's signature does not verify; canonicalisation disagrees with the reference implementation")
	}
}

// TestRefusesAValidPackageThatCarriesAnOffer is the point of the vector being
// in testdata: it is a real, valid, correctly signed federation package, and a
// directory must still refuse it.
func TestRefusesAValidPackageThatCarriesAnOffer(t *testing.T) {
	raw := []byte(strings.TrimSpace(read(t, "full-offer-xaa.json")))
	_, err := pkgv1.Parse(raw)
	if err == nil {
		t.Fatal("Parse accepted a package carrying transport_offer, data_offer and cut")
	}
	if !strings.Contains(err.Error(), "never carries an offer") {
		t.Fatalf("Parse = %v; the refusal must say why", err)
	}
}

func TestRefusesEachOfferBlockSeparately(t *testing.T) {
	k := testsupport.NewKey(t, "offer-block-test")
	cases := map[string]string{
		"transport_offer": `"transport_offer": {"endpoint":"_fed._udp.xaa.example","listener":true,"public_key":"oHV+Ce6IBJRv7MI5Vq8VXANwAOtSadjrGx+8SB28IVE=","proposed_link_subnet":"169.254.10.0/31","measured_mtu":1380}`,
		"data_offer":      `"data_offer": {"release":["release/weather/**"],"accept_hz":100,"accept_bytes_per_message":1048576,"accept_distinct_keys":5000}`,
		"cut":             `"cut": {"contact":"fed-ops@xaa.example"}`,
	}
	for member, block := range cases {
		t.Run(member, func(t *testing.T) {
			entry := testsupport.DirectoryEntry("xaa", "2026-09-05", "2026-12-05")
			withOffer := strings.TrimSuffix(strings.TrimSpace(entry), "}") + ",\n  " + block + "\n}"
			raw := testsupport.Sign(t, k, withOffer)

			_, err := pkgv1.Parse(raw)
			if err == nil {
				t.Fatalf("Parse accepted a package carrying %s", member)
			}
			msg := err.Error()
			if !strings.Contains(msg, member) {
				t.Fatalf("Parse = %v; the refusal must name %s", err, member)
			}
			// The refusal has to explain itself, or the next person to hit it
			// files it as a bug in the validator.
			for _, phrase := range []string{"directly between the two parties", "everyone can read"} {
				if !strings.Contains(msg, phrase) {
					t.Errorf("Parse = %v; the refusal must say why, mentioning %q", err, phrase)
				}
			}
		})
	}
}

func TestAcceptsADirectoryEntry(t *testing.T) {
	k := testsupport.NewKey(t, "accepts-entry")
	raw := testsupport.SignedEntry(t, k, "xaa", "2026-09-05", "2026-12-05")
	p, err := pkgv1.Parse(raw)
	if err != nil {
		t.Fatalf("Parse = %v; want acceptance", err)
	}
	if p.SovereignID != "xaa" || p.Issued != "2026-09-05" || p.Expires != "2026-12-05" {
		t.Fatalf("Parse returned %+v", p)
	}
	if string(p.Raw) != string(raw) {
		t.Fatal("Parse did not keep the submitted bytes")
	}
	if err := p.VerifySignature(k.Pub); err != nil {
		t.Fatalf("VerifySignature = %v", err)
	}
}

func TestVerifySignatureRefusesAnotherKey(t *testing.T) {
	mine := testsupport.NewKey(t, "mine")
	theirs := testsupport.NewKey(t, "theirs")
	raw := testsupport.SignedEntry(t, mine, "xaa", "2026-09-05", "2026-12-05")
	p, err := pkgv1.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.VerifySignature(theirs.Pub); err == nil {
		t.Fatal("VerifySignature accepted a signature made by a different key")
	}
}

func TestStructuralRefusals(t *testing.T) {
	k := testsupport.NewKey(t, "structural")
	base := testsupport.DirectoryEntry("xaa", "2026-09-05", "2026-12-05")

	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			"wrong spec version",
			strings.Replace(base, `"federation-package/v1"`, `"federation-package/v2"`, 1),
			"this instance accepts",
		},
		{
			"unknown top-level member",
			strings.TrimSuffix(strings.TrimSpace(base), "}") + `,"transport_offer_v2":{"endpoint":"x"}}`,
			"unknown top-level member",
		},
		{
			"null member",
			strings.Replace(base, `"pqc_capable": true`, `"pqc_capable": null`, 1),
			"null at $.capabilities.pqc_capable",
		},
		{
			"empty transports",
			strings.Replace(base, `["ipsec-fips", "wireguard"]`, `[]`, 1),
			"an empty array is not a declaration",
		},
		{
			"incomplete identity",
			strings.Replace(base,
				`"ca_fingerprint": "sha256:d49211cac3357142f3cf9c2ee216cdd452793ce89428d5ea856f9f62e71efe55"`,
				`"ca_fingerprint": "sha256:d49211cac3357142f3cf9c2ee216cdd452793ce89428d5ea856f9f62e71efe55","surprise": 1`, 1),
			`unknown member "surprise"`,
		},
		{
			"uppercase ca_fingerprint",
			strings.Replace(base, "sha256:d49211", "sha256:D49211", 1),
			"64 lowercase hex characters",
		},
		{
			"sovereign_id with an uppercase letter",
			strings.Replace(base, `"sovereign_id": "xaa"`, `"sovereign_id": "XAA"`, 1),
			"lowercase a-z0-9-",
		},
		{
			"expires before issued",
			strings.Replace(base, `"expires": "2026-12-05"`, `"expires": "2026-09-04"`, 1),
			"is before issued",
		},
		{
			"issued is not a real date",
			strings.Replace(base, `"issued": "2026-09-05"`, `"issued": "2026-13-05"`, 1),
			"not a real date",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := testsupport.Sign(t, k, tc.src)
			_, err := pkgv1.Parse(raw)
			if err == nil {
				t.Fatalf("Parse accepted %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Parse = %v; want an error mentioning %q", err, tc.want)
			}
		})
	}
}

func TestMissingRequiredMemberIsRefused(t *testing.T) {
	// Not signed: an unsigned package is missing "signature", which is one of
	// the always-required members.
	raw := []byte(testsupport.DirectoryEntry("xaa", "2026-09-05", "2026-12-05"))
	_, err := pkgv1.Parse(raw)
	if err == nil || !strings.Contains(err.Error(), `missing required member "signature"`) {
		t.Fatalf("Parse = %v; want a refusal naming the missing signature", err)
	}
}

func TestDecodeVerifyingKey(t *testing.T) {
	k := testsupport.NewKey(t, "decode-key")
	if _, err := pkgv1.DecodeVerifyingKey(k.PubB64); err != nil {
		t.Fatalf("DecodeVerifyingKey(%s) = %v", k.PubB64, err)
	}
	if len(k.PubB64) != 44 || !strings.HasSuffix(k.PubB64, "=") {
		t.Fatalf("a verifying key must be 44 characters ending in one '='; got %q", k.PubB64)
	}

	bad := map[string]string{
		// A SubjectPublicKeyInfo export is what most libraries hand you, and it
		// is the wrong thing. The error names it rather than saying "bad key".
		"DER SubjectPublicKeyInfo": "MCowBQYDK2VwAyEAoHV+Ce6IBJRv7MI5Vq8VXANwAOtSadjrGx+8SB28IVE=",
		"signature-shaped":         strings.Repeat("A", 86) + "==",
		"url-safe alphabet":        strings.Repeat("-", 43) + "=",
		"too short":                "AAAA",
		"empty":                    "",
	}
	for name, v := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := pkgv1.DecodeVerifyingKey(v); err == nil {
				t.Fatalf("DecodeVerifyingKey(%q) accepted it", v)
			}
		})
	}
}

func TestDecodeSignature(t *testing.T) {
	if _, err := pkgv1.DecodeSignature(strings.Repeat("A", 86) + "=="); err != nil {
		t.Fatalf("DecodeSignature of an 88-character value = %v", err)
	}
	bad := map[string]string{
		"key-shaped":        strings.Repeat("A", 43) + "=",
		"one pad character": strings.Repeat("A", 87) + "=",
		"whitespace inside": strings.Repeat("A", 43) + " " + strings.Repeat("A", 42) + "==",
		"empty":             "",
	}
	for name, v := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := pkgv1.DecodeSignature(v); err == nil {
				t.Fatalf("DecodeSignature(%q) accepted it", v)
			}
		})
	}
}

func TestIsExpiredIsReportedNotEnforced(t *testing.T) {
	k := testsupport.NewKey(t, "expiry")
	raw := testsupport.SignedEntry(t, k, "xaa", "2026-01-01", "2026-03-01")

	// Parse does not consult the clock. An expired package is a valid package,
	// and refusing to parse one would put the directory in the business of
	// deciding which entries a consumer may see.
	p, err := pkgv1.Parse(raw)
	if err != nil {
		t.Fatalf("Parse refused an expired package: %v", err)
	}
	if !p.IsExpired(time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC)) {
		t.Fatal("IsExpired = false the day after expiry")
	}
	if p.IsExpired(time.Date(2026, 3, 1, 23, 0, 0, 0, time.UTC)) {
		t.Fatal("IsExpired = true on the expiry date itself")
	}
}
