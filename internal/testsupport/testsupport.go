// Package testsupport builds signed packages for tests.
//
// It is not part of the service. It exists so that a test can produce a
// correctly signed directory entry without the test itself re-implementing
// canonicalisation, which would let a bug in the canonicaliser hide behind an
// identical bug in the test.
package testsupport

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/usareur-af/saltlick/internal/canonical"
)

// Key is a test signing key.
type Key struct {
	Priv   ed25519.PrivateKey
	Pub    ed25519.PublicKey
	PubB64 string
}

// NewKey makes a keypair from a deterministic seed string, so a failing test
// names the same key every run.
func NewKey(t *testing.T, seed string) Key {
	t.Helper()
	s := make([]byte, ed25519.SeedSize)
	copy(s, seed)
	priv := ed25519.NewKeyFromSeed(s)
	pub := priv.Public().(ed25519.PublicKey)
	return Key{Priv: priv, Pub: pub, PubB64: base64.StdEncoding.EncodeToString(pub)}
}

// KeyFromSeedHex loads a key from a 32-byte hex seed, the encoding the
// conformance-vector test keys use.
func KeyFromSeedHex(t *testing.T, seedHex string) Key {
	t.Helper()
	s, err := hex.DecodeString(strings.TrimSpace(seedHex))
	if err != nil || len(s) != ed25519.SeedSize {
		t.Fatalf("bad seed hex %q: %v", seedHex, err)
	}
	priv := ed25519.NewKeyFromSeed(s)
	pub := priv.Public().(ed25519.PublicKey)
	return Key{Priv: priv, Pub: pub, PubB64: base64.StdEncoding.EncodeToString(pub)}
}

// DirectoryEntry is a valid directory entry for a sovereign_id: the
// always-required blocks and nothing else.
func DirectoryEntry(sovereignID, issued, expires string) string {
	return fmt.Sprintf(`{
  "spec": "federation-package/v1",
  "sovereign_id": %q,
  "issued": %q,
  "expires": %q,
  "identity": {
    "trust_domain": "spiffe://%s.example",
    "ca_fingerprint": "sha256:d49211cac3357142f3cf9c2ee216cdd452793ce89428d5ea856f9f62e71efe55"
  },
  "capabilities": {
    "transports": ["ipsec-fips", "wireguard"],
    "fabric_fips_image": true,
    "pqc_capable": true,
    "fabric_version": "1.9.0"
  }
}`, sovereignID, issued, expires, sovereignID)
}

// Sign canonicalises unsigned, signs it, and returns the canonical bytes with
// the signature member in place -- the bytes a party would publish.
func Sign(t *testing.T, k Key, unsigned string) []byte {
	t.Helper()
	doc, err := canonical.Parse([]byte(unsigned))
	if err != nil {
		t.Fatalf("parsing the unsigned package: %v", err)
	}
	stripped := doc.Without("signature")
	input, err := canonical.Write(stripped)
	if err != nil {
		t.Fatalf("canonicalising the signing input: %v", err)
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(k.Priv, input))
	stripped.Members = append(stripped.Members, canonical.Member{
		Name:  "signature",
		Value: &canonical.Value{Kind: canonical.KindString, Str: sig},
	})
	out, err := canonical.Write(stripped)
	if err != nil {
		t.Fatalf("canonicalising the signed package: %v", err)
	}
	return out
}

// SignedEntry is DirectoryEntry plus Sign.
func SignedEntry(t *testing.T, k Key, sovereignID, issued, expires string) []byte {
	t.Helper()
	return Sign(t, k, DirectoryEntry(sovereignID, issued, expires))
}

// TestDigest is a well-formed package_sha256 for pointer tests.
const TestDigest = "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

// Pointer is a valid saltlick-pointer/v1 record, unsigned.
func Pointer(sovereignID, packageURL, expires string) string {
	return fmt.Sprintf(`{
  "spec": "saltlick-pointer/v1",
  "sovereign_id": %q,
  "package_url": %q,
  "package_sha256": %q,
  "expires": %q
}`, sovereignID, packageURL, TestDigest, expires)
}

// SignedPointer is Pointer plus Sign, with package_url
// https://<sovereign_id>.example/federation-package.json.
func SignedPointer(t *testing.T, k Key, sovereignID, expires string) []byte {
	t.Helper()
	return Sign(t, k, Pointer(sovereignID, "https://"+sovereignID+".example/federation-package.json", expires))
}
