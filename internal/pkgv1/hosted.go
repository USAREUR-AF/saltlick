package pkgv1

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"

	"github.com/usareur-af/saltlick/internal/canonical"
)

// A party with no public host of its own may keep two files beside its entry:
// its signed federation package and its CA certificate. The directory serves
// them as the party's own host would. It does not read them into the listing,
// index them or judge them, and a reader checks both exactly as it would check
// a file fetched from anywhere else: the package against the key it bound out
// of band, the CA against the package's identity.ca_fingerprint.

// ParseHostedPackage reads the body of a package upload: the party's complete
// signed federation package, offers included. It refuses anything that is not
// a federation-package/v1 document in RFC 8785 canonical form with a
// well-formed signature. The canonical-form rule is what makes the bytes served
// the bytes a pointer's package_sha256 names.
//
// It does not verify the signature; call VerifySignature with the entry's
// bound key.
func ParseHostedPackage(raw []byte) (*Package, error) {
	doc, err := canonical.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("malformed JSON: %w", err)
	}
	if doc.Kind != canonical.KindObject {
		return nil, fmt.Errorf("a package is a JSON object")
	}
	if err := refuseNulls(doc, "$"); err != nil {
		return nil, err
	}
	spec, err := str(doc, "spec")
	if err != nil {
		return nil, err
	}
	if spec != SpecVersion {
		return nil, fmt.Errorf("spec is %q; a hosted package is %q", spec, SpecVersion)
	}
	sovID, err := str(doc, "sovereign_id")
	if err != nil {
		return nil, err
	}
	if !sovereignIDRe.MatchString(sovID) {
		return nil, fmt.Errorf("sovereign_id %q is not 2-16 characters of lowercase a-z0-9-", sovID)
	}
	sig, err := str(doc, "signature")
	if err != nil {
		return nil, err
	}
	if _, err := DecodeSignature(sig); err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}
	canon, err := canonical.Write(doc)
	if err != nil {
		return nil, fmt.Errorf("canonicalising: %w", err)
	}
	if !bytes.Equal(canon, raw) {
		return nil, fmt.Errorf("the package is not in RFC 8785 canonical form; upload the canonical bytes, " +
			"which are the bytes a pointer's package_sha256 is computed over")
	}
	return &Package{Raw: raw, Doc: doc, Spec: SpecVersion, SovereignID: sovID}, nil
}

// ParseCA reads the body of a CA upload: one or more PEM CERTIFICATE blocks,
// each an X.509 CA certificate, with nothing but whitespace around them. It
// returns the SHA-256 of each certificate's DER, the form a package's
// identity.ca_fingerprint takes.
func ParseCA(raw []byte) ([]string, error) {
	var fingerprints []string
	rest := raw
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			if len(bytes.TrimSpace(rest)) != 0 {
				return nil, fmt.Errorf("the body carries something other than PEM certificate blocks")
			}
			break
		}
		// pem.Decode skips text before a block; the upload carries none.
		if lead := bytes.Index(rest, []byte("-----BEGIN")); lead > 0 && len(bytes.TrimSpace(rest[:lead])) != 0 {
			return nil, fmt.Errorf("the body carries something other than PEM certificate blocks")
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("PEM block %q: only CERTIFICATE blocks are accepted; never upload a private key", block.Type)
		}
		if len(block.Headers) != 0 {
			return nil, fmt.Errorf("a CERTIFICATE block carries PEM headers")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("certificate %d is not X.509: %v", len(fingerprints)+1, err)
		}
		if !cert.IsCA {
			return nil, fmt.Errorf("certificate %d (%s) is not a CA certificate", len(fingerprints)+1, cert.Subject)
		}
		sum := sha256.Sum256(block.Bytes)
		fingerprints = append(fingerprints, "sha256:"+hex.EncodeToString(sum[:]))
		rest = next
	}
	if len(fingerprints) == 0 {
		return nil, fmt.Errorf("the body carries no PEM CERTIFICATE block")
	}
	return fingerprints, nil
}
