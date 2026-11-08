package pkgv1

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/usareur-af/saltlick/internal/canonical"
)

// The SPIFFE key uses a trust bundle may carry (SPIFFE Trust Domain and Bundle,
// §4.2.1).
const (
	SPIFFEUseX509SVID = "x509-svid"
	SPIFFEUseJWTSVID  = "jwt-svid"
)

// SPIFFEBundle is what an upload check reads out of a SPIFFE trust bundle.
type SPIFFEBundle struct {
	// X509Authorities is the SHA-256 of the DER of each x509-svid key's first
	// x5c certificate, "sha256:" + hex, in document order.
	X509Authorities []string
	// JWTAuthorities counts the jwt-svid keys.
	JWTAuthorities int
}

// ParseSPIFFEBundle reads the body of a SPIFFE trust bundle upload: the JWKS
// document `spire-server bundle show -format spiffe` prints. It refuses
// anything that is not a JSON object with a non-empty "keys" array in which
// every key is an object whose "use" is x509-svid or jwt-svid, and every
// x509-svid key carries a non-empty "x5c" array whose first element is the
// standard base64 of a DER X.509 certificate. "spiffe_sequence" and
// "spiffe_refresh_hint", when present, are non-negative integers.
//
// The JSON is read strictly: a duplicate member name is refused, as it is
// everywhere else in this directory, since two readers of one document must
// not see two different bundles.
func ParseSPIFFEBundle(raw []byte) (*SPIFFEBundle, error) {
	doc, err := canonical.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("malformed JSON: %w", err)
	}
	if doc.Kind != canonical.KindObject {
		return nil, fmt.Errorf("a SPIFFE bundle is a JSON object")
	}
	for _, name := range []string{"spiffe_sequence", "spiffe_refresh_hint"} {
		if m := doc.Get(name); m != nil && (m.Kind != canonical.KindNumber || m.Num[0] == '-') {
			return nil, fmt.Errorf("%s must be a non-negative integer", name)
		}
	}
	keys := doc.Get("keys")
	if keys == nil {
		return nil, fmt.Errorf("keys is missing")
	}
	if keys.Kind != canonical.KindArray {
		return nil, fmt.Errorf("keys must be an array")
	}
	if len(keys.Items) == 0 {
		return nil, fmt.Errorf("keys is empty; a SPIFFE bundle carries at least one key")
	}
	var b SPIFFEBundle
	for i, k := range keys.Items {
		n := i + 1
		if k.Kind != canonical.KindObject {
			return nil, fmt.Errorf("key %d is not a JSON object", n)
		}
		use, err := str(k, "use")
		if err != nil {
			return nil, fmt.Errorf("key %d: %w", n, err)
		}
		switch use {
		case SPIFFEUseJWTSVID:
			b.JWTAuthorities++
		case SPIFFEUseX509SVID:
			x5c := k.Get("x5c")
			if x5c == nil || x5c.Kind != canonical.KindArray || len(x5c.Items) == 0 {
				return nil, fmt.Errorf("key %d is an x509-svid key with no x5c certificate", n)
			}
			first := x5c.Items[0]
			if first.Kind != canonical.KindString {
				return nil, fmt.Errorf("key %d: x5c[0] must be a string", n)
			}
			der, err := base64.StdEncoding.Strict().DecodeString(first.Str)
			if err != nil {
				return nil, fmt.Errorf("key %d: x5c[0] is not standard base64: %v", n, err)
			}
			if _, err := x509.ParseCertificate(der); err != nil {
				return nil, fmt.Errorf("key %d: x5c[0] is not a DER X.509 certificate: %v", n, err)
			}
			sum := sha256.Sum256(der)
			b.X509Authorities = append(b.X509Authorities, "sha256:"+hex.EncodeToString(sum[:]))
		default:
			return nil, fmt.Errorf("key %d: use is %q; a SPIFFE bundle key is %q or %q",
				n, use, SPIFFEUseX509SVID, SPIFFEUseJWTSVID)
		}
	}
	return &b, nil
}
