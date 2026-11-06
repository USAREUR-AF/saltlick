package pkgv1

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/usareur-af/saltlick/internal/canonical"
)

// A pointer record says where a party's signed package can be fetched and what
// its digest is. It holds pointers, not permissions: no key material, no
// identities, no namespaces.
//
// A counterparty looks the pointer up, fetches the package from package_url,
// checks the package's signatures against its own trust store, and recomputes
// the digest. The directory is not an input to that check: a wrong pointer
// leads to a package that fails it, and a missing one leaves the package to
// travel by any other channel.

// pointerMembers are exactly the members a pointer carries.
var pointerMembers = []string{
	"spec", "sovereign_id", "package_url", "package_sha256", "expires", "signature",
}

// maxPackageURL bounds package_url.
const maxPackageURL = 2048

var packageSHA256Re = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// parsePointer reads a document already established to declare PointerSpec.
// The caller has refused nulls and offer blocks.
func parsePointer(raw []byte, doc *canonical.Value) (*Package, error) {
	known := map[string]bool{}
	for _, m := range pointerMembers {
		known[m] = true
	}
	for _, name := range doc.Names() {
		if !known[name] {
			return nil, fmt.Errorf("unknown top-level member %q; a %s record carries only %s",
				name, PointerSpec, strings.Join(pointerMembers, ", "))
		}
	}
	for _, m := range pointerMembers {
		if doc.Get(m) == nil {
			return nil, fmt.Errorf("missing required member %q", m)
		}
	}

	sovID, err := str(doc, "sovereign_id")
	if err != nil {
		return nil, err
	}
	if !sovereignIDRe.MatchString(sovID) {
		return nil, fmt.Errorf("sovereign_id %q is not 2-16 characters of lowercase a-z0-9-", sovID)
	}

	u, err := str(doc, "package_url")
	if err != nil {
		return nil, err
	}
	if err := checkPackageURL(u); err != nil {
		return nil, err
	}

	digest, err := str(doc, "package_sha256")
	if err != nil {
		return nil, err
	}
	if !packageSHA256Re.MatchString(digest) {
		return nil, fmt.Errorf("package_sha256 must be 'sha256:' followed by exactly 64 lowercase hex characters")
	}

	expires, err := date(doc, "expires")
	if err != nil {
		return nil, err
	}
	if _, err := DecodeSignature(mustStr(doc, "signature")); err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}

	return &Package{
		Raw:         raw,
		Doc:         doc,
		Spec:        PointerSpec,
		SovereignID: sovID,
		Expires:     expires,
	}, nil
}

// checkPackageURL accepts an absolute https URL with a host, no userinfo and no
// fragment, at most maxPackageURL characters.
func checkPackageURL(s string) error {
	if len(s) > maxPackageURL {
		return fmt.Errorf("package_url is %d characters; at most %d", len(s), maxPackageURL)
	}
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("package_url is not a URL: %v", err)
	}
	switch {
	case u.Scheme != "https":
		return fmt.Errorf("package_url must be an absolute https:// URL; got scheme %q", u.Scheme)
	case u.Host == "" || u.Hostname() == "":
		return fmt.Errorf("package_url has no host")
	case u.User != nil:
		return fmt.Errorf("package_url carries userinfo; a pointer never carries credentials")
	case u.Fragment != "" || strings.Contains(s, "#"):
		return fmt.Errorf("package_url carries a fragment")
	}
	return nil
}
