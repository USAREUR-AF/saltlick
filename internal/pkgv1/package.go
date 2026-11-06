// Package pkgv1 reads a federation-package/v1 document as a directory entry.
//
// A directory entry is an ordinary federation package carrying only the
// always-required blocks. The package format has no tier field and no tier
// ladder: presence is the declaration. A package carrying transport_offer is
// willing to connect; one carrying data_offer is willing to exchange. Neither
// belongs in a directory readable by everyone, so this package refuses them.
//
// Nothing here judges a party. It checks that a document is a well-formed
// package of the kind a directory holds, and that a signature verifies over the
// bytes as submitted. Whether the party behind it is who it claims is not a
// question this repository can answer, and no function in it tries to.
package pkgv1

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/usareur-af/saltlick/internal/canonical"
)

// SpecVersion is the package spec version this instance accepts. The spec
// version is the migration path for the signature algorithm: an implementation
// of this version verifies signatures under this version's algorithm, and only
// over packages that declare this version. A package written for an older or a
// newer lineage is refused unread, in either direction.
const SpecVersion = "federation-package/v1"

// PointerSpec is the pointer record: where a party's signed package can be
// fetched, and the digest of it. See pointer.go.
const PointerSpec = "saltlick-pointer/v1"

// Accepted lists every spec value an entry may declare.
var Accepted = []string{PointerSpec, SpecVersion}

// requiredMembers are the always-required blocks of a package (§3).
var requiredMembers = []string{
	"spec", "sovereign_id", "issued", "expires", "identity", "capabilities", "signature",
}

// offerMembers are the blocks a directory entry must never carry.
//
// Reachability, release sets and accepted limits are sovereign operational
// detail. They move directly between two parties, over a channel those two
// parties chose, and never through a directory that everyone can read. This is
// not a policy setting and there is no flag to relax it: a directory that
// carried an offer would be publishing one party's operational posture to every
// reader, which is a different service from this one.
var offerMembers = map[string]string{
	"transport_offer": "reachability -- endpoint, listener role, link subnet, MTU",
	"data_offer":      "release sets and accepted limits",
	"cut":             "contact details for severing a peering",
}

var (
	sovereignIDRe    = regexp.MustCompile(`^[a-z0-9-]{2,16}$`)
	caFingerprintRe  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	dateRe           = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
	base64StdCharsRe = regexp.MustCompile(`^[A-Za-z0-9+/]*$`)
)

// Package is one directory entry: the bytes exactly as submitted, plus the
// parsed tree used to check them.
//
// Raw is the field that matters. It is what GET returns and what a signature
// was computed over. Nothing in this repository re-serialises it.
type Package struct {
	Raw         []byte
	Doc         *canonical.Value
	Spec        string // SpecVersion or PointerSpec
	SovereignID string
	Issued      string // empty for a pointer, which carries no issued date
	Expires     string
}

// Parse reads raw bytes as a directory entry and refuses anything that is not
// one. It does not verify the signature; call VerifySignature for that, with a
// key that reached you over a channel this service had nothing to do with.
func Parse(raw []byte) (*Package, error) {
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

	for member, what := range offerMembers {
		if doc.Get(member) != nil {
			return nil, fmt.Errorf(
				"package carries %q (%s): a directory entry never carries an offer. "+
					"That is sovereign operational detail and moves directly between the two parties, "+
					"not through a directory everyone can read. Publish the always-required blocks only",
				member, what)
		}
	}

	if spec := doc.Get("spec"); spec != nil && spec.Kind == canonical.KindString && spec.Str == PointerSpec {
		return parsePointer(raw, doc)
	}

	// An unknown top-level member is refused rather than ignored. Presence is
	// the declaration in this format, so a member this version does not know is
	// a declaration this version cannot read -- and a block named, say,
	// "transport_offer_v2" must not reach a reader by being unrecognised.
	known := map[string]bool{}
	for _, m := range requiredMembers {
		known[m] = true
	}
	for _, name := range doc.Names() {
		if !known[name] {
			return nil, fmt.Errorf("unknown top-level member %q; a directory entry carries only %s",
				name, strings.Join(requiredMembers, ", "))
		}
	}
	for _, m := range requiredMembers {
		if doc.Get(m) == nil {
			return nil, fmt.Errorf("missing required member %q", m)
		}
	}

	spec, err := str(doc, "spec")
	if err != nil {
		return nil, err
	}
	if spec != SpecVersion {
		return nil, fmt.Errorf("spec is %q; this instance accepts %s", spec, strings.Join(quoted(Accepted), " or "))
	}

	sovID, err := str(doc, "sovereign_id")
	if err != nil {
		return nil, err
	}
	if !sovereignIDRe.MatchString(sovID) {
		return nil, fmt.Errorf("sovereign_id %q is not 2-16 characters of lowercase a-z0-9-", sovID)
	}

	issued, err := date(doc, "issued")
	if err != nil {
		return nil, err
	}
	expires, err := date(doc, "expires")
	if err != nil {
		return nil, err
	}
	if expires < issued {
		return nil, fmt.Errorf("expires %s is before issued %s", expires, issued)
	}

	if err := checkIdentity(doc.Get("identity")); err != nil {
		return nil, err
	}
	if err := checkCapabilities(doc.Get("capabilities")); err != nil {
		return nil, err
	}
	if _, err := DecodeSignature(mustStr(doc, "signature")); err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}

	return &Package{
		Raw:         raw,
		Doc:         doc,
		Spec:        SpecVersion,
		SovereignID: sovID,
		Issued:      issued,
		Expires:     expires,
	}, nil
}

// SigningInput is the canonical form of the package with the signature member
// removed -- the bytes the party's signature covers (§5).
func (p *Package) SigningInput() ([]byte, error) {
	return canonical.Write(p.Doc.Without("signature"))
}

// VerifySignature checks the package's own signature under key.
//
// Passing this says one thing and no more: whoever holds that key signed these
// bytes. It says nothing about whether the key belongs to the party named in
// sovereign_id. That binding is established over a channel authenticated
// independently of this service -- a call to a voice you recognise, a meeting, a
// courier -- and a key learned only from a directory is a key learned from
// whoever runs the directory.
func (p *Package) VerifySignature(key ed25519.PublicKey) error {
	sig, err := DecodeSignature(mustStr(p.Doc, "signature"))
	if err != nil {
		return err
	}
	input, err := p.SigningInput()
	if err != nil {
		return fmt.Errorf("canonicalising signing input: %w", err)
	}
	if !ed25519.Verify(key, input, sig) {
		return fmt.Errorf("signature does not verify under the supplied key")
	}
	return nil
}

// IsExpired reports whether the package's expires date is before now. It is
// reported and never enforced: an expired entry is still served, flagged. The
// directory does not get to decide that a consumer may not see it.
func (p *Package) IsExpired(now time.Time) bool {
	return p.Expires < now.UTC().Format("2006-01-02")
}

// DecodeVerifyingKey decodes a raw 32-byte Ed25519 public key, base64 with the
// standard alphabet of RFC 4648 s4, padded: exactly 44 characters ending in one
// '='. One '=', not two -- a signature is 88 characters ending '=='.
//
// Not PEM, not DER, not OpenSSH. A SubjectPublicKeyInfo export is 60 characters
// beginning "MCowBQYDK2Vw", which is the tell that the wrong thing has been
// transcribed; the error below names it.
func DecodeVerifyingKey(s string) (ed25519.PublicKey, error) {
	if strings.HasPrefix(s, "MCowBQYDK2Vw") {
		return nil, fmt.Errorf("value is a DER SubjectPublicKeyInfo, not a raw key: strip the 12-byte prefix and send the 32 raw bytes, base64")
	}
	if len(s) != 44 || !strings.HasSuffix(s, "=") || strings.HasSuffix(s, "==") {
		return nil, fmt.Errorf("verifying key must be exactly 44 base64 characters ending in one '='; got %d characters", len(s))
	}
	b, err := strictBase64(s)
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("verifying key must be %d bytes; got %d", ed25519.PublicKeySize, len(b))
	}
	return ed25519.PublicKey(b), nil
}

// EncodeVerifyingKey is the inverse of DecodeVerifyingKey.
func EncodeVerifyingKey(k ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(k)
}

// DecodeSignature decodes a 64-byte Ed25519 signature: exactly 88 base64
// characters ending in '=='. Any other length is refused before verification is
// attempted, so a wrong-shaped value fails as a malformed value rather than as a
// bad signature -- two different findings that would otherwise look alike.
func DecodeSignature(s string) ([]byte, error) {
	if len(s) != 88 || !strings.HasSuffix(s, "==") {
		return nil, fmt.Errorf("signature must be exactly 88 base64 characters ending in '=='; got %d characters", len(s))
	}
	b, err := strictBase64(s)
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.SignatureSize {
		return nil, fmt.Errorf("signature must be %d bytes; got %d", ed25519.SignatureSize, len(b))
	}
	return b, nil
}

// strictBase64 rejects any character outside the standard alphabet -- whitespace
// and line breaks included, which the standard library's decoder skips -- and
// rejects a final quantum whose unused bits are not zero.
func strictBase64(s string) ([]byte, error) {
	body := strings.TrimRight(s, "=")
	if !base64StdCharsRe.MatchString(body) {
		return nil, fmt.Errorf("value contains a character outside the standard base64 alphabet (A-Z a-z 0-9 + /); the URL-safe alphabet is not accepted")
	}
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("base64: %w", err)
	}
	return b, nil
}

func refuseNulls(v *canonical.Value, path string) error {
	switch v.Kind {
	case canonical.KindNull:
		return fmt.Errorf("null at %s: a null is an error at any depth; a member is either present with a value or absent", path)
	case canonical.KindObject:
		for _, m := range v.Members {
			if err := refuseNulls(m.Value, path+"."+m.Name); err != nil {
				return err
			}
		}
	case canonical.KindArray:
		for i, item := range v.Items {
			if err := refuseNulls(item, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkIdentity(v *canonical.Value) error {
	if v.Kind != canonical.KindObject {
		return fmt.Errorf("identity must be an object")
	}
	if err := onlyMembers(v, "identity", "trust_domain", "ca_fingerprint"); err != nil {
		return err
	}
	td, err := str(v, "trust_domain")
	if err != nil {
		return fmt.Errorf("identity.%w", err)
	}
	if td == "" {
		return fmt.Errorf("identity.trust_domain is empty")
	}
	fp, err := str(v, "ca_fingerprint")
	if err != nil {
		return fmt.Errorf("identity.%w", err)
	}
	if !caFingerprintRe.MatchString(fp) {
		return fmt.Errorf("identity.ca_fingerprint must be 'sha256:' followed by exactly 64 lowercase hex characters")
	}
	return nil
}

func checkCapabilities(v *canonical.Value) error {
	if v.Kind != canonical.KindObject {
		return fmt.Errorf("capabilities must be an object")
	}
	if err := onlyMembers(v, "capabilities", "transports", "fabric_fips_image", "pqc_capable", "fabric_version"); err != nil {
		return err
	}
	transports := v.Get("transports")
	if transports == nil || transports.Kind != canonical.KindArray {
		return fmt.Errorf("capabilities.transports must be an array")
	}
	// An empty array is not a declaration. It is a malformed block, not a
	// declaration that happens to carry nothing.
	if len(transports.Items) == 0 {
		return fmt.Errorf("capabilities.transports is empty; an empty array is not a declaration")
	}
	for i, item := range transports.Items {
		if item.Kind != canonical.KindString || item.Str == "" {
			return fmt.Errorf("capabilities.transports[%d] must be a non-empty string", i)
		}
	}
	for _, name := range []string{"fabric_fips_image", "pqc_capable"} {
		b := v.Get(name)
		if b == nil || b.Kind != canonical.KindBool {
			return fmt.Errorf("capabilities.%s must be true or false", name)
		}
	}
	fv, err := str(v, "fabric_version")
	if err != nil {
		return fmt.Errorf("capabilities.%w", err)
	}
	if fv == "" {
		return fmt.Errorf("capabilities.fabric_version is empty")
	}
	return nil
}

// onlyMembers refuses a block carrying a member this version does not know, for
// the same reason as the top-level check: an unrecognised member is a
// declaration that would otherwise pass unread.
func onlyMembers(v *canonical.Value, block string, allowed ...string) error {
	ok := map[string]bool{}
	for _, a := range allowed {
		ok[a] = true
	}
	for _, name := range v.Names() {
		if !ok[name] {
			return fmt.Errorf("unknown member %q in %s; %s carries only %s", name, block, block, strings.Join(allowed, ", "))
		}
	}
	for _, a := range allowed {
		if v.Get(a) == nil {
			return fmt.Errorf("%s is missing %q; a block that is present but incomplete is refused, never defaulted", block, a)
		}
	}
	return nil
}

func str(v *canonical.Value, name string) (string, error) {
	m := v.Get(name)
	if m == nil {
		return "", fmt.Errorf("%s is missing", name)
	}
	if m.Kind != canonical.KindString {
		return "", fmt.Errorf("%s must be a string", name)
	}
	return m.Str, nil
}

// mustStr is for members Parse has already established are strings.
func mustStr(v *canonical.Value, name string) string {
	s, _ := str(v, name)
	return s
}

func date(v *canonical.Value, name string) (string, error) {
	s, err := str(v, name)
	if err != nil {
		return "", err
	}
	if !dateRe.MatchString(s) {
		return "", fmt.Errorf("%s must be a YYYY-MM-DD date; got %q", name, s)
	}
	if _, err := time.Parse("2006-01-02", s); err != nil {
		return "", fmt.Errorf("%s is not a real date: %q", name, s)
	}
	return s, nil
}

func quoted(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = fmt.Sprintf("%q", s)
	}
	return out
}
