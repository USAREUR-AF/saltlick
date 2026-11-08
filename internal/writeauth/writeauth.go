// Package writeauth implements the directory's trust-on-first-use write
// control, and nothing beyond it.
//
// Read this before using anything here. What follows protects the directory's
// own record: it stops one party overwriting another party's entry. That is its
// entire purpose.
//
//   - It does NOT establish that a party is who it claims to be.
//   - It does NOT make a key trustworthy. A key learned only from this
//     directory is a key learned from whoever runs the directory.
//   - A consumer must still bind a party's verifying key over a channel
//     authenticated independently of this service, exactly as composing a
//     federation agreement requires.
//
// If an entry that passed these checks is ever described anywhere -- an API
// field, a UI label, a log line -- as a "verified party", the invariant this
// service exists to hold has quietly broken. The shape to keep in mind is an
// SSH host key: accepting one on first connection tells you that the same host
// answered next time, and tells you nothing at all about who that host is.
package writeauth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/usareur-af/saltlick/internal/pkgv1"
)

// StatementVersion domain-separates what a request signature covers, so a
// signature made for one purpose cannot be replayed as another.
const StatementVersion = "saltlick-request/v1"

// Statement is the exact byte string a write request's signature covers. It
// binds the method, the resource in the path, the request body and the key
// being presented, so that none of the four can be swapped for another.
//
// The directory keeps a hosted file's statement signature and serves it on GET,
// so a reader rebuilds this statement from what it fetched and verifies it.
//
// Five lines, each terminated by a newline:
//
//	saltlick-request/v1
//	<METHOD>
//	<the path below /v1/parties/: <sovereign_id>, <sovereign_id>/package, <sovereign_id>/ca or <sovereign_id>/spiffe-bundle>
//	sha256:<hex of the request body, empty string hashed where there is none>
//	<presented verifying key, base64, or "-" where there is none>
func Statement(method, sovereignID string, body []byte, presentedKey string) []byte {
	sum := sha256.Sum256(body)
	if presentedKey == "" {
		presentedKey = "-"
	}
	return []byte(strings.Join([]string{
		StatementVersion,
		method,
		sovereignID,
		"sha256:" + hex.EncodeToString(sum[:]),
		presentedKey,
		"",
	}, "\n"))
}

// Decision is the outcome of applying the trust-on-first-use rules to a write.
type Decision struct {
	// KeyToBind is the key that will be recorded against the entry after this
	// write. On a first publish it is the presented key; on an ordinary replace
	// it is unchanged; on a rotation it is the new key.
	KeyToBind ed25519.PublicKey
	// FirstUse is true when this write binds a key for a sovereign_id that had
	// none. Nothing about the party is established by it.
	FirstUse bool
	// Rotation is true when this write replaces the bound key with a different
	// one, authorised by a signature under the key being replaced.
	Rotation bool
}

// Refusal is a write refused by the trust-on-first-use rules. It is separated
// from an ordinary error so the API can answer 403 for "your signature does not
// authorise this" and 400 for "your request was malformed".
type Refusal struct{ Reason string }

func (r *Refusal) Error() string { return r.Reason }

// AuthorisePut applies the trust-on-first-use rules to a publish.
//
// boundKey is the key currently recorded for this sovereign_id, empty if there
// is none. presentedKey is the key the writer supplies and wishes to be bound
// after this write. requestSig is a signature over Statement(...).
//
// The rules, in the order they are applied:
//
//  1. No entry yet: the presented key is bound, on the writer's say-so alone.
//     This is the first-use step and it authenticates nobody.
//  2. An entry exists and the presented key equals the bound key: the request
//     signature must verify under it.
//  3. An entry exists and the presented key differs: this is a rotation, and
//     the request signature must verify under the CURRENT key -- the one being
//     replaced. A party that has lost its key cannot rotate; an operator clears
//     the entry, which is an administrative act and is logged as one.
//
// In every case the package's own signature must additionally verify under the
// key being bound; that check is the caller's, immediately after this one, and
// is what keeps a stored entry verifiable under the key the directory advertises
// for it.
func AuthorisePut(boundKey string, presentedKey ed25519.PublicKey, requestStatement, requestSig []byte) (*Decision, error) {
	if len(presentedKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("presented key is not a 32-byte Ed25519 public key")
	}
	if len(requestSig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("request signature is not a 64-byte Ed25519 signature")
	}

	if boundKey == "" {
		// Trust on first use. The signature below proves only that the writer
		// holds the key it is asking us to bind -- which is exactly as much as
		// accepting an SSH host key on first connection proves.
		if !ed25519.Verify(presentedKey, requestStatement, requestSig) {
			return nil, &Refusal{Reason: "request signature does not verify under the key presented for binding"}
		}
		return &Decision{KeyToBind: presentedKey, FirstUse: true}, nil
	}

	current, err := pkgv1.DecodeVerifyingKey(boundKey)
	if err != nil {
		return nil, fmt.Errorf("stored bound key is unreadable: %w", err)
	}

	if presentedKey.Equal(current) {
		if !ed25519.Verify(current, requestStatement, requestSig) {
			return nil, &Refusal{Reason: "request signature does not verify under the key bound to this sovereign_id"}
		}
		return &Decision{KeyToBind: current}, nil
	}

	// A different key. One party must not be able to overwrite another's entry,
	// so this is refused unless the key already bound has authorised its own
	// replacement.
	if !ed25519.Verify(current, requestStatement, requestSig) {
		return nil, &Refusal{Reason: "a different key is already bound to this sovereign_id. " +
			"A replacement key must be authorised by a request signature under the key it replaces. " +
			"If that key is lost, an operator must clear the entry"}
	}
	return &Decision{KeyToBind: presentedKey, Rotation: true}, nil
}

// AuthoriseHosted applies the rule for a file hosted beside an entry: the
// presented key must be the key already bound to the entry, and the request
// signature must verify under it. A file never binds or rotates a key; that is
// the entry's write alone.
func AuthoriseHosted(boundKey string, presentedKey ed25519.PublicKey, requestStatement, requestSig []byte) error {
	current, err := pkgv1.DecodeVerifyingKey(boundKey)
	if err != nil {
		return fmt.Errorf("stored bound key is unreadable: %w", err)
	}
	if len(requestSig) != ed25519.SignatureSize {
		return fmt.Errorf("request signature is not a 64-byte Ed25519 signature")
	}
	if !presentedKey.Equal(current) {
		return &Refusal{Reason: "the presented key is not the key bound to this sovereign_id's entry; " +
			"a hosted file is signed by the entry's key, and a key is rotated through the entry"}
	}
	if !ed25519.Verify(current, requestStatement, requestSig) {
		return &Refusal{Reason: "request signature does not verify under the key bound to this sovereign_id"}
	}
	return nil
}

// AuthoriseDelete requires a signature under the bound key.
func AuthoriseDelete(boundKey string, requestStatement, requestSig []byte) error {
	current, err := pkgv1.DecodeVerifyingKey(boundKey)
	if err != nil {
		return fmt.Errorf("stored bound key is unreadable: %w", err)
	}
	if len(requestSig) != ed25519.SignatureSize {
		return fmt.Errorf("request signature is not a 64-byte Ed25519 signature")
	}
	if !ed25519.Verify(current, requestStatement, requestSig) {
		return &Refusal{Reason: "request signature does not verify under the key bound to this sovereign_id"}
	}
	return nil
}
