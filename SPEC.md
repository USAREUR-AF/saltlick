# saltlick — a peering directory that grants nothing

## What this is

A directory where a party publishes its own interconnection capability, so two organisations
can check compatibility **before** they build anything between them.

It is modelled on PeeringDB — the database internet network operators consult before turning
up a BGP session — and it takes exactly one property from it.

## The invariant, which governs every decision below

**Advisory, never authoritative. Being listed grants access to nothing.**

The service's only job is to stop two competent parties from misconfiguring each other. It is
not a trust root, not an authorisation source, and not a party to any agreement. Every feature
request of the form "could the directory also check X" is a request to make it load-bearing,
and the answer is no.

Two consequences that must be visible in the code, not just the docs:

1. **The directory does not decide whether a party is who it claims to be.** It stores and
   serves bytes. A consumer verifies signatures itself, against a key bound over a channel
   authenticated independently of this service.
2. **Federation must work with this service switched off.** The real mechanism is the
   specification plus the same versioned tool: both sides compose independently and compare one
   digest, needing no server and working with an entirely offline partner. If anything ever
   *requires* the directory, the invariant is broken.

## What it stores

An ordinary federation package as defined by `federation-package-spec.md`, carrying **only the
always-required blocks**. The package spec has no tier field and no tier ladder — *presence is
the declaration*. So a directory entry is a complete, valid package from a party that is not,
here, offering to connect or exchange:

| Present | Never present in the directory |
|---|---|
| `spec`, `sovereign_id`, `issued`, `expires`, `signature` | `transport_offer` — willing to connect |
| `identity` — `trust_domain`, `ca_fingerprint` | `data_offer` — willing to exchange |
| `capabilities` — `transports`, `fabric_fips_image`, `pqc_capable`, `fabric_version` | `cut` — contacts |

**Reject a submission carrying `transport_offer`, `data_offer` or `cut`**, with a message
saying why: reachability, release sets and accepted limits are sovereign operational detail
and move directly between two parties, never through a directory readable by everyone.

## The intended entry: a pointer record

The directory holds pointers, not permissions. The intended entry is a signed pointer record:
where a party can be reached for its signed package, and the digest of that package. No key
material, no identities, no namespaces.

| Member | Value |
|---|---|
| `spec` | `"saltlick-pointer/v1"` |
| `sovereign_id` | as for a package: 2–16 characters of `a-z0-9-` |
| `package_url` | absolute `https://` URL where the party's signed package can be fetched; at most 2048 characters; no userinfo, no fragment |
| `package_sha256` | `"sha256:"` + 64 lowercase hex: SHA-256 of the package's canonical bytes |
| `expires` | `YYYY-MM-DD` |
| `signature` | Ed25519 by the party, 88 base64 characters, over the RFC 8785 canonical form of the record without `signature` |

Exactly these members; any other is refused. The first write claims the `sovereign_id`, later
writes must be signed by the same key (trust on first use, below), and an expired pointer is
served and flagged, as for a package.

A counterparty looks the pointer up, fetches the package from `package_url`, checks its
signatures against its own trust store, and recomputes the digest. **The directory is not an
input to that check.** A wrong pointer leads to a package that fails it; a missing one leaves
the package to travel by any other channel.

The recognition-only package above stays accepted. The `spec` member of the submitted body says
which of the two it is.

## Hosted files: a party with no public host

A party behind NAT, with no public host of its own, keeps up to three files beside its entry,
and its pointer's `package_url` names this instance's own `/v1/parties/{sovereign_id}/package`:

| File | Body | Checked on upload |
|---|---|---|
| `package` | the party's complete signed federation package, offers included | `spec` is `federation-package/v1`; `sovereign_id` equals the path's; the body is in RFC 8785 canonical form; its signature verifies under the entry's bound key |
| `ca` | one or more PEM `CERTIFICATE` blocks, nothing else but whitespace | each block parses as an X.509 certificate with the CA flag set |
| `spiffe-bundle` | the party's SPIFFE trust bundle: the JWKS document `spire-server bundle show -format spiffe` prints | strict JSON (no duplicate member names, integers only); a JSON object with a non-empty `keys` array; every key an object whose `use` is `x509-svid` or `jwt-svid`; every `x509-svid` key's `x5c` a non-empty array whose first element is the standard base64 of a DER X.509 certificate; `spiffe_sequence` and `spiffe_refresh_hint`, when present, non-negative integers |

A body that is not what its path names is refused with 422.

Rules for all three:

1. **An entry must exist first.** A file never claims a `sovereign_id`; the entry's first publish
   binds the key. An upload with no entry is refused with 409.
2. **Signed by the bound key.** `X-Saltlick-Key` must be the entry's bound key and the request
   signature must verify under it (403 otherwise). A key is rotated through the entry, never
   through a file.
3. **Same limits as an entry:** the 64 KiB body cap and the per-source write budget.
4. **Stored and served byte for byte, with the signature that wrote them.** `GET` carries
   `X-Saltlick-Bound-Key` beside the bytes, and the upload's own `X-Saltlick-Key`,
   `X-Saltlick-Signature` and `X-Saltlick-Resource` (below). Content types: `package` and
   `spiffe-bundle` `application/json`, `ca` `application/pem-certificate-chain`.
5. **Removed with the entry.** Deleting or clearing the entry deletes its files.

**The directory does not compare the files with the entry.** A hosted package is not checked
against the pointer's `package_sha256`, and a hosted CA is not checked against the package's
`identity.ca_fingerprint`: the pointer and the files are written in separate requests, and the
reader makes both checks itself whatever the directory did. The canonical-form rule is what
makes the stored bytes the bytes `package_sha256` is computed over.

**Offers.** The refusal of `transport_offer`, `data_offer` and `cut` applies to the entry, which
is what the listing reads. A hosted package is a file its party chose to publish, served as the
party's own public host would serve it; the listing shows a link to it and takes nothing from it.

The out-of-band act is unchanged: the two parties read each other's verifying key and CA
fingerprint aloud, and a reader checks the hosted files against those, not against the
directory.

### One package per counterparty

A federation package carries one `transport_offer`: one endpoint, one WireGuard key, one
proposed link subnet. A party holding several peerings therefore signs one package per
counterparty, and a single `package` slot would let each upload replace the last. A party keeps
those packages at `/v1/parties/{sovereign_id}/packages/{counterparty}`, one slot per
counterparty:

- The body and its checks are those of `package`, and rules 1 to 5 above apply to each slot.
- `{counterparty}` matches `^[a-z0-9-]{2,16}$` and differs from `{sovereign_id}`: composition
  refuses two packages with one `sovereign_id`, so a slot for oneself can only hold a mistake.
  Otherwise 400.
- The resource line of the upload statement is `<sovereign_id>/packages/<counterparty>`, so the
  served signature records which counterparty the party signed the package for. A reader checks
  that line equals the slot it asked for, exactly as for any hosted file.
- Uploading one slot never changes another slot or `package`.
- `DELETE /v1/parties/{sovereign_id}/packages/{counterparty}` withdraws that one slot when the
  peering ends, leaving the entry, its key binding and every other file; 404 when the slot holds
  nothing. It is signed by the bound key over the statement `DELETE`,
  `<sovereign_id>/packages/<counterparty>`, `sha256:` of **the package being withdrawn** (the
  bytes the slot serves, not the empty request body) and `-`. `saltlick sign -method DELETE
  -upload packages/<counterparty> -file <package>` builds it.
- **What makes a withdrawal final.** Two rules, together:
  1. The withdrawal statement names the bytes it withdraws, so a saved `DELETE` withdraws only
     that package and is refused (403) against any later package in the slot.
  2. The directory keeps the upload signature of every counterparty package that left the
     slot, and refuses (409) a `PUT` presenting it. A package leaves the slot when a `DELETE`
     withdraws it or when it is **superseded**: a later upload with a different signature
     replaces it. A saved `GET` of the slot (body, `X-Saltlick-Key`, `X-Saltlick-Signature`)
     replayed as a `PUT` therefore cannot restore a withdrawn package, nor roll the slot back
     over a newer one to a stale endpoint or key. Re-uploading the package the slot holds now
     (the same signature) supersedes nothing and is accepted. Ed25519 signatures are
     deterministic, so the party itself cannot re-upload bytes that left the slot either: to
     offer that counterparty a package again, it signs and uploads a new one.
  Deleting the entry withdraws its counterparty packages by the same rule 2, so re-claiming the
  name does not let a saved slot upload return. The single `package` slot, the entry `DELETE`
  and its statement are unchanged.
- The directory does not interpret the slot name, does not check that `{counterparty}` has an
  entry, and does not list slots in `GET /v1/parties` or on the home page. Being listed still
  grants nothing, and the directory still computes nothing about who peers with whom; a slot is
  the party's own statement. A slot name is readable by anyone who requests it, so a party that
  does not want a peering visible exchanges that package another way.

The package format, the single `package` slot and the pointer record are unchanged. A party with
one peering, and a reader that does not know about slots, keep working as before.

### Checking a hosted file against the key read aloud

The signed package names its CA through `identity.ca_fingerprint`; nothing in it names the
SPIFFE bundle. So every hosted file is served with the request signature of the upload that
stored it, and a reader checks the bytes against the party's verifying key directly. A `GET` of
a hosted file carries:

| Header | Value |
|---|---|
| `X-Saltlick-Key` | the `X-Saltlick-Key` value the upload presented, exactly as presented: 44 base64 characters, the raw 32-byte Ed25519 key |
| `X-Saltlick-Signature` | the upload's request signature: 88 base64 characters, a 64-byte Ed25519 signature |
| `X-Saltlick-Resource` | `<sovereign_id>/<kind>`: `xaa/package`, `xaa/packages/xab`, `xaa/ca` or `xaa/spiffe-bundle` |

The signature covers exactly these bytes, five lines each ending in a single `\n` (0x0A), no
carriage returns, no trailing whitespace:

```
saltlick-request/v1\n
PUT\n
<sovereign_id>/<kind>\n
sha256:<64 lowercase hex: SHA-256 of the response body exactly as received>\n
<the X-Saltlick-Key value>\n
```

A reader:

1. Checks that `X-Saltlick-Key` equals the verifying key the two parties read aloud.
2. Checks that `X-Saltlick-Resource` is the sovereign_id and kind it asked for; the directory
   sends it for convenience, and the reader builds line 3 from its own request.
3. Builds the statement above from the body it received.
4. Verifies `X-Saltlick-Signature` over it with Ed25519 (RFC 8032, pure, no prehash) under the
   key read aloud.

A file that fails is not the party's. The `X-Saltlick-Key` names the key that wrote the file,
which after a rotation of the entry's key differs from `X-Saltlick-Bound-Key` until the party
uploads the file again. A file stored without a signature is served without the three headers.

## Write authenticity — and what it is NOT

Anyone may read. Writes need to be controlled or one party could overwrite another's entry.

**Trust on first use.** The first publish for a `sovereign_id` binds the verifying key supplied
with that request. Every later write to that `sovereign_id` must carry a signature that
verifies under the bound key. Same shape as SSH host keys.

**This must be documented at the API and in the code as protecting the directory's own record
— nothing more.** It does not establish that the party is who it claims. A consumer must still
bind that key out of band, exactly as `goat federate compose` requires. If this ever gets
described as "verified party," the invariant has quietly broken.

Rotation: an entry's bound key may be replaced by a request signed by the *current* key. Losing
the key means an operator must clear the entry — a plainly administrative act, logged.

## API

```
GET    /v1/parties                          list: sovereign_id, spec, issued (packages only), expires,
                                            expired(bool), bound_key, package/ca/spiffe_bundle
                                            (paths, when hosted)
GET    /v1/parties/{sovereign_id}           the stored entry, byte-for-byte as submitted
PUT    /v1/parties/{sovereign_id}           publish or replace; TOFU rules above
DELETE /v1/parties/{sovereign_id}           signed by the bound key; removes the hosted files too
GET    /v1/parties/{sovereign_id}/package   the hosted package, byte-for-byte (application/json)
PUT    /v1/parties/{sovereign_id}/package   host or replace it; rules above
GET    /v1/parties/{sovereign_id}/packages/{counterparty}
                                            the package the party signed for one counterparty,
                                            byte-for-byte (application/json)
PUT    /v1/parties/{sovereign_id}/packages/{counterparty}
                                            host or replace it; rules above
DELETE /v1/parties/{sovereign_id}/packages/{counterparty}
                                            withdraw that one package, for good; signed by the
                                            bound key over the withdrawn package's sha256
GET    /v1/parties/{sovereign_id}/ca        the hosted CA certificate(s), byte-for-byte
                                            (application/pem-certificate-chain)
PUT    /v1/parties/{sovereign_id}/ca        host or replace them; rules above
GET    /v1/parties/{sovereign_id}/spiffe-bundle
                                            the hosted SPIFFE trust bundle, byte-for-byte
                                            (application/json)
PUT    /v1/parties/{sovereign_id}/spiffe-bundle
                                            host or replace it; rules above
GET    /healthz                             liveness
GET    /v1/spec                             which entry formats this instance accepts
```

Every write carries `X-Saltlick-Key` (except DELETE) and `X-Saltlick-Signature`, an Ed25519
signature over the request statement: five newline-terminated lines `saltlick-request/v1`, the
method, the path below `/v1/parties/` (`<sovereign_id>`, `<sovereign_id>/package`,
`<sovereign_id>/packages/<counterparty>`, `<sovereign_id>/ca` or `<sovereign_id>/spiffe-bundle`), `sha256:` + hex of the body (for a counterparty package's `DELETE`, of the package withdrawn), and the presented key or `-`. The path line
keeps a signature for one resource from being replayed against another.

`GET` returns the submitted bytes **unaltered** — a consumer must be able to verify the
signature over exactly what was signed. Never re-serialise, re-order, or pretty-print stored
package bytes.

**Expiry is reported, not enforced.** An expired package is still served, flagged
`expired: true`. Refusing to serve it would be the directory making a decision. Advisory means
the consumer decides.

## Non-goals, stated so they do not creep in

- No accounts, no organisations, no roles, no approval workflow.
- No notion of a relationship between two parties. The directory never knows who peers with whom.
- No brokering, no matchmaking, no "compatible partners" endpoint that ranks anyone.
- No federation *between* directory instances. Each coalition runs its own; there is no global
  directory and no attempt to build one.

## Build constraints

- **No dependency on the goat monorepo.** This repository must be self-hostable and is expected
  to be open-sourced. Another organisation stands up their own instance from this repo alone.
- **Go**, single static binary, so a coalition body can run it without a toolchain.
- **SQLite** for storage — one file, trivially backed up, no external database to operate.
- Container image, and Terraform to stand one up.
- Tests must cover: TOFU binding, rejection of a second party overwriting an entry, rejection of
  `transport_offer`/`data_offer`/`cut` in an entry, byte-exact round-trip of stored bytes,
  expired-but-served, and for hosted files every refusal above, the round trip, and that the
  served signature verifies under the writer's key and fails for altered bytes.

## Governance

Whoever convenes a coalition runs its instance. Each coalition or alliance runs its
own. The name is the invariant restated: mountain goats travel real distances to a mineral lick,
a known fixed location that nobody owns, and being there grants you nothing.
