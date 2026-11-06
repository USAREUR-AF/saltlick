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

A party behind NAT, with no public host of its own, keeps two files beside its entry, and its
pointer's `package_url` names this instance's own `/v1/parties/{sovereign_id}/package`:

| File | Body | Checked on upload |
|---|---|---|
| `package` | the party's complete signed federation package, offers included | `spec` is `federation-package/v1`; `sovereign_id` equals the path's; the body is in RFC 8785 canonical form; its signature verifies under the entry's bound key |
| `ca` | one or more PEM `CERTIFICATE` blocks, nothing else but whitespace | each block parses as an X.509 certificate with the CA flag set |

Rules for both:

1. **An entry must exist first.** A file never claims a `sovereign_id`; the entry's first publish
   binds the key. An upload with no entry is refused with 409.
2. **Signed by the bound key.** `X-Saltlick-Key` must be the entry's bound key and the request
   signature must verify under it (403 otherwise). A key is rotated through the entry, never
   through a file.
3. **Same limits as an entry:** the 64 KiB body cap and the per-source write budget.
4. **Stored and served byte for byte.** `GET` carries `X-Saltlick-Bound-Key` beside the bytes.
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
                                            expired(bool), bound_key, package/ca (paths, when hosted)
GET    /v1/parties/{sovereign_id}           the stored entry, byte-for-byte as submitted
PUT    /v1/parties/{sovereign_id}           publish or replace; TOFU rules above
DELETE /v1/parties/{sovereign_id}           signed by the bound key; removes the hosted files too
GET    /v1/parties/{sovereign_id}/package   the hosted package, byte-for-byte (application/json)
PUT    /v1/parties/{sovereign_id}/package   host or replace it; rules below
GET    /v1/parties/{sovereign_id}/ca        the hosted CA certificate(s), byte-for-byte
                                            (application/pem-certificate-chain)
PUT    /v1/parties/{sovereign_id}/ca        host or replace them; rules below
GET    /healthz                             liveness
GET    /v1/spec                             which entry formats this instance accepts
```

Every write carries `X-Saltlick-Key` (except DELETE) and `X-Saltlick-Signature`, an Ed25519
signature over the request statement: five newline-terminated lines `saltlick-request/v1`, the
method, the path below `/v1/parties/` (`<sovereign_id>`, `<sovereign_id>/package` or
`<sovereign_id>/ca`), `sha256:` + hex of the body, and the presented key or `-`. The path line
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
  expired-but-served, and for hosted files every refusal above and the round trip.

## Governance

Whoever convenes a coalition runs its instance. Each coalition or alliance runs its
own. The name is the invariant restated: mountain goats travel real distances to a mineral lick,
a known fixed location that nobody owns, and being there grants you nothing.
