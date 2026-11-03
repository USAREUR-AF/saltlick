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
GET    /v1/parties                    list: sovereign_id, issued, expires, expired(bool)
GET    /v1/parties/{sovereign_id}     the stored package, byte-for-byte as submitted
PUT    /v1/parties/{sovereign_id}     publish or replace; TOFU rules above
DELETE /v1/parties/{sovereign_id}     signed by the bound key
GET    /healthz                       liveness
GET    /v1/spec                       which package spec version this instance accepts
```

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
  `transport_offer`/`data_offer`/`cut`, byte-exact round-trip of stored bytes, expired-but-served.

## Governance

Whoever convenes a coalition runs its instance. Each coalition or alliance runs its
own. The name is the invariant restated: mountain goats travel real distances to a mineral lick,
a known fixed location that nobody owns, and being there grants you nothing.
