# saltlick

A directory where an organisation publishes its own interconnection capability, so that two
organisations can check compatibility before they build a link between them. It is modelled on
PeeringDB, the database internet network operators consult before turning up a BGP session.

The directory holds pointers, not permissions. The expected entry is a signed **pointer
record**: where the party's signed package can be fetched, and that package's digest. A
recognition-only [federation package](SPEC.md) — who the party is, what its trust anchor is,
what its fabric can do — is accepted too. The body's `spec` member says which it is.

## The invariant

**Advisory, never authoritative. Being listed grants access to nothing.**

The service's only job is to stop two competent parties from misconfiguring each other. It is
not a trust root, not an authorisation source, and not a party to any agreement. Two
consequences follow, and both are enforced in code rather than left to documentation:

**The directory does not decide whether a party is who it claims to be.** It stores and serves
bytes. Write control here is trust-on-first-use, the same shape as an SSH host key: it stops
one party overwriting another's entry, and establishes nothing about identity. A consumer binds
a party's verifying key over a channel authenticated independently of this service — a call to
a voice you recognise, a meeting, a courier. A key learned only from a directory is a key
learned from whoever runs the directory.

**Federation works with this service switched off.** Two parties compose independently with the
same versioned tool and compare one digest. That needs no server and works with an entirely
offline partner. Nothing in the federation mechanism may come to require the directory.

`SPEC.md` is the authority. This file is how to run what it describes.

## Where it runs

The directory is a neutral meeting place outside every party's private network. Any party
reaches it over the internet, over public TLS. It sits inside no party's mesh or VPN, so no
party has to attach another to its network to use it.

Exposure is safe because the service grants nothing and nothing it serves is trusted:

| Property | What it means for an internet-reachable instance |
|---|---|
| Entries are self-verifying | A package carries a signature over its own canonical form. A consumer checks it against a key bound out of band, so a tampered or forged entry fails at the consumer |
| Writes are trust-on-first-use | The first `PUT` for a `sovereign_id` binds the key it presents; every later write must be signed by that key |
| Offers are refused in entries | An entry carrying `transport_offer`, `data_offer` or `cut` is refused with HTTP 422, so the listing never shows reachability, release sets or contacts |
| Hosted files are the party's own | A party with no public host keeps its signed package, CA certificate and SPIFFE trust bundle beside its entry; each is signed by the entry's key, checked on upload, and served byte for byte with the upload's signature for the reader to verify |
| No accounts | There is nothing to log in to and no credential to steal. Authentication would protect nothing, because nothing served is trusted |

What it exposes:

| Request | Who |
|---|---|
| `GET` — list, entry, hosted package, CA and SPIFFE bundle, spec, health | Anyone |
| `PUT`, `DELETE` | Anyone holding the bound key; the request is signed |

What protects it:

| Control | Where | Value |
|---|---|---|
| Public TLS | Caddy (ACME) in `deploy/`, ALB with a public ACM certificate in `terraform/` | — |
| Per-source rate limit, reads | the service | 10/s, burst 30 |
| Per-source rate limit, writes | the service | 6/min, burst 6 |
| Body cap | the service, and Caddy in `deploy/` | 64 KiB, HTTP 413 above it |
| Server timeouts | the service | header 10 s, read 30 s, write 30 s, idle 120 s |
| Offer refusal in entries | the service | HTTP 422 |

What it never holds: accounts, passwords, private keys. Offers reach it only inside a package a
party chose to host here.

`saltlick serve` binds `127.0.0.1:8080` for a bare local run. The expected deployment puts it
behind a public TLS proxy or load balancer; the container image sets `SALTLICK_ADDR=:8080` so
that proxy can reach it.

### Per-source rate limits

Each client address has two token buckets: one for reads (`GET`, `HEAD`) and one for writes
(`PUT`, `DELETE`). `/healthz` draws on neither. A request over budget gets HTTP 429 with
`Retry-After` in seconds.

| Flag | Env | Default |
|---|---|---|
| `-read-limit` | `SALTLICK_READ_LIMIT` | `10/s` |
| `-read-burst` | `SALTLICK_READ_BURST` | `30` |
| `-write-limit` | `SALTLICK_WRITE_LIMIT` | `6/m` |
| `-write-burst` | `SALTLICK_WRITE_BURST` | `6` |
| `-trusted-proxies` | `SALTLICK_TRUSTED_PROXIES` | empty |

Rates are `N/s`, `N/m` or `N/h`; `0` turns that budget off.

The client address is the connection's peer, unless the peer falls inside
`-trusted-proxies` (comma-separated CIDRs or addresses). Then `X-Forwarded-For` is read from
the right, skipping trusted hops, and the first address that is not a trusted proxy is the
client. With no trusted proxy set, `X-Forwarded-For` is ignored, because any client can write
it. Set it to the address range of the proxy in front of the service: `deploy/` sets it to the
compose network, `terraform/` to the VPC.

IPv6 clients are counted per /64. A bucket idle long enough to refill is dropped, and each
budget tracks at most 65,536 sources; past that, a new source is refused with 429 until idle
ones age out.

## The pointer record

| Member | Value |
|---|---|
| `spec` | `"saltlick-pointer/v1"` |
| `sovereign_id` | 2–16 characters of `a-z0-9-` |
| `package_url` | absolute `https://` URL of the party's signed package; at most 2048 characters; no userinfo, no fragment |
| `package_sha256` | `"sha256:"` + 64 lowercase hex: SHA-256 of the package's canonical bytes |
| `expires` | `YYYY-MM-DD`; reported, never enforced |
| `signature` | Ed25519 by the party over the RFC 8785 canonical form of the record without `signature` |

Exactly these members; anything else — a key, an identity, a contact, an offer — is refused
with HTTP 422. A pointer has no `issued` date, so its list item and `GET` headers carry none.

A counterparty uses it in four steps, and the directory is an input to none of the checks:

1. `GET /v1/parties/xaa` — the pointer.
2. Fetch the package from `package_url`.
3. Verify the package's signatures against its own trust store.
4. Recompute the package's digest and compare it with `package_sha256`.

## A party with no public host

A party behind NAT keeps its package, CA certificate and SPIFFE trust bundle here. In order:

1. `PUT /v1/parties/xaa` — the pointer, with `package_url` set to
   `https://<this instance>/v1/parties/xaa/package`. This binds the key on first use.
2. `PUT /v1/parties/xaa/package` — the canonical signed package, offers included.
3. `PUT /v1/parties/xaa/ca` — the CA certificate(s), PEM.
4. `PUT /v1/parties/xaa/spiffe-bundle` — the SPIFFE trust bundle, when the party runs SPIRE
   federation: the output of `spire-server bundle show -format spiffe`.

| Upload | Checked |
|---|---|
| `package` | `federation-package/v1`; `sovereign_id` is the path's; RFC 8785 canonical bytes; signature verifies under the entry's bound key |
| `ca` | PEM `CERTIFICATE` blocks only, each an X.509 CA certificate |
| `spiffe-bundle` | A JSON object with a non-empty `keys` array; every key's `use` is `x509-svid` or `jwt-svid`; every `x509-svid` key's `x5c[0]` is the standard base64 of a DER X.509 certificate; `spiffe_sequence` and `spiffe_refresh_hint`, when present, are non-negative integers |

Each needs an existing entry (409 without one) and a request signed by the entry's bound key
(403 otherwise), shares the 64 KiB cap and the write budget, is served byte for byte, and is
deleted with the entry. A body that is not what its path names is refused with 422. The
directory does not compare the files with the pointer: the reader recomputes the digest and
checks the CA's SHA-256 against the package's `identity.ca_fingerprint`.

Each file is served with the signature of the upload that stored it, so a reader checks any of
the three, the SPIFFE bundle included, against the key the two parties read aloud.
[Checking a hosted file's signature](#checking-a-hosted-files-signature) shows how.

### Several peerings: one package per counterparty

A package carries one transport offer: one endpoint, one WireGuard key, one link subnet. A party
that peers with two counterparties signs two packages, and one `package` slot would let the
second replace the first. So a party also keeps one package per counterparty:

5. `PUT /v1/parties/xaa/packages/xab` — the package `xaa` signed for its peering with `xab`.

The counterparty `xab` fetches `GET /v1/parties/xaa/packages/xab`. Each slot is checked exactly
as `package` is, is served byte for byte with its upload signature, and is deleted with the
entry, or withdrawn alone with a signed `DELETE` of its path when the peering ends. A
withdrawal is final: the `DELETE` statement names the bytes withdrawn, and the directory refuses
any upload that has left the slot (withdrawn, or superseded by a later upload with another
signature) if it is ever replayed, so returning needs a newly signed package. The
counterparty name has the form of a `sovereign_id` and is not the party itself (400
otherwise). The upload signature's resource line is `xaa/packages/xab`, so a reader checks under
the key read aloud that `xaa` signed this package for `xab`, not for someone else.

The package format does not change, and the single `package` slot and the pointer keep working
as before; a party with one peering needs neither. The directory does not interpret the slot
name, does not check that the counterparty exists, and does not list slots in the catalogue or
on the home page. A slot name is still readable by anyone who asks for it: a party that does not
want a peering visible exchanges that package out of band or serves it from its own host.

## What a recognition-only package may and may not carry

| Present | Refused |
|---|---|
| `spec`, `sovereign_id`, `issued`, `expires`, `signature` | `transport_offer` — willing to connect |
| `identity` — `trust_domain`, `ca_fingerprint` | `data_offer` — willing to exchange |
| `capabilities` — `transports`, `fabric_fips_image`, `pqc_capable`, `fabric_version` | `cut` — contacts |

Reachability, release sets, accepted limits and cut procedures are sovereign operational
detail. They move directly between two parties, not through a directory that everyone can read.
A submission carrying any of the three blocks is refused with HTTP 422 and a message saying so.

The package format has no tier field: presence is the declaration. A package carrying
`transport_offer` is willing to connect. That is why the refusal is on the block itself and
not on a flag.

## Running it

Requires Go 1.25 to build. The SQLite driver is `modernc.org/sqlite`, which is pure Go, so the
binary is static and needs no cgo, no libc and no external database.

```bash
make build                       # ./saltlick
make test                        # the whole suite
make check                       # gofmt, go vet, go test — the Go half of CI
./saltlick serve -db saltlick.db        # binds 127.0.0.1:8080
```

`-addr`, or `SALTLICK_ADDR`, moves it. `-db`, or `SALTLICK_DB`, names the database file; the
file is created on first start if the directory exists and is writable.

Container:

```bash
make image                       # saltlick:dev, distroless static, non-root
docker run -p 8080:8080 -v saltlick-data:/data saltlick:dev
```

Storage is SQLite in WAL mode, so it is three files — `saltlick.db`, `saltlick.db-wal` and
`saltlick.db-shm`. Persist the **directory**, not the one file: a single-file bind mount loses
the write-ahead log. Back it up by copying all three, or by stopping the service first.

To stand an instance up rather than run it locally: `deploy/` is docker compose plus Caddy with
a public ACME certificate, which is the expected way a coalition body runs this. `terraform/`
puts one instance on AWS behind an internet-facing load balancer, for operators who already run
there.

### Subcommands

| Command | Does |
|---|---|
| `saltlick serve [-addr :8080] [-db saltlick.db] [-trusted-proxies <cidrs>]` | Run the directory; rate-limit flags above |
| `saltlick keygen [-out xaa]` | Generate an Ed25519 keypair in the encoding the API expects |
| `saltlick sign -key xaa.key -package xaa.json -out xaa.signed.json` | Sign a package; print the publish headers on stderr |
| `saltlick sign -key xaa.key -method DELETE -id xaa` | Print the header a delete needs; add `-upload packages/xab -file <that package>` to withdraw only the package for `xab` |
| `saltlick sign -key xaa.key -upload ca -file xaa-ca.pem -id xaa` | Print the headers to host a CA (or `-upload package`, `-upload packages/<counterparty>`, `-upload spiffe-bundle`) beside the entry; the file is sent unchanged |
| `saltlick clear -db saltlick.db -id xaa -reason "key lost"` | Release a binding; logged |
| `saltlick log -db saltlick.db` | Print the administrative log |

`clear` is deliberately not an HTTP endpoint. A party that has lost its signing key cannot
rotate, because a replacement key must be authorised by the key it replaces. Removing the entry
is an administrative act by an operator with the database file, and it is recorded.

## API

| Method | Path | Does |
|---|---|---|
| `GET` | `/v1/parties` | List: `sovereign_id`, `spec`, `issued` (packages only), `expires`, `expired`, `bound_key`, and `package` / `ca` / `spiffe_bundle` paths when hosted |
| `GET` | `/v1/parties/{sovereign_id}` | The stored entry, byte-for-byte as submitted |
| `PUT` | `/v1/parties/{sovereign_id}` | Publish or replace |
| `DELETE` | `/v1/parties/{sovereign_id}` | Signed by the bound key; deletes the hosted files too |
| `GET` | `/v1/parties/{sovereign_id}/package` | The hosted package, byte-for-byte, `application/json` |
| `PUT` | `/v1/parties/{sovereign_id}/package` | Host or replace it; signed by the entry's bound key |
| `GET` | `/v1/parties/{sovereign_id}/packages/{counterparty}` | The package the party signed for one counterparty, byte-for-byte, `application/json` |
| `PUT` | `/v1/parties/{sovereign_id}/packages/{counterparty}` | Host or replace it; signed by the entry's bound key; other counterparties' packages and `package` are untouched |
| `DELETE` | `/v1/parties/{sovereign_id}/packages/{counterparty}` | Withdraw that one package for good when the peering ends; signed by the bound key over the withdrawn package's sha256; everything else stays |
| `GET` | `/v1/parties/{sovereign_id}/ca` | The hosted CA certificate(s), byte-for-byte, `application/pem-certificate-chain` |
| `PUT` | `/v1/parties/{sovereign_id}/ca` | Host or replace them; signed by the entry's bound key |
| `GET` | `/v1/parties/{sovereign_id}/spiffe-bundle` | The hosted SPIFFE trust bundle, byte-for-byte, `application/json` |
| `PUT` | `/v1/parties/{sovereign_id}/spiffe-bundle` | Host or replace it; signed by the entry's bound key |
| `GET` | `/v1/spec` | `spec`: the package format; `accepts`: every entry format, `saltlick-pointer/v1` and `federation-package/v1` |
| `GET` | `/healthz` | Liveness |

Anyone may read. Writes need two headers:

| Header | Value |
|---|---|
| `X-Saltlick-Key` | The 32-byte raw Ed25519 verifying key, base64, 44 characters ending in one `=`. `PUT` only |
| `X-Saltlick-Signature` | Ed25519 signature over the request statement below, base64, 88 characters ending `==` |

The request statement is five newline-terminated lines:

```
saltlick-request/v1
PUT
xaa
sha256:<hex of the request body; the empty string hashed where there is no body>
<the X-Saltlick-Key value, or "-" where there is none>
```

The third line is the path below `/v1/parties/`: `xaa` for the entry, `xaa/package`,
`xaa/packages/xab`, `xaa/ca` or `xaa/spiffe-bundle` for a hosted file. It binds the method, the resource, the body and the key presented, so none of
the four can be swapped for another. `saltlick sign` builds and signs it for you.

### GET returns the submitted bytes unaltered

Not re-serialised, not re-ordered, not pretty-printed, not wrapped in an envelope. A consumer
must be able to verify a signature over exactly what was signed, and each of those
transformations breaks that while leaving the response looking correct. Directory metadata
therefore travels in headers:

| Header | On |
|---|---|
| `X-Saltlick-Expired` | `GET /v1/parties/{id}` |
| `X-Saltlick-Bound-Key`, `X-Saltlick-Expires` | `GET /v1/parties/{id}`; the bound key also on the hosted files |
| `X-Saltlick-Issued` | `GET /v1/parties/{id}`, packages only |
| `X-Saltlick-Key`, `X-Saltlick-Signature`, `X-Saltlick-Resource` | `GET` of a hosted file: the key the upload presented, its request signature, and the statement's resource line |
| `X-Saltlick-Advisory` | Every response |

### Checking a hosted file's signature

A hosted file's `GET` carries the upload's `X-Saltlick-Key`, `X-Saltlick-Signature` and
`X-Saltlick-Resource`. Check that `X-Saltlick-Key` is the key the two parties read aloud,
rebuild the request statement from the headers and the bytes received, and verify the signature
over it with Ed25519 under the key read aloud:

```bash
curl -s -D h.txt https://directory.example/v1/parties/xaa/spiffe-bundle -o bundle.json
hdr() { grep -i "^$1:" h.txt | cut -d' ' -f2 | tr -d '\r'; }
printf 'saltlick-request/v1\nPUT\n%s\nsha256:%s\n%s\n' \
  "$(hdr X-Saltlick-Resource)" "$(sha256sum bundle.json | cut -d' ' -f1)" "$(hdr X-Saltlick-Key)" > statement
hdr X-Saltlick-Signature | base64 -d > sig
# the key read aloud, as an OpenSSL public key
{ printf '302a300506032b6570032100' | xxd -r -p; printf '%s' "<key read aloud>" | base64 -d; } |
  openssl pkey -pubin -inform DER -out xaa.pub.pem
openssl pkeyutl -verify -pubin -inkey xaa.pub.pem -rawin -in statement -sigfile sig
```

`statement` is the exact byte string the signature covers. `X-Saltlick-Key` is the key that
wrote the file; after the entry's key rotates it differs from `X-Saltlick-Bound-Key` until the
party uploads the file again.

### Expiry is reported, never enforced

An expired package is still served, with `X-Saltlick-Expired: true` and `"expired": true` in the
list. Refusing to serve it would be the directory deciding something on the consumer's behalf,
and a consumer may well want it — to see what a party last published, and whom to chase.
Publishing an already-expired package is likewise allowed.

### Write control: trust on first use

1. **No entry yet.** The presented key is bound, on the writer's say-so alone. The request
   signature must verify under it, which proves the writer holds the key and nothing more.
2. **An entry exists, same key.** The request signature must verify under the bound key.
3. **An entry exists, a different key.** This is a rotation. The request signature must verify
   under the **current** key — the one being replaced — and the package must be re-signed under
   the new one, so the stored entry still verifies under the key the directory advertises for
   it. Rotations are written to the administrative log, which makes a directory compromise
   detectable after the fact.

A second party's key cannot overwrite an existing entry: HTTP 403, with a message saying a
different key is already bound.

## Publishing an entry

```bash
saltlick keygen -out xaa
```

Read the verifying key to your counterparty in eleven groups of four characters, state the
group count first, and have them read it back. That human step is what binds the key. This
directory is a cache of that binding, never its source.

Write the pointer, naming where your signed package is served and its digest:

```bash
cat > xaa.pointer.json <<'EOF'
{
  "spec": "saltlick-pointer/v1",
  "sovereign_id": "xaa",
  "package_url": "https://xaa.example/federation-package.json",
  "package_sha256": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "expires": "2026-12-06"
}
EOF
saltlick sign -key xaa.key -package xaa.pointer.json -out xaa.pointer.signed.json
```

and publish it as below. A recognition-only package instead carries only the always-required
blocks:

```bash
cat > xaa.json <<'EOF'
{
  "spec": "federation-package/v1",
  "sovereign_id": "xaa",
  "issued": "2026-09-06",
  "expires": "2026-12-06",
  "identity": {
    "trust_domain": "spiffe://xaa.example",
    "ca_fingerprint": "sha256:d49211cac3357142f3cf9c2ee216cdd452793ce89428d5ea856f9f62e71efe55"
  },
  "capabilities": {
    "transports": ["ipsec-fips", "wireguard"],
    "fabric_fips_image": true,
    "pqc_capable": true,
    "fabric_version": "1.9.0"
  }
}
EOF
```

Sign it. The signed package goes to stdout or `-out`; the two headers go to stderr.

```bash
saltlick sign -key xaa.key -package xaa.json -out xaa.signed.json
# X-Saltlick-Key: pLgCyHH6SH7N02G9sFrWG1wODsv0PT434mlFj8H5X64=
# X-Saltlick-Signature: Yi/jkhGxt3ZjimFb3Gw51TxhOfWTuHPZ37PcbhlB3wCCd50lEMZzOYXT1THSSJIAsNEwMnhk51F5KC8Z49tzBg==
```

Publish:

```bash
curl -X PUT https://directory.example/v1/parties/xaa \
  -H "X-Saltlick-Key: pLgCyHH6SH7N02G9sFrWG1wODsv0PT434mlFj8H5X64=" \
  -H "X-Saltlick-Signature: Yi/jkhGxt3ZjimFb3Gw51TxhOfWTuHPZ37PcbhlB3wCCd50lEMZzOYXT1THSSJIAsNEwMnhk51F5KC8Z49tzBg==" \
  --data-binary @xaa.signed.json
```

```json
{
  "sovereign_id": "xaa",
  "issued": "2026-09-06",
  "expires": "2026-12-06",
  "expired": false,
  "bound_key": "pLgCyHH6SH7N02G9sFrWG1wODsv0PT434mlFj8H5X64=",
  "first_use": true,
  "rotated": false,
  "advisory": "advisory only: being listed in this directory grants access to nothing, and this service does not establish that any party is who it claims to be"
}
```

Read it back and confirm the bytes are unchanged:

```bash
curl -s https://directory.example/v1/parties/xaa -o fetched.json
cmp xaa.signed.json fetched.json && echo identical
```

Host a CA certificate beside the entry (the package and the SPIFFE bundle the same way, with
`-upload package` and `-upload spiffe-bundle`):

```bash
saltlick sign -key xaa.key -upload ca -file xaa-ca.pem -id xaa
# X-Saltlick-Key: pLgCyHH6SH7N02G9sFrWG1wODsv0PT434mlFj8H5X64=
# X-Saltlick-Signature: <88 characters>
curl -X PUT https://directory.example/v1/parties/xaa/ca \
  -H "X-Saltlick-Key: ..." -H "X-Saltlick-Signature: ..." --data-binary @xaa-ca.pem
```

Delete:

```bash
curl -X DELETE https://directory.example/v1/parties/xaa \
  -H "X-Saltlick-Signature: $(saltlick sign -key xaa.key -method DELETE -id xaa | cut -d' ' -f2)"
```

`sovereign_id` values in these examples come from the ISO 3166-1 user-assigned range
(`xaa`–`xzz`), which is reserved so that private use cannot collide with a real assignment. A
fixture copied into production cannot collide with an actual party.

## Non-goals

Stated so they do not creep in, and enforced by
`TestNoRankingOrMatchingEndpointExists` in `internal/httpapi/server_test.go`:

- **No ranking, matching or brokering.** No "compatible partners" endpoint, no sort by
  capability, no filter. The directory never knows who peers with whom. A query answering
  "which parties could xaa federate with" makes the operator of the box a broker, and makes its
  answer an input to somebody's decision.
- **No accounts, organisations, roles or approval workflow.**
- **No enforcement.** No refusing to serve an expired package, no "verified" flag.
- **No federation between directory instances.** Each coalition runs its own. There is no global
  directory and no attempt to build one.

Every feature request of the form "could the directory also check X" is a request to make it
load-bearing.

## Layout

| Path | Holds |
|---|---|
| `cmd/saltlick/main.go` | The binary: `serve`, `keygen`, `sign`, `clear`, `log` |
| `internal/httpapi/server.go` | The HTTP surface. Its package comment states what may not be added and why |
| `internal/pkgv1/package.go` | Reading a package as a directory entry; the offer-block refusal |
| `internal/pkgv1/pointer.go` | Reading a pointer record |
| `internal/pkgv1/hosted.go`, `internal/pkgv1/spiffe.go` | Checking a hosted package, CA and SPIFFE bundle on upload |
| `internal/writeauth/writeauth.go` | Trust-on-first-use, and what it explicitly does not establish |
| `internal/canonical/` | Strict JSON reading and RFC 8785 canonicalisation, for signature checking |
| `internal/store/store.go` | SQLite. The `package` and hosted `body` columns hold the submitted bytes as a BLOB; each hosted file keeps the key and signature that wrote it |
| `internal/httpapi/ratelimit.go` | Per-source token buckets and the client-address rule |
| `deploy/`, `terraform/` | Running an instance: docker compose with Caddy, and an AWS module |

`internal/canonical` exists because the standard library's JSON decoder keeps the last of two
members with the same name, discards the source text of a number, and substitutes U+FFFD for
invalid UTF-8. Each of those silently changes the bytes a signature was computed over.

`internal/pkgv1/testdata/full-offer-xaa.json` is the `compose-full` conformance vector,
copied verbatim, with its published test key. `TestConformanceVectorRoundTripsAndVerifies`
checks this repository's canonicalisation against a signature produced by a different
implementation; `TestRefusesAValidPackageThatCarriesAnOffer` checks that a real, valid,
correctly signed package is still refused as a directory entry.

## Governance

Each coalition or alliance runs its own instance. There is no global one.

The name restates the invariant: mountain goats travel real distances to a mineral lick, a
known fixed location that nobody owns, and being there grants you nothing.

## Licence

`saltlick` was written by U.S. Federal government employees. In the U.S. it is not subject to copyright and is in the public domain; in countries where copyright is recognized, it is released under the [Apache License 2.0](LICENSE). See [INTENT.md](INTENT.md).
