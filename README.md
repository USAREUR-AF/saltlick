# saltlick

A directory where an organisation publishes its own interconnection capability, so that two
organisations can check compatibility before they build a link between them. It is modelled on
PeeringDB, the database internet network operators consult before turning up a BGP session.

An entry is an ordinary [federation package](SPEC.md) carrying only the always-required blocks:
who the party is, what its trust anchor is, and what its fabric can do.

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

## It is deliberately not internet-facing

The directory runs mesh-internal. `saltlick serve` binds `127.0.0.1:8080` unless told
otherwise; the container image sets `SALTLICK_ADDR=:8080` because there the network namespace
is the boundary.

A partner may therefore be unable to fetch from it, and that is tolerated rather than worked
around. A package is self-verifying: it carries its own signature over its own canonical form,
and the verifying key was bound over a channel that has nothing to do with this service. So a
partner who cannot reach the directory is not blocked — the package goes over any channel that
can carry a file, and it is exactly as trustworthy on arrival. Nothing here needs to be
reachable for two parties to federate.

The point to revisit this is a partner who cannot fetch **and** for whom exchanging the file by
other means is too slow. Until then, exposing the directory buys nothing that the file transfer
does not already give, and costs an internet-facing surface.

## What an entry may and may not carry

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

To stand an instance up rather than run it locally: `deploy/` is docker compose plus Caddy for
TLS, which is the expected way a coalition body runs this. `terraform/` puts one instance on
AWS behind an internal load balancer, for operators who already run there.

### Subcommands

| Command | Does |
|---|---|
| `saltlick serve [-addr :8080] [-db saltlick.db]` | Run the directory |
| `saltlick keygen [-out xaa]` | Generate an Ed25519 keypair in the encoding the API expects |
| `saltlick sign -key xaa.key -package xaa.json -out xaa.signed.json` | Sign a package; print the publish headers on stderr |
| `saltlick sign -key xaa.key -method DELETE -id xaa` | Print the header a delete needs |
| `saltlick clear -db saltlick.db -id xaa -reason "key lost"` | Release a binding; logged |
| `saltlick log -db saltlick.db` | Print the administrative log |

`clear` is deliberately not an HTTP endpoint. A party that has lost its signing key cannot
rotate, because a replacement key must be authorised by the key it replaces. Removing the entry
is an administrative act by an operator with the database file, and it is recorded.

## API

| Method | Path | Does |
|---|---|---|
| `GET` | `/v1/parties` | List: `sovereign_id`, `issued`, `expires`, `expired`, `bound_key` |
| `GET` | `/v1/parties/{sovereign_id}` | The stored package, byte-for-byte as submitted |
| `PUT` | `/v1/parties/{sovereign_id}` | Publish or replace |
| `DELETE` | `/v1/parties/{sovereign_id}` | Signed by the bound key |
| `GET` | `/v1/spec` | Which package spec version this instance accepts |
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

It binds the method, the `sovereign_id`, the body and the key presented, so none of the four
can be swapped for another. `saltlick sign` builds and signs it for you.

### GET returns the submitted bytes unaltered

Not re-serialised, not re-ordered, not pretty-printed, not wrapped in an envelope. A consumer
must be able to verify a signature over exactly what was signed, and each of those
transformations breaks that while leaving the response looking correct. Directory metadata
therefore travels in headers:

| Header | On |
|---|---|
| `X-Saltlick-Expired` | `GET /v1/parties/{id}` |
| `X-Saltlick-Bound-Key`, `X-Saltlick-Issued`, `X-Saltlick-Expires` | `GET /v1/parties/{id}` |
| `X-Saltlick-Advisory` | Every response |

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

Write the package. Only the always-required blocks:

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
curl -X PUT http://localhost:8080/v1/parties/xaa \
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
curl -s http://localhost:8080/v1/parties/xaa -o fetched.json
cmp xaa.signed.json fetched.json && echo identical
```

Delete:

```bash
curl -X DELETE http://localhost:8080/v1/parties/xaa \
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
| `internal/writeauth/writeauth.go` | Trust-on-first-use, and what it explicitly does not establish |
| `internal/canonical/` | Strict JSON reading and RFC 8785 canonicalisation, for signature checking |
| `internal/store/store.go` | SQLite. The `package` column holds the submitted bytes as a BLOB |
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

