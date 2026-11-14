# AGENTS.md

Instructions for AI coding agents, and a short version for anyone working here. [CONTRIBUTING.md](CONTRIBUTING.md) is the full process.

## What this repository is

saltlick is a directory service where an organization publishes its own interconnection capability, so that two organizations can check compatibility before they build a link. It is used with [goat](https://github.com/USAREUR-AF/goatcore) federation. Its invariant: the directory is advisory, never authoritative; an entry grants access to nothing, and federation works with the service switched off. `SPEC.md` is the authority for behavior.

One Go binary with a SQLite store (`modernc.org/sqlite`, no cgo).

## Layout

| Path | What |
|---|---|
| `cmd/saltlick/` | the binary: `serve`, `keygen`, `sign`, `clear`, `log` |
| `internal/httpapi/` | the HTTP surface and rate limits; the package comment states what may not be added |
| `internal/pkgv1/` | reading packages and pointer records; the checks on upload |
| `internal/writeauth/` | trust-on-first-use write control |
| `internal/canonical/` | strict JSON reading and RFC 8785 canonical form, for signature checks |
| `internal/store/` | the SQLite store |
| `deploy/`, `terraform/` | running an instance: Docker Compose with Caddy, and an AWS module |
| `SPEC.md` | the specification |

## Before you push

CI (`.github/workflows/ci.yml`) runs these:

```bash
make check                                   # gofmt, go vet, go test
go build ./...
go test -race -count=1 ./...
docker build -t saltlick:dev .               # or: make image
terraform -chdir=terraform fmt -check -recursive -diff
```

A change to behavior updates `SPEC.md` in the same pull request. Do not add anything that makes the directory an authorization source or that federation would come to depend on.

## Rules

1. **Nothing from a real deployment.** No hostname, domain, address, key or person of a real goatnet goes into a file or a commit message. Use made-up names, documentation addresses (RFC 5737) and `example.org` mail.
2. **Commits.** Conventional Commits subject of 100 characters or fewer, with a scope (`fix(<component>): …`). Every commit is signed off (`git commit -s`, the DCO) and signed with a key GitHub verifies. The organization's required check `verified-commits` refuses a pull request that holds an unverified commit.
3. **One logical change per pull request.**
4. **Vulnerabilities** go through [SECURITY.md](SECURITY.md), never a public issue.

The contribution guide for goat as a whole is [goatcore CONTRIBUTING.md](https://github.com/USAREUR-AF/goatcore/blob/main/CONTRIBUTING.md).
