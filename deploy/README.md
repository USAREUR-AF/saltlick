# Self-hosting saltlick

**This is the expected way to run the directory.** A coalition body runs it on
one small host reachable from the internet — its own hardware or a small VM —
outside every party's private network. One `docker compose up` gets you the
service, a persistent database volume, and a public TLS certificate.

Running it in AWS instead is possible — see [`../terraform/`](../terraform/) —
but it costs about $27/month to do what a $6 VM does here.

## What faces the internet

| Port | Serves |
|---|---|
| 80 | The ACME HTTP-01 challenge, then a redirect to 443 |
| 443 | The directory, over TLS |

The directory container has no host port; only Caddy reaches it. Why exposing
it is safe, and what protects it, is in the [top-level README](../README.md#where-it-runs):
entries are self-verifying, writes are signed and trust-on-first-use, offer
blocks are refused, and the service grants nothing. Caddy caps a body at
64 KiB; the service rate-limits each source.

## Requirements

| | |
|---|---|
| Docker | with the Compose plugin |
| Public DNS | an A (or AAAA) record for `SALTLICK_DOMAIN` pointing at this host |
| Inbound firewall | TCP 80 and 443 open from the internet |
| Host | roughly 256 MB of RAM and a few hundred megabytes of disk; the directory holds a few kilobytes per party |

## Run it

```sh
cp .env.example .env      # set SALTLICK_DOMAIN and SALTLICK_IMAGE
docker compose up -d
docker compose logs -f
```

Caddy obtains the certificate on first start. Then check it from anywhere:

```sh
curl https://directory.example/healthz
curl https://directory.example/v1/spec
curl https://directory.example/v1/parties
```

## Settings

| `.env` key | Default | Sets |
|---|---|---|
| `SALTLICK_DOMAIN` | — (required) | The public hostname Caddy serves and certifies |
| `SALTLICK_IMAGE` | — (required) | The image, pinned: `ghcr.io/usareur-af/saltlick:<tag>@sha256:<digest>`; the release workflow prints the digest |
| `BIND_ADDR` | `0.0.0.0` | The interface Caddy listens on for 80 and 443 |
| `SALTLICK_SUBNET` | `172.30.53.0/24` | The compose network; the service believes `X-Forwarded-For` only from it |
| `SALTLICK_READ_LIMIT` / `_READ_BURST` | `10/s` / `30` | Per-source read budget |
| `SALTLICK_WRITE_LIMIT` / `_WRITE_BURST` | `6/m` / `6` | Per-source write budget |

Caddy replaces any `X-Forwarded-For` a client sends with the address it saw,
and the service trusts that header only from `SALTLICK_SUBNET`, so the rate
limits count the real client.

## TLS

By default Caddy gets a certificate from Let's Encrypt for `SALTLICK_DOMAIN`
and renews it. Nothing to configure beyond the DNS record and open ports.

On a private network, where no ACME challenge can be answered, use one of the
alternatives documented in the `Caddyfile`:

| Alternative | Caddyfile line | Clients must |
|---|---|---|
| Caddy's local CA | `tls internal` | trust the root: `docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt .` |
| Your own CA | `tls /etc/caddy/certs/cert.pem /etc/caddy/certs/key.pem`, files in `./certs/` | trust your CA |

TLS is transport hygiene. It is not what makes a package trustworthy — a
consumer verifies the signature over the bytes themselves, against a key bound
out of band. Plaintext would still be wrong, because it invites someone on the
path to alter bytes in flight and waste a consumer's time.

## Where the data lives

The database is in the `saltlick_data` Docker volume, mounted at `/data` inside
the container. It survives `docker compose restart`, `docker compose down`, host
reboots, and image upgrades. It does **not** survive `docker compose down -v`,
which deletes volumes.

It is **three** files, not one. SQLite runs in write-ahead-log mode:

```
/data/saltlick.db
/data/saltlick.db-wal    recently committed writes live here
/data/saltlick.db-shm
```

Two consequences. Mount the directory, never the single `.db` file — the volume
above already does this, and it is the thing not to "simplify" later. And back
up all three: a copy of `saltlick.db` alone can be missing writes that were
still in the WAL.

## Backups

Stop the service first. A copy taken while SQLite is writing can catch it
mid-transaction, and a clean shutdown folds the WAL back into the database:

```sh
docker compose stop saltlick
docker run --rm -v saltlick_saltlick_data:/data -v "$PWD:/out" \
  alpine cp -a /data/. /out/backup/
docker compose start saltlick
```

That is a few seconds of downtime for an advisory directory, which is a fair
trade. If you must copy without stopping, take all three files in one command
and accept that the result is best-effort.

The container image is distroless and has no shell, so `docker compose exec
saltlick sh` will not work — go through a helper container as above.

Losing the database costs every party their published entry and their
trust-on-first-use key binding, and each would have to republish.

## Upgrading

```sh
# set SALTLICK_IMAGE in .env to the new tag and digest
docker compose pull && docker compose up -d
```

The volume is untouched, so entries, their key bindings and their hosted files survive. On
start the service adds any column the current schema has and the database lacks; there is
nothing to run by hand.

## Run exactly one

The database is SQLite. One process writes it. Do not run two saltlick
containers against the same volume, and do not put the volume on a network file
system shared with another host. If the directory ever needs more capacity, give
it a bigger machine — it is serving a few kilobytes per party to a handful of
readers, so this will not come up.

## Behind an existing reverse proxy

If you already terminate TLS somewhere — nginx, HAProxy, a cloud load
balancer — delete the `caddy` service and the `caddy_data` / `caddy_config`
volumes from `docker-compose.yml`, and give `saltlick` a port mapping instead:

```yaml
    ports:
      - "${BIND_ADDR:-0.0.0.0}:8080:8080"
```

Set `SALTLICK_TRUSTED_PROXIES` to your proxy's address (CIDRs, comma-separated)
so the rate limits count the client rather than the proxy, make the proxy set
`X-Forwarded-For`, cap bodies at 64 KiB there too, and terminate TLS there.
