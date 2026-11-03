# Self-hosting saltlick

**This is the expected way to run the directory.** A coalition body runs it
inside their own network, on their own hardware or a small VM. One
`docker compose up` gets you the service, a persistent database volume, and TLS.

Running it in AWS instead is possible — see [`../terraform/`](../terraform/) —
but it costs about $27/month to do what a $6 VM does here.

## It is not meant to be internet-facing

The directory runs on your internal network, reachable by your operators and
the coalition members you have already attached to that network. The defaults
here enforce that: the ports bind to loopback until you set `BIND_ADDR`, and
TLS uses a local CA rather than a public one.

That is a decision, not an oversight, and it follows from what the directory is:

- **Being listed grants nothing.** The directory is advisory. It is not a trust
  root and not an authorisation source, so exposing it widely buys nothing.
- **Packages are self-verifying.** A consumer checks the signature on the bytes
  themselves, against a key bound over a channel authenticated independently of
  this service. Fetching over a private network loses nothing a consumer needed.
- **Federation works with the directory switched off.** Two parties compose
  independently and compare a digest. If reaching the directory were ever
  required, that property would already be broken.

The accepted consequence is real: **a partner outside your network cannot fetch
from your instance.** They exchange packages with you directly instead, which is
slower and manual. If that becomes the binding constraint — a partner who
genuinely cannot fetch, and direct exchange too slow to live with — that is the
moment to revisit it, not before.

## Requirements

- Docker with the Compose plugin.
- A hostname that resolves, on your internal network, to this machine.
- Roughly 256 MB of RAM and a few hundred megabytes of disk. The directory
  holds a few kilobytes per party.

No public DNS, no public IP, no inbound firewall rule from the internet.

## Run it

```sh
cp .env.example .env      # set SALTLICK_DOMAIN and BIND_ADDR
docker compose up -d
docker compose logs -f
```

`BIND_ADDR` defaults to `127.0.0.1`, which is right for a first run and useless
to anyone else. Set it to this host's address on your internal network once you
are happy.

Then check it:

```sh
curl https://directory.internal.example/healthz
curl https://directory.internal.example/v1/spec
curl https://directory.internal.example/v1/parties
```

## TLS

By default Caddy runs a small local CA and issues itself a certificate — zero
configuration, works immediately. Clients must trust that CA's root, so hand it
out:

```sh
docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt .
```

If you already have a CA, use it instead: put the certificate and key in
`./certs/` and swap the `tls internal` line in the `Caddyfile` for

```
tls /etc/caddy/certs/cert.pem /etc/caddy/certs/key.pem
```

TLS here is transport hygiene and nothing more. It is not what makes a package
trustworthy — a consumer verifies the signature over the bytes themselves,
against a key bound out of band. Serving over plaintext would still be wrong,
because it invites someone on the path to alter bytes in flight and waste a
consumer's time.

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
# set SALTLICK_IMAGE in .env to the new tag
docker compose pull && docker compose up -d
```

The volume is untouched, so entries and their key bindings survive.

## Run exactly one

The database is SQLite. One process writes it. Do not run two saltlick
containers against the same volume, and do not put the volume on a network file
system shared with another host. If the directory ever needs more capacity, give
it a bigger machine — it is serving a few kilobytes per party to a handful of
readers, so this will not come up.

## Behind an existing reverse proxy

If you already terminate TLS somewhere — nginx, HAProxy, a corporate ingress —
delete the `caddy` service and the `caddy_data` / `caddy_config` volumes from
`docker-compose.yml`, and give `saltlick` a port mapping instead:

```yaml
    ports:
      - "${BIND_ADDR:-127.0.0.1}:8080:8080"
```

Point your proxy at it and terminate TLS there.
