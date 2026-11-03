# Running saltlick on AWS

One instance of the directory on an internal network, behind TLS, with the
SQLite file on storage that survives a task restart. About 200 lines of
Terraform in six files, meant to be read and adapted rather than consumed as a
black box.

**Most operators do not need this.** Running the directory on your own hardware
is simpler, cheaper, and the expected case for a coalition body — see
[`../deploy/`](../deploy/). Use this if you already run in AWS and want the
directory there too.

## It is deliberately not internet-facing

The load balancer is internal. It holds private addresses only and has no path
from the internet, and the default `allowed_cidr_blocks` is the VPC's own CIDR
— nothing outside the VPC reaches it until you say so.

That is a decision, not an omission, and it follows from what the directory is:

- **Being listed grants nothing.** The directory is advisory. It is not a trust
  root and not an authorisation source, so exposing it widely buys nothing.
- **Packages are self-verifying.** A consumer checks the signature on the bytes
  themselves, against a key bound over a channel authenticated independently of
  this service. Fetching over a private network loses nothing a consumer needed.
- **Federation works with the directory switched off.** Two parties compose
  independently and compare a digest. If reaching the directory were ever
  required, that property would already be broken.

The accepted consequence is real and worth stating plainly: **a partner outside
your network cannot fetch from your instance.** They exchange packages with you
directly instead, which is slower and manual. If that becomes the binding
constraint — a partner who genuinely cannot fetch, and direct exchange too slow
to live with — that is the moment to revisit this, not before.

Reaching the instance is your job and deliberately outside this module. Attach
the VPC to whatever network your operators already use: a peering connection, a
transit gateway, a VPN, or a mesh peer holding a route to `vpc_cidr`. This
module does not guess which, because the answer differs per organisation.

## What it creates

| File | Resources |
|---|---|
| `network.tf` | A VPC, two subnets in two availability zones, an internet gateway for **outbound** traffic only, a route table |
| `alb.tf` | An **internal** Application Load Balancer, an HTTPS listener using your ACM certificate, an HTTP listener that redirects to it, a target group probing `/healthz`, and the load balancer's security group |
| `storage.tf` | An encrypted EFS file system, a mount target per subnet, an access point owning `/saltlick` as uid/gid 65532 (the distroless `nonroot` user the container runs as), and its security group |
| `service.tf` | An ECS cluster, a Fargate task definition, a service running exactly one task, a task execution IAM role, a CloudWatch log group, and the task's security group |
| `outputs.tf` | The internal load balancer hostname, VPC id and CIDR, EFS file system id, log group, cluster and service names |

There is no NAT gateway. The task gets a public IP so it can pull its image and
ship logs, and its security group accepts traffic only from the internal load
balancer, so it is not reachable from outside regardless. If your account
forbids public IPs on tasks, set `task_assign_public_ip = false` — but only if
this VPC already has a NAT gateway or ECR/S3/Logs VPC endpoints, because this
module creates neither and the task will otherwise fail to start.

## Rough cost

Region-dependent; these are `eu-west-1` list prices as a sense of scale, not a
quote.

| | Monthly |
|---|---|
| Application Load Balancer (internal costs the same as public) | ~$17 idle, plus a few cents of capacity units at this traffic |
| Fargate task, 0.25 vCPU / 0.5 GB, always on | ~$9 |
| EFS, standard storage | under $0.10 — the database is measured in megabytes |
| CloudWatch Logs | under $1 |
| **Total** | **~$27/month** |

The load balancer is two thirds of the bill and buys three things: a stable
name, a health check, and TLS termination. You could drop `alb.tf` and reach
the task directly on its private IP, but the task's address changes every time
it restarts and you would have to terminate TLS in the service itself. For
$17/month, keeping it is the boring choice.

## Before you apply

1. **Publish the container image.** This module does not build or push
   anything. Push to a registry your AWS account can pull from — a public
   registry needs no credentials; a private one needs a pull secret this module
   does not set up.
2. **Get a certificate into ACM**, in the same region, for the internal
   hostname you will serve the directory on. Since the name is internal, this
   is usually your own CA's certificate, imported. A public ACM certificate
   works too if you own the domain and are willing to point the name at private
   addresses.
3. **Decide where state goes.** Terraform keeps state in a local file unless
   you say otherwise, which is fine if one person applies this. If more than
   one does, uncomment and fill in the `backend "s3"` block in `versions.tf`.
   It is left blank on purpose: this repository is open source and cannot
   assume anything about your buckets, roles or naming.

## Variables you must set

| Variable | Example |
|---|---|
| `aws_region` | `"eu-west-1"` |
| `image` | `"ghcr.io/usareur-af/saltlick:v1.0.0"` — prefer a digest or an immutable tag; `latest` means a task restart can silently change versions |
| `certificate_arn` | `"arn:aws:acm:eu-west-1:123456789012:certificate/…"` |

You will almost certainly also set `allowed_cidr_blocks`, once the VPC is
attached to the network your operators come from. Everything else has a working
default: `name`, `vpc_cidr`, `container_port`, `db_path`, `task_cpu`,
`task_memory`, `task_assign_public_ip`, `log_retention_days`, `tags`. See
`variables.tf`.

## Apply

```sh
cp terraform.tfvars.example terraform.tfvars   # edit it; it is gitignored
terraform init
terraform plan
terraform apply
```

Then point your internal directory hostname at the `load_balancer_dns_name`
output. The name must match the certificate, or clients will refuse the
connection.

Check it **from inside the VPC or from a network you have attached to it** — it
will not answer from your laptop over the internet, by design:

```sh
curl https://directory.internal.example/healthz
curl https://directory.internal.example/v1/parties
```

No secrets are involved anywhere in this deployment. The directory holds public
packages, and the service authenticates writes with keys its clients hold, not
with credentials you configure here.

## Deploying a new version

Publish a new image, then:

```sh
terraform apply -var 'image=ghcr.io/usareur-af/saltlick:v1.1.0'
```

The old task stops before the new one starts, so expect a few seconds where the
directory returns 503. That is deliberate — see below.

## The one constraint you must not break

**Never raise `desired_count` above 1.**

SQLite over NFS tolerates exactly one writer. The service pins itself to a
single task and deploys by stopping the old task before starting the new one
(`deployment_minimum_healthy_percent = 0`) for that reason alone. Two tasks on
one EFS file system will corrupt the database. If the instance ever needs more
capacity, give the task more CPU and memory; do not add tasks.

## Backups

The database lives on EFS under `/saltlick/`. SQLite runs in WAL mode, so it is
**three** files — `saltlick.db`, `saltlick.db-wal`, `saltlick.db-shm` — and a
backup that takes only the first can miss recently committed writes. Back up the
directory, not the file.

Nothing here backs it up. Options, cheapest first:

- **AWS Backup** on the EFS file system — a plan and a rule, roughly 15 lines.
  It snapshots the whole file system, so the WAL problem does not arise.
  Deliberately not included because retention is your policy, not ours.
- **Copy the directory out** from anything that can mount the file system. Take
  all three files. A copy taken while the service is writing can still catch it
  mid-transaction; scaling the service to zero first removes the question, at
  the cost of a minute of downtime.

Losing it costs every party their published entry and their trust-on-first-use
key binding, and each would have to republish. It is not catastrophic, but it
is rude.

## Destroy

```sh
terraform destroy
```

This deletes the EFS file system and the database with it. Take a copy first if
the entries matter. The ACM certificate is not managed here and survives.
