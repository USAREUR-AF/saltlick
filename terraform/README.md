# Running saltlick on AWS

One instance of the directory behind an internet-facing load balancer with a
public TLS certificate, with the SQLite file on storage that survives a task
restart. About 200 lines of Terraform in six files, meant to be read and
adapted rather than consumed as a black box.

**Most operators do not need this.** Running the directory on one small host is
simpler, cheaper, and the expected case for a coalition body — see
[`../deploy/`](../deploy/). Use this if you already run in AWS and want the
directory there too.

## Who reaches it

The directory is a neutral meeting place that any party reaches over the
internet; why that is safe is in the [top-level README](../README.md#where-it-runs).

| `internet_facing` | Load balancer | `allowed_cidr_blocks` |
|---|---|---|
| `true` (default) | public addresses | required, no default; `["0.0.0.0/0"]` for every party, or the parties' ranges |
| `false` | private addresses only | defaults to `vpc_cidr`; widen to the networks attached to the VPC |

`plan` refuses `internet_facing = true` with `allowed_cidr_blocks` unset or
empty, so opening the directory to the internet is always a line someone wrote.

The task trusts `X-Forwarded-For` from `vpc_cidr` (`SALTLICK_TRUSTED_PROXIES`),
where only the load balancer reaches it, so per-source rate limits count the
client rather than the load balancer.

## What it creates

| File | Resources |
|---|---|
| `network.tf` | A VPC, two subnets in two availability zones, an internet gateway for **outbound** traffic only, a route table |
| `alb.tf` | An Application Load Balancer (internet-facing unless `internet_facing = false`), an HTTPS listener using your ACM certificate, an HTTP listener that redirects to it, a target group probing `/healthz`, and the load balancer's security group |
| `storage.tf` | An encrypted EFS file system, a mount target per subnet, an access point owning `/saltlick` as uid/gid 65532 (the distroless `nonroot` user the container runs as), and its security group |
| `service.tf` | An ECS cluster, a Fargate task definition, a service running exactly one task, a task execution IAM role, a CloudWatch log group, and the task's security group |
| `outputs.tf` | The load balancer hostname, VPC id and CIDR, EFS file system id, log group, cluster and service names |

There is no NAT gateway. The task gets a public IP so it can pull its image and
ship logs, and its security group accepts traffic only from the load balancer,
so it is not reachable from outside regardless. If your account
forbids public IPs on tasks, set `task_assign_public_ip = false` — but only if
this VPC already has a NAT gateway or ECR/S3/Logs VPC endpoints, because this
module creates neither and the task will otherwise fail to start.

## Rough cost

Region-dependent; these are `eu-west-1` list prices as a sense of scale, not a
quote.

| | Monthly |
|---|---|
| Application Load Balancer (internet-facing and internal cost the same) | ~$17 idle, plus a few cents of capacity units at this traffic |
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
2. **Get a public ACM certificate**, in the same region, for the public name
   you will serve the directory on (DNS validation is simplest). With
   `internet_facing = false`, import your own CA's certificate for the
   internal name instead.
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
| `allowed_cidr_blocks` | `["0.0.0.0/0"]` — required while `internet_facing = true` |

Terraform 1.9 or later. Everything else has a working default:
`internet_facing`, `name`, `vpc_cidr`, `container_port`, `db_path`,
`task_cpu`, `task_memory`, `task_assign_public_ip`, `log_retention_days`,
`tags`. See `variables.tf`.

## Apply

```sh
cp terraform.tfvars.example terraform.tfvars   # edit it; it is gitignored
terraform init
terraform plan
terraform apply
```

Then point the directory's public name at the `load_balancer_dns_name` output
(a CNAME, or a Route 53 alias). The name must match the certificate, or clients
will refuse the connection.

```sh
curl https://directory.example/healthz
curl https://directory.example/v1/parties
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

On start the service adds any column the current schema has and the database
lacks; there is nothing to run by hand.

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
