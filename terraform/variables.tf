# ---------------------------------------------------------------------------
# Required
# ---------------------------------------------------------------------------

variable "aws_region" {
  description = "AWS region to deploy into, e.g. eu-west-1."
  type        = string
}

variable "image" {
  description = <<-EOT
    Container image reference for saltlick, including the tag or digest, e.g.
    "ghcr.io/usareur-af/saltlick:v1.0.0". This module does not build or push
    images; publish one to a registry your account can pull from first. Prefer
    a digest (…@sha256:…) or an immutable tag over "latest" so a task restart
    cannot silently change the running version.
  EOT
  type        = string
}

variable "certificate_arn" {
  description = <<-EOT
    ARN of an ACM certificate in this region for the hostname you will serve
    the directory on. With internet_facing = true this is a public ACM
    certificate for a public name you own. With internet_facing = false it is
    usually your own CA's certificate, imported into ACM.

    TLS is not optional. Nothing in the directory is a secret, but consumers
    verify signatures over the exact bytes it returns, and plaintext transport
    invites someone on the path to change them.
  EOT
  type        = string
}

# ---------------------------------------------------------------------------
# Optional — the defaults are reasonable for a directory serving a coalition
# ---------------------------------------------------------------------------

variable "name" {
  description = "Name prefix for every resource this module creates."
  type        = string
  default     = "saltlick"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC this module creates. Change it if it collides with a network you peer or attach this VPC to."
  type        = string
  default     = "10.20.0.0/16"
}

variable "internet_facing" {
  description = <<-EOT
    Whether the load balancer is internet-facing (public addresses) or internal
    (private addresses only). The directory is a neutral meeting place that any
    party reaches over the internet, so true is the expected case. Set false to
    run it on a private network attached to this VPC.
  EOT
  type        = bool
  default     = true
}

variable "allowed_cidr_blocks" {
  description = <<-EOT
    Who may reach the load balancer on 80 and 443.

    With internet_facing = true this must be set explicitly; there is no
    default. For a directory every party can reach, write ["0.0.0.0/0"]. To
    admit only some parties, list their ranges.

    With internet_facing = false it defaults to the VPC's own CIDR: nothing
    outside this VPC, until you list the ranges attached to it.
  EOT
  type        = list(string)
  default     = null

  validation {
    condition     = !var.internet_facing || (var.allowed_cidr_blocks != null ? length(var.allowed_cidr_blocks) > 0 : false)
    error_message = "internet_facing = true needs allowed_cidr_blocks set explicitly, e.g. [\"0.0.0.0/0\"] for every party."
  }
}

variable "container_port" {
  description = "Port the saltlick process listens on inside the container."
  type        = number
  default     = 8080
}

variable "db_path" {
  description = <<-EOT
    Path to the SQLite database inside the container. Must sit under /data,
    which is the persistent mount, because SQLite runs in WAL mode and writes
    two siblings next to it (-wal and -shm) that have to persist too.
  EOT
  type        = string
  default     = "/data/saltlick.db"

  validation {
    condition     = startswith(var.db_path, "/data/")
    error_message = "db_path must be under /data/, otherwise the database is lost on task restart."
  }
}

variable "task_cpu" {
  description = "Fargate CPU units. 256 = 0.25 vCPU, which is ample for a directory of this size."
  type        = number
  default     = 256
}

variable "task_memory" {
  description = "Fargate memory in MiB. Must be a valid pairing with task_cpu."
  type        = number
  default     = 512
}

variable "task_assign_public_ip" {
  description = <<-EOT
    Whether the task gets a public IP. It does not make the task reachable —
    its security group accepts traffic only from the load balancer —
    but it is how the task pulls its image and ships logs without a NAT
    gateway, which would cost more per month than everything else here.

    Set false only if this VPC already has a NAT gateway, or ECR/S3/CloudWatch
    Logs VPC endpoints. This module creates neither, so setting it false
    without one of those leaves the task unable to start.
  EOT
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention for the container's stdout/stderr."
  type        = number
  default     = 30
}

variable "tags" {
  description = "Tags applied to every resource. Add whatever your organisation requires."
  type        = map(string)
  default     = {}
}
