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
    ARN of an ACM certificate in this region for the internal hostname you will
    serve the directory on. The load balancer is internal, so this is usually a
    certificate from your own CA imported into ACM. A public ACM certificate
    also works if you own the domain and are willing to point a name at private
    addresses.

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

variable "allowed_cidr_blocks" {
  description = <<-EOT
    Who may reach the internal load balancer. Defaults to the VPC's own CIDR,
    which means: nothing outside this VPC, until you say otherwise.

    Widen it to the ranges your operators and coalition members actually come
    from once the VPC is attached to that network — a mesh peer's range, a
    peered VPC, a VPN pool. Deliberately not "0.0.0.0/0" by default; see the
    README on why this service is not internet-facing.
  EOT
  type        = list(string)
  default     = null
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
    its security group accepts traffic only from the internal load balancer —
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
