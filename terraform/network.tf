# A small, self-contained VPC across two availability zones.
#
# Two AZs because an Application Load Balancer requires two, even an internal
# one. Nothing here is reachable from the internet: the load balancer is
# internal and holds only private addresses (see alb.tf).
#
# The internet gateway exists for outbound traffic only — the task pulls its
# container image and ships logs through it. If your account forbids public IPs
# on tasks, see the task_assign_public_ip variable, and note that this module
# creates neither a NAT gateway nor VPC endpoints.

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = var.name }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id

  tags = { Name = var.name }
}

resource "aws_subnet" "this" {
  count = 2

  vpc_id            = aws_vpc.this.id
  availability_zone = data.aws_availability_zones.available.names[count.index]
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index)

  tags = { Name = "${var.name}-${count.index}" }
}

resource "aws_route_table" "egress" {
  vpc_id = aws_vpc.this.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }

  tags = { Name = "${var.name}-egress" }
}

resource "aws_route_table_association" "this" {
  count = length(aws_subnet.this)

  subnet_id      = aws_subnet.this[count.index].id
  route_table_id = aws_route_table.egress.id
}
