# Internal entry point.
#
# `internal = true` is the load-bearing line: the load balancer gets private
# addresses only and has no path from the internet. It exists to give the
# directory a stable name, a health check, and a place to terminate TLS.
#
# Reaching it is your job and deliberately outside this module. Attach the VPC
# to whatever network your operators and coalition members already use — a mesh
# peer with a route to var.vpc_cidr, a VPC peering connection, a transit
# gateway, a VPN. This module does not guess which.

locals {
  # Default to the VPC itself. A caller who reaches the directory from a mesh
  # or a peered network must widen this to those ranges.
  allowed_cidr_blocks = coalesce(var.allowed_cidr_blocks, [var.vpc_cidr])
}

resource "aws_security_group" "alb" {
  name        = "${var.name}-alb"
  description = "Ingress to the internal saltlick load balancer"
  vpc_id      = aws_vpc.this.id

  tags = { Name = "${var.name}-alb" }
}

resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  count = length(local.allowed_cidr_blocks)

  security_group_id = aws_security_group.alb.id
  description       = "HTTPS from allowed internal callers"
  cidr_ipv4         = local.allowed_cidr_blocks[count.index]
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "alb_http_redirect" {
  count = length(local.allowed_cidr_blocks)

  security_group_id = aws_security_group.alb.id
  description       = "HTTP, redirected to HTTPS"
  cidr_ipv4         = local.allowed_cidr_blocks[count.index]
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "alb_to_task" {
  security_group_id            = aws_security_group.alb.id
  description                  = "Forward to the saltlick task"
  referenced_security_group_id = aws_security_group.task.id
  from_port                    = var.container_port
  to_port                      = var.container_port
  ip_protocol                  = "tcp"
}

resource "aws_lb" "this" {
  name               = var.name
  load_balancer_type = "application"
  internal           = true
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.this[*].id

  drop_invalid_header_fields = true
}

resource "aws_lb_target_group" "this" {
  name        = var.name
  port        = var.container_port
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = aws_vpc.this.id

  # A short drain: there is one task and no long-lived requests, so waiting the
  # default 300s on every deploy only lengthens the single-writer gap below.
  deregistration_delay = 10

  health_check {
    path                = "/healthz"
    matcher             = "200"
    interval            = 15
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this.arn
  }
}

resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}
