# The service itself: one Fargate task behind the load balancer.

resource "aws_cloudwatch_log_group" "this" {
  name              = "/${var.name}"
  retention_in_days = var.log_retention_days
}

# Pulls the image and writes logs. The container itself calls no AWS API, so
# there is deliberately no task role.
resource "aws_iam_role" "execution" {
  name = "${var.name}-execution"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_security_group" "task" {
  name        = "${var.name}-task"
  description = "saltlick task: load balancer in, image pull and NFS out"
  vpc_id      = aws_vpc.this.id

  tags = { Name = "${var.name}-task" }
}

resource "aws_vpc_security_group_ingress_rule" "task_from_alb" {
  security_group_id            = aws_security_group.task.id
  description                  = "Only the load balancer reaches the task"
  referenced_security_group_id = aws_security_group.alb.id
  from_port                    = var.container_port
  to_port                      = var.container_port
  ip_protocol                  = "tcp"
}

# Outbound is open because the task pulls its image from a registry you choose
# and mounts EFS. Nothing reaches the task inbound except the load balancer.
resource "aws_vpc_security_group_egress_rule" "task_egress" {
  security_group_id = aws_security_group.task.id
  description       = "Registry pull, logs, NFS"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

resource "aws_ecs_cluster" "this" {
  name = var.name
}

resource "aws_ecs_task_definition" "this" {
  family                   = var.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.execution.arn

  volume {
    name = "data"

    efs_volume_configuration {
      file_system_id     = aws_efs_file_system.this.id
      transit_encryption = "ENABLED"

      authorization_config {
        access_point_id = aws_efs_access_point.this.id
        iam             = "DISABLED"
      }
    }
  }

  container_definitions = jsonencode([{
    name      = var.name
    image     = var.image
    essential = true

    portMappings = [{
      containerPort = var.container_port
      protocol      = "tcp"
    }]

    # SALTLICK_ADDR is set explicitly. The binary's own default is
    # 127.0.0.1:8080, which inside a task would be unreachable from the load
    # balancer; the network namespace is the boundary here, not the bind
    # address.
    environment = [
      { name = "SALTLICK_ADDR", value = ":${var.container_port}" },
      { name = "SALTLICK_DB", value = var.db_path },
      # The load balancer is the only thing that reaches the task, from inside
      # the VPC, and appends the client's address to X-Forwarded-For. Trusting
      # that header from the VPC lets per-source rate limits see the client.
      { name = "SALTLICK_TRUSTED_PROXIES", value = var.vpc_cidr },
    ]

    # The DIRECTORY /data, not the database file: SQLite runs in WAL mode, so
    # saltlick.db has -wal and -shm siblings that must land on the same
    # persistent mount. See storage.tf.
    mountPoints = [{
      sourceVolume  = "data"
      containerPath = "/data"
      readOnly      = false
    }]

    # No container healthCheck: a static-binary image has no shell to run one
    # in. The load balancer probes /healthz over the network instead.

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.this.name
        awslogs-region        = var.aws_region
        awslogs-stream-prefix = var.name
      }
    }
  }])
}

resource "aws_ecs_service" "this" {
  name            = var.name
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.this.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  # Give the process time to open the database and start serving before the
  # load balancer's verdict can kill the task.
  health_check_grace_period_seconds = 60

  # Stop the old task before starting the new one. The usual rolling deploy
  # would briefly run two tasks, and two writers on one SQLite file over NFS is
  # how you corrupt it. The cost is a few seconds of downtime per deploy, which
  # an advisory directory can afford.
  deployment_minimum_healthy_percent = 0
  deployment_maximum_percent         = 100

  network_configuration {
    subnets          = aws_subnet.this[*].id
    security_groups  = [aws_security_group.task.id]
    assign_public_ip = var.task_assign_public_ip
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.this.arn
    container_name   = var.name
    container_port   = var.container_port
  }

  # The task cannot start until the file system is actually mountable.
  depends_on = [
    aws_efs_mount_target.this,
    aws_lb_listener.https,
  ]
}
