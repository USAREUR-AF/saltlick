# Persistent storage for the SQLite database.
#
# Fargate task storage is destroyed when the task stops, so the database lives
# on EFS and the DIRECTORY is mounted at /data. A stopped, restarted,
# redeployed or rescheduled task finds the same files.
#
# Directory, not file, and it matters: SQLite runs in WAL mode here, so the
# database is three files — saltlick.db, saltlick.db-wal, saltlick.db-shm.
# Mounting only the .db would leave the write-ahead log on task-local storage,
# and committed writes would vanish on restart while everything still looked
# fine. Do not "simplify" this to a single-file mount.
#
# SQLite over NFS only behaves if exactly one process has the file open for
# writing. Two things enforce that here and both matter:
#   - the service runs a single task (desired_count = 1), and
#   - the deployment stops the old task before starting the new one
#     (see aws_ecs_service.this).
# If you raise the task count, you will corrupt the database. Scale by giving a
# bigger instance more CPU, not by adding tasks.

resource "aws_efs_file_system" "this" {
  creation_token = var.name
  encrypted      = true

  tags = { Name = var.name }
}

resource "aws_efs_mount_target" "this" {
  count = length(aws_subnet.this)

  file_system_id  = aws_efs_file_system.this.id
  subnet_id       = aws_subnet.this[count.index].id
  security_groups = [aws_security_group.efs.id]
}

# The access point owns the directory and forces every access to a fixed
# uid/gid. 65532 is the `nonroot` user of the distroless base image the
# container runs as; keep the two in step if that ever changes.
resource "aws_efs_access_point" "this" {
  file_system_id = aws_efs_file_system.this.id

  posix_user {
    uid = 65532
    gid = 65532
  }

  root_directory {
    path = "/saltlick"

    creation_info {
      owner_uid   = 65532
      owner_gid   = 65532
      permissions = "0755"
    }
  }

  tags = { Name = var.name }
}

resource "aws_security_group" "efs" {
  name        = "${var.name}-efs"
  description = "NFS from the saltlick task only"
  vpc_id      = aws_vpc.this.id

  tags = { Name = "${var.name}-efs" }
}

resource "aws_vpc_security_group_ingress_rule" "efs_from_task" {
  security_group_id            = aws_security_group.efs.id
  description                  = "NFS from the saltlick task"
  referenced_security_group_id = aws_security_group.task.id
  from_port                    = 2049
  to_port                      = 2049
  ip_protocol                  = "tcp"
}
