output "load_balancer_dns_name" {
  description = <<-EOT
    Private DNS name of the internal load balancer. It resolves to addresses
    inside the VPC and is not reachable from the internet. Point your internal
    directory hostname at it, and make sure that name matches certificate_arn.
  EOT
  value       = aws_lb.this.dns_name
}

output "vpc_id" {
  description = "VPC holding the directory. Attach it to the network your operators reach it from — peering, transit gateway, VPN, or a mesh peer with a route to vpc_cidr."
  value       = aws_vpc.this.id
}

output "vpc_cidr" {
  description = "CIDR of that VPC, for writing the route on the other side."
  value       = aws_vpc.this.cidr_block
}

output "efs_file_system_id" {
  description = "File system holding the SQLite database. Back this up."
  value       = aws_efs_file_system.this.id
}

output "log_group" {
  description = "CloudWatch Logs group carrying the container's output."
  value       = aws_cloudwatch_log_group.this.name
}

output "ecs_cluster" {
  description = "Cluster name, for `aws ecs` commands and the console."
  value       = aws_ecs_cluster.this.name
}

output "ecs_service" {
  description = "Service name, for forcing a redeploy after publishing a new image."
  value       = aws_ecs_service.this.name
}
