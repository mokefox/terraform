output "ecs_cluster_name" {
  description = "ECS cluster name created by the fis module"
  value       = aws_ecs_cluster.this.name
}

output "ecs_service_name" {
  description = "ECS service name created by the fis module"
  value       = aws_ecs_service.this.name
}

output "ecs_task_definition_arn" {
  description = "ARN of the task definition used by the ecs service"
  value       = aws_ecs_task_definition.app.arn
}

output "fis_iam_role_arn" {
  description = "IAM role ARN that FIS uses for fault injection"
  value       = aws_iam_role.fis.arn
}

output "security_group_id" {
  description = "Security group ID attached to the FIS task"
  value       = aws_security_group.sg.id
}

output "fis_experiment_task_stop_id" {
  description = "ID of the ECS task stop FIS experiment template (null if disabled)"
  value       = var.enable_fis ? aws_fis_experiment_template.task_stop[0].id : null
}

output "fis_experiment_network_latency_id" {
  description = "ID of the network latency FIS experiment template (null if disabled)"
  value       = var.enable_fis ? aws_fis_experiment_template.network_latency[0].id : null
}

output "fis_experiment_network_blackhole_id" {
  description = "ID of the network blackhole FIS experiment template (null if disabled)"
  value       = var.enable_fis ? aws_fis_experiment_template.network_blackhole[0].id : null
}

# Duplicate outputs removed

output "fis_iam_policy_arn" {
  description = "ARN of the IAM policy attached to the FIS role"
  value       = aws_iam_policy.fis.arn
}