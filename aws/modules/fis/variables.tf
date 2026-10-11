variable "project" {
  description = "Project name"
  type        = string
  default     = "ministack"
}

variable "cluster_arn" {
  description = "ECS cluster ARN"
  type        = string
  default     = ""
}

# FIS configuration – all attributes optional, default empty lists
variable "fis" {
  description = "FIS configuration object (optional)"
  type = object({
    ecs                      = list(object({ cluster_name = string, service_name = string, selection_mode = string }))
    ec2                      = list(object({ instance_ids = list(string), selection_mode = string }))
    rds                      = list(object({ cluster_arns = list(string), selection_mode = string }))
    network_advanced         = list(object({ instance_ids = list(string), selection_mode = string, duration = string, loss = string, jitter = string, dns_fault = string }))
    api_fault                = list(object({ service = string, operation_name = string, error_code = string, percentage = number, duration = string }))
    ebs_fault                = list(object({ volume_arns = list(string), duration = string }))
    resource_stress          = list(object({ instance_ids = list(string), duration = string, cpu_load = number }))
    ecs_network_fault        = list(object({ cluster_name = string, service_name = string, selection_mode = string, duration = string, fault_type = string }))
    observability_disruption = list(object({ instance_ids = list(string), selection_mode = string, duration = string, target_service = string }))
    chained_scenarios        = list(object({ name = string, instance_ids = list(string), duration = string }))
    stop_alarms              = list(string)
  })
  default = {
    ecs                      = []
    ec2                      = []
    rds                      = []
    network_advanced         = []
    api_fault                = []
    ebs_fault                = []
    resource_stress          = []
    ecs_network_fault        = []
    observability_disruption = []
    chained_scenarios        = []
    stop_alarms              = []
  }
}

variable "region" {
  description = "AWS region"
  type        = string
}

variable "environment" {
  description = "Environment name (e.g., staging, prod)"
  type        = string
}

variable "ec2_config" {
  description = "EC2 configuration (unused in this module)"
  type        = any
  default     = {}
}

variable "lb_config" {
  description = "Load balancer configuration (unused)"
  type        = any
  default     = {}
}

variable "task_family" {
  description = "ECS task definition family"
  type        = string
  default     = "ministack-demo"
}

variable "vpc_id" {
  description = "VPC ID"
  type        = string
}

variable "subnet_ids" {
  description = "List of subnet IDs"
  type        = list(string)
}

variable "enable_fis" {
  description = "Flag to enable creation of FIS resources"
  type        = bool
  default     = false
}
