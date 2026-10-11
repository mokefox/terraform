variable "region" {
  description = "AWS region"
  type        = string
}

variable "project" {
  description = "Project name"
  type        = string
  default     = "ministack"
}

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

variable "environment" {
  description = "Environment name (e.g., staging, prod)"
  type        = string
  default     = "staging"
}

variable "ec2_config" {
  description = "EC2 configuration (unused here)"
  type        = any
  default     = {}
}

variable "lb_config" {
  description = "Load balancer configuration (unused here)"
  type        = any
  default     = {}
}

variable "enable_fis" {
  description = "Ministack で FIS リソースを作成するか"
  type        = bool
  default     = false
}

variable "vpc_id" {
  description = "VPC ID (from network stack)"
  type        = string
}

variable "subnet_ids" {
  description = "List of subnet IDs (from network stack)"
  type        = list(string)
}