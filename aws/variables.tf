variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "project" {
  description = "Project context map"
  type        = map(string)
  default     = {}
}

variable "ec2_config" {
  description = "EC2 config (unused)"
  type        = any
  default     = {}
}

variable "lb_config" {
  description = "Load balancer config (unused)"
  type        = any
  default     = {}
}

variable "vpc_id" {
  description = "VPC ID for ministack"
  type        = string
  default     = "vpc-dummy"
}

variable "subnet_ids" {
  description = "Subnet IDs for ministack"
  type        = list(string)
  default     = ["subnet-dummy-1", "subnet-dummy-2"]
}

