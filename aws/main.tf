terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.49.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "aws" {
  region                      = "us-east-1"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  s3_use_path_style           = true

  endpoints {
    ecs        = "http://localhost:4566"
    iam        = "http://localhost:4566"
    ssm        = "http://localhost:4566"
    fis        = "http://localhost:4566"
    cloudwatch = "http://localhost:4566"
    logs       = "http://localhost:4566"
  }
}

# Ministack 用の FIS/ECS スタック
module "ministack_fis" {
  source     = "./stacks/ministack_fis"
  region     = var.region
  project    = lookup(var.project, "service", "ministack")
  ec2_config = var.ec2_config
  lb_config  = var.lb_config
  vpc_id     = var.vpc_id
  subnet_ids = var.subnet_ids
}

