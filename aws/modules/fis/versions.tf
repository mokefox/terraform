terraform {
  required_version = "~> 1.15.5"
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
