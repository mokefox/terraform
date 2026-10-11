terraform {
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
  region                      = var.region
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  # Route FIS (and any other needed services) to the local Floci endpoint (port 4566 by default)
  endpoints {
    fis = "http://localhost:4566"
  }
}

