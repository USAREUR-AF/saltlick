terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # State configuration is deliberately left to you. Terraform will keep state
  # in a local file unless you configure a backend, which is fine for a single
  # instance managed by one person. If more than one person applies this, put
  # state somewhere shared and locked. Uncomment and edit:
  #
  # backend "s3" {
  #   bucket       = "your-terraform-state-bucket"
  #   key          = "saltlick/terraform.tfstate"
  #   region       = "eu-west-1"
  #   encrypt      = true
  #   use_lockfile = true # Terraform 1.10+; older versions use dynamodb_table
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = var.tags
  }
}
