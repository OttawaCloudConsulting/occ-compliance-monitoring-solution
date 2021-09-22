provider "aws" {
  region              = var.provider_variables.region
  access_key          = var.provider_variables.access_key
  secret_key          = var.provider_variables.secret_key
  token               = var.provider_variables.token
  allowed_account_ids = var.provider_variables.allowed_account_ids
  default_tags {
    tags = {
      owner          = var.standard_tags.owner
      classification = var.standard_tags.classification
      solution       = var.standard_tags.solution
      deployment     = var.standard_tags.deployment
      deploy-date    = var.standard_tags.deploy-date
      category       = var.standard_tags.category
    }
  }
}