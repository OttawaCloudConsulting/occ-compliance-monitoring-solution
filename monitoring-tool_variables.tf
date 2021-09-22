variable "provider_variables" {
  type = object({
    region              = string,
    access_key          = string,
    secret_key          = string,
    token               = string,
    allowed_account_ids = list(string)
  })
}

#variable "log_bucket" {
#  type          = object({
#    name  = string 
#    id    = string
#  })
#  description   = "S3 Logging Bucket, including ID"
#}

variable "standard_tags" {
  type = object({
    owner          = string
    classification = string
    solution       = string
    deployment     = string
    deploy-date    = string
    category       = string
  })
  description = "Standard Tags"
}

variable "department" {
  type = object({
    lowercase = string
    uppercase = string
  })
  description = "Name as acronym component for parameterization"
}

variable "codepipeline_project_variables" {
  type = object({
    projectname             = string
    projectnameshort        = string
    artifactzip             = string
    integratorzip           = string
    integratorlambdahandler = string
  })
  description = "Set of variables specific to the CodePipeline Project"
}

variable "lambda_sechub_enabler" {
  type = object({
    description   = string
    function_name = string
    handler       = string
    memory_size   = number
    runtime       = string
    timeout       = number
  })
  description = "Lambda Function variables for Security Hub Enabler"
}

variable "lambda_sechub_standards_manager" {
  type = object({
    description   = string
    function_name = string
    handler       = string
    memory_size   = number
    runtime       = string
    timeout       = number
  })
  description = "Lambda Function variables for Security Hub Enabler"
}

variable "lambda_sechub_standards_manager_env" {
  type = object({
    EXCLUDED_REGIONS  = string
    DESIRED_STANDARDS = string
    IAM_REMOTE_ROLE   = string
  })
  description = "Lambda Function environment variables for Security Hub Standards Manager"
}

variable "s3bucket_public_block" {
  type = object({
    block_public_acls       = string
    block_public_policy     = string
    restrict_public_buckets = string
    ignore_public_acls      = string
  })
  description = "Standard Public Block Settings"
}

variable "remote_execution_role" {}
variable "stageparams_config_rules" {}
variable "stageparams_securityhub" {}
variable "stageparams_sechuborgadmin" {}
variable "stageparams_config_rules_mra" {}
variable "stageparams_config_sechub_integrator" {}
variable "stageparams_sechub_standards_manager" {}
