# log_bucket = {
#     name  = string,
#     id    = string
# }

standard_tags = {
  owner          = "firstname.lastname@mydomain.com",
  classification = "unclassified",
  solution       = "compliance-monitor"
  deployment     = "terraform",
  deploy-date    = "2021-04-11",
  category       = "governance"
}

department = {
  lowercase = "myorg",
  uppercase = "MYORG"
}

codepipeline_project_variables = {
  projectname             = "nist-compliance-monitor",
  projectnameshort        = "compliancemonitor",
  artifactzip             = "ComplianceMonitor.zip",
  integratorzip           = "lambda_map_config_findings_to_sechub.py.zip"
  integratorlambdahandler = "lambda_map_config_findings_to_sechub.lambda_handler"
}

provider_variables = {
  region              = "ca-central-1",
  allowed_account_ids = ["123456789012"]
  access_key          = "",
  secret_key          = "",
  token               = ""
}

stageparams_config_rules = {
  "StackSetName"                = "nist-compliance-monitor-configrules",
  "TemplatePath"                = "SourceArtifact::config-rules.yml",
  "Capabilities"                = "CAPABILITY_AUTO_EXPAND,CAPABILITY_IAM,CAPABILITY_NAMED_IAM",
  "PermissionModel"             = "SERVICE_MANAGED",
  "OrganizationsAutoDeployment" = "Enabled",
  "Regions"                     = "ca-central-1,us-east-1",
  "FailureTolerancePercentage"  = 100,
  "MaxConcurrentPercentage"     = 100,
  "Parameters"                  = "ParameterKey=pDefaultRegion,ParameterValue=ca-central-1",
  "Description"                 = "Deploys NIST Compliance Monitoring Solution"
}

stageparams_config_rules_mra = {
  "ActionMode"   = "CREATE_UPDATE",
  "StackName"    = "nist-compliance-monitor-configrules",
  "Capabilities" = "CAPABILITY_AUTO_EXPAND,CAPABILITY_IAM,CAPABILITY_NAMED_IAM",
  "RoleArn"      = "",
  "TemplatePath" = "SourceArtifact::config-rules.yml"
}

stageparams_securityhub = {
  "StackSetName"                = "nist-compliance-monitor-securityhub",
  "TemplatePath"                = "SourceArtifact::enable-sechub.yml",
  "Capabilities"                = "CAPABILITY_AUTO_EXPAND,CAPABILITY_IAM,CAPABILITY_NAMED_IAM",
  "PermissionModel"             = "SERVICE_MANAGED",
  "OrganizationsAutoDeployment" = "Enabled",
  "Regions"                     = "ca-central-1,us-east-1,us-east-2,us-west-1,us-west-2",
  "FailureTolerancePercentage"  = 100,
  "MaxConcurrentPercentage"     = 100,
  "Description"                 = "Deploys Security Hub as a StackSet across the Organization"
}

stageparams_sechuborgadmin = {
}

stageparams_sechub_standards_manager = {}

lambda_sechub_standards_manager_env = {
  EXCLUDED_REGIONS  = "ca-central-1, us-east-1"
  DESIRED_STANDARDS = "CIS AWS Foundations Benchmark v1.2.0"
  IAM_REMOTE_ROLE   = "AWSCloudFormationStackSetExecutionRole"
}

stageparams_config_sechub_integrator = {
  "StackSetName"                = "nist-compliance-monitor-integrator",
  "TemplatePath"                = "SourceArtifact::config_sechub_integration.yml",
  "Capabilities"                = "CAPABILITY_AUTO_EXPAND,CAPABILITY_IAM,CAPABILITY_NAMED_IAM",
  "PermissionModel"             = "SERVICE_MANAGED",
  "OrganizationsAutoDeployment" = "Enabled",
  "Regions"                     = "ca-central-1,us-east-1",
  "FailureTolerancePercentage"  = 100,
  "MaxConcurrentPercentage"     = 100,
  "Description"                 = "Deploys Compliance Monitoring Config Rule Security Hub integrator"
}

## This needs to go back in to 'stageparams_config_sechub_integrator' with the dynamic resources from the main code
# "Parameters"                  = "ParameterKey=pDefaultRegion,ParameterValue=ca-central-1",

s3bucket_public_block = {
  "block_public_acls"       = "true"
  "block_public_policy"     = "true"
  "restrict_public_buckets" = "true"
  "ignore_public_acls"      = "true"
}

lambda_sechub_enabler = {
  "description"   = "Configures Organization Administration of Security Hub"
  "function_name" = "nist-sechub_enabler"
  "handler"       = "sechub_enabler.lambda_handler"
  "memory_size"   = 128
  "runtime"       = "python3.8"
  "timeout"       = 60
}
lambda_sechub_standards_manager = {
  "description"   = "Configures Standards witing Security Hub"
  "function_name" = "nist-sechub_standards_manager"
  "handler"       = "sechub_standards_manager.lambda_handler"
  "memory_size"   = 128
  "runtime"       = "python3.8"
  "timeout"       = 120
}