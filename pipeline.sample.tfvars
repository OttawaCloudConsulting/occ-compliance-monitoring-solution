# log_bucket = {
#     name  = string,
#     id    = string
# }

standard_tags = {
    owner                           = "firstname.lastname@mydomain.com",
    classification                  = "unclassified",
    solution                        = "compliance-monitor"
    deployment                      = "terraform",
    deploy-date                     = "2021-04-11",
    category                        = "automation"
}

department = {
    lowercase                       = "mydept",
    uppercase                       = "MYDEPT"
}

codepipeline_project_variables = {
    projectname                     = "compliance-monitor",
    projectnameshort                = "compliancemonitor",
    artifactzip                     = "MyArtifact.zip",
    integratorzip                   = "lambda_map_config_findings_to_sechub.py.zip"
    integratorlambdahandler         = "lambda_map_config_findings_to_sechub.lambda_handler"
}

provider_variables = {
    region                          = "ca-central-1",
    allowed_account_ids             = ["123456789012"]
    access_key                      = "",
    secret_key                      = "",
    token                           = ""
}

stageparams_config_rules = {
    "StackSetName"                  = "compliance-monitor-configrules",
    "TemplatePath"                  = "SourceArtifact::config-rules.yml",
    "Capabilities"                  = "CAPABILITY_AUTO_EXPAND,CAPABILITY_IAM,CAPABILITY_NAMED_IAM",
    "PermissionModel"               = "SERVICE_MANAGED",
    "OrganizationsAutoDeployment"   = "Enabled",
    "Regions"                       = "ca-central-1",
    "FailureTolerancePercentage"    = 100,
    "MaxConcurrentPercentage"       = 100,
    "Parameters"                    = "ParameterKey=pDefaultRegion,ParameterValue=ca-central-1",
    "Description"                   = "Deploys Compliance Monitoring Solution"
                }

stageparams_config_rules_mra = {
    "ActionMode"                    = "CREATE_UPDATE",
    "StackName"                     = "compliance-monitor-configrules",
    "Capabilities"                  = "CAPABILITY_AUTO_EXPAND,CAPABILITY_IAM,CAPABILITY_NAMED_IAM",
    "RoleArn"                       = "",
    "TemplatePath"                  = "SourceArtifact::config-rules.yml"
                }

stageparams_securityhub = {
    "StackSetName"                  = "compliance-monitor-securityhub",
    "TemplatePath"                  = "SourceArtifact::enable-sechub.yml",
    "Capabilities"                  = "CAPABILITY_AUTO_EXPAND,CAPABILITY_IAM,CAPABILITY_NAMED_IAM",
    "PermissionModel"               = "SERVICE_MANAGED",
    "OrganizationsAutoDeployment"   = "Enabled",
    "Regions"                       = "ca-central-1",
    "FailureTolerancePercentage"    = 100,
    "MaxConcurrentPercentage"       = 100,
    "Description"                   = "Deploys Security Hub as a StackSet across the Organization"
                }

stageparams_sechuborgadmin = {
                }

stageparams_config_sechub_integrator = {
    "StackSetName"                  = "compliance-monitor-integrator",
    "TemplatePath"                  = "SourceArtifact::config_sechub_integration.yml",
    "Capabilities"                  = "CAPABILITY_AUTO_EXPAND,CAPABILITY_IAM,CAPABILITY_NAMED_IAM",
    "PermissionModel"               = "SERVICE_MANAGED",
    "OrganizationsAutoDeployment"   = "Enabled",
    "Regions"                       = "ca-central-1",
    "FailureTolerancePercentage"    = 100,
    "MaxConcurrentPercentage"       = 100,
    "Description"                   = "Deploys Compliance Monitoring Config Rule Security Hub integrator"
}

s3bucket_public_block = {
    "block_public_acls"             = "true"
    "block_public_policy"           = "true"
    "restrict_public_buckets"       = "true"
    "ignore_public_acls"            = "true"
                  }

lambda_sechub_enabler = {
    "description"                   = "Configures Organization Administration of Security Hub"
    "function_name"                 = "sechub_enabler"
    "handler"                       = "sechub_enabler.lambda_handler"
    "memory_size"                   = 128
    "runtime"                       = "python3.8"
    "timeout"                       = 3
}

iam_role_lambda_config_sechub = {
    "path"                          = "/"
    "name"                          = "config-sechub-lambda-role"
    "assume_role_policy"            = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"lambda.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}"
    "max_session_duration"          = 3600
}

iam_policy_lambda_configsechub = {
    "policy"                        = "{\"Statement\":[{\"Action\":[\"securityhub:BatchImportFindings\"],\"Resource\":[\"*\"],\"Effect\":\"Allow\"},{\"Action\":[\"logs:CreateLogGroup\",\"logs:CreateLogStream\",\"logs:PutLogEvents\"],\"Resource\":\"*\",\"Effect\":\"Allow\"},{\"Action\":[\"config:DescribeConfigRules\"],\"Resource\":\"*\",\"Effect\":\"Allow\"}]}"
}

eventsrule_config_sechub = {
    "name"                          = "Config-Sechub-CW-Rule"
    "description"                   = "This CW rule integrates AWS Config Compliance events with AWS Lambda as a target"
    "event_pattern"                 = "{\"detail-type\":[\"Config Rules Compliance Change\"],\"source\":[\"aws.config\"],\"detail\":{\"messageType\":[\"ComplianceChangeNotification\"]}}"
}

cloudwatch_event_target_config_sechub = {
    "rule"                          = "Config-Sechub-CW-Rule"
}

lambda_function_config_sechub = {
    "artifactzip"                   = "lambda_map_config_findings_to_sechub.py.zip"
    "description"                   = "Forwards Config Rule findings to Security Hub"
    "function_name"                 = "Config-SecHub-Lambda"
    "handler"                       = "lambda_function.lambda_handler"
    "memory_size"                   = 128
    "runtime"                       = "python3.7"
    "timeout"                       = 300
}