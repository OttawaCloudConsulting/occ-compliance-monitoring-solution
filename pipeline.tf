provider "aws" {
    region              = var.provider_variables.region
    access_key          = var.provider_variables.access_key
    secret_key          = var.provider_variables.secret_key
    token               = var.provider_variables.token
    allowed_account_ids = var.provider_variables.allowed_account_ids
}

#### Existing Resources ####

data "aws_organizations_organization" "awsorg" {}

data "aws_caller_identity" "current" {}

data "aws_organizations_organization" "security_account" {}

locals {
  security_account = [for x in data.aws_organizations_organization.security_account.non_master_accounts: x.id if x.name == "security"][0]
}

####  New Resources ####

## IAM Resources ##

resource "aws_iam_policy" "IAMManagedPolicy" {
    name = "${var.department.uppercase}-${var.codepipeline_project_variables.projectname}-CodePipelineCFN"
    path = "/"
    policy = "${file("./src/iam_policy_codepipelin.json")}"
}

resource "aws_iam_role" "IAMRoleCodePipeline" {
    path = "/"
    name = "${var.department.uppercase}-${var.codepipeline_project_variables.projectname}-CodePipeline"
    assume_role_policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"codepipeline.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}"
    managed_policy_arns = [aws_iam_policy.IAMManagedPolicy.arn]
    max_session_duration = 3600
    tags = var.standard_tags
}

resource "aws_iam_policy" "IAMManagedPolicySecHubDelAdminLambda" {
    name = "${var.department.uppercase}-securityhub-delegatedadmin-lambda"
    path = "/"
    policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
    {
      "Sid": "EnableSecurityHubDelegatedAdmin",
      "Effect": "Allow",
      "Action": [
          "securityhub:EnableOrganizationAdminAccount",
          "securityhub:DisableOrganizationAdminAccount",
          "securityhub:ListOrganizationAdminAccounts",
          "securityhub:EnableSecurityHub",
          "securityhub:DescribeHub",
          "securityhub:UpdateOrganizationConfiguration",
          "sts:GetCallerIdentity",
          "organizations:ListAccounts",
          "organizations:ListAWSServiceAccessForOrganization",
          "organizations:DescribeOrganization",
          "organizations:RegisterDelegatedAdministrator",
          "organizations:DeregisterDelegatedAdministrator",
          "organizations:EnableAWSServiceAccess"
      ]
      "Resource": "*"
    },
    {
        "Action": [
            "sts:AssumeRole"
        ],
        "Resource": [
            "arn:aws:iam::${local.security_account}:role/AWSCloudFormationStackSetExecutionRole"
        ],
        "Effect": "Allow"
    },
    {
      "Action": [
          "codepipeline:PutJobSuccessResult",
          "codepipeline:PutJobFailureResult"
      ]
      "Resource": "*",
      "Effect": "Allow"
    },
    {
      "Action": [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
      ],
      "Resource": [
          "arn:aws:logs:ca-central-1:*:log-group:/aws/lambda/*"
      ],
      "Effect": "Allow"
    },
  ]
  })
}

resource "aws_iam_role" "IAMRoleSecHubDelAdminLambda" {
    path = "/"
    name = "${var.department.uppercase}-securityhub-delegatedadmin-lambda"
    assume_role_policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"lambda.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}"
    managed_policy_arns = [aws_iam_policy.IAMManagedPolicySecHubDelAdminLambda.arn]
    max_session_duration = 3600
    tags = var.standard_tags
}

## KMS Resources ##

resource "aws_kms_key" "compliancemonitor" {
  description             = "Compliance Monitor Key"
  deletion_window_in_days = 10
  enable_key_rotation     = true
  policy = jsonencode({
    "Version": "2012-10-17",
    "Id": "key-alz-1",
    "Statement": [{
            "Sid": "Allow administration of the key",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
            },
            "Action": [
                "kms:Create*",
                "kms:Describe*",
                "kms:Enable*",
                "kms:List*",
                "kms:Put*",
                "kms:Update*",
                "kms:Revoke*",
                "kms:Disable*",
                "kms:Get*",
                "kms:Delete*",
                "kms:ScheduleKeyDeletion",
                "kms:CancelKeyDeletion",
                "kms:Tag*",
                "kms:Untag*"
            ],
            "Resource": "*"
        },
        {
            "Sid": "Allow use of the key",
            "Effect": "Allow",
            "Principal": {
                "AWS": [
                    "${aws_iam_role.IAMRoleSecHubDelAdminLambda.arn}",
                    "${aws_iam_role.IAMRoleCodePipeline.arn}"
                ]
            },
            "Action": [
                "kms:Encrypt",
                "kms:Decrypt",
                "kms:ReEncrypt*",
                "kms:GenerateDataKey*",
                "kms:DescribeKey"
            ],
            "Resource": "*"
        },
        {
            "Sid": "Allow organizational use of the key",
            "Effect": "Allow",
            "Principal": {
                "AWS": "*"
            },
            "Action": [
                "kms:Encrypt",
                "kms:Decrypt",
                "kms:ReEncrypt*",
                "kms:GenerateDataKey*",
                "kms:DescribeKey"
            ],
            "Resource": "*",
            "Condition": {
                "ArnLike": {
                    "aws:PrincipalARN": [
                        "arn:aws:iam::*:role/AWSCloudFormationStackSetExecutionRole",
                        "arn:aws:iam::*:role/stacksets-exec-*",
                        "arn:aws:iam::*:role/aws-reserved/sso.amazonaws.com/*/AWSReservedSSO_AdministratorAccess_*",
                        "arn:aws:iam::*:role/aws-landingzone-PublisherLambdaRole*"
                    ]
                }
            }
        }
    ]
})
  tags = var.standard_tags
}

resource "aws_kms_alias" "compliancemonitor" {
  name          = "alias/compliancemonitor"
  target_key_id = aws_kms_key.compliancemonitor.key_id
}

##  S3 Resources  ##

resource "aws_s3_bucket" "S3Bucket" {
    bucket      = "${var.department.lowercase}-${data.aws_caller_identity.current.account_id}-${var.codepipeline_project_variables.projectname}"
    acl         = "private"
    versioning {
      enabled = true
    }
    server_side_encryption_configuration {
      rule {
        apply_server_side_encryption_by_default {
          sse_algorithm     = "aws:kms"
          kms_master_key_id = aws_kms_key.compliancemonitor.arn
        }
      }
    }
#    logging {
#      target_bucket = var.S3Bucket.id
#      target_prefix = "log/s3_artifact/"
#    }
    tags = var.standard_tags
}

resource "aws_s3_bucket_public_access_block" "S3Bucket" {
  bucket = aws_s3_bucket.S3Bucket.id
  block_public_acls         = var.s3bucket_public_block.block_public_acls
  block_public_policy       = var.s3bucket_public_block.block_public_policy
  restrict_public_buckets   = var.s3bucket_public_block.restrict_public_buckets
  ignore_public_acls        = var.s3bucket_public_block.ignore_public_acls
}

resource "aws_s3_bucket_policy" "S3BucketPolicy" {
    depends_on = [
      aws_s3_bucket_public_access_block.S3Bucket,
    ]
    bucket = aws_s3_bucket.S3Bucket.id
    policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
    {
      "Sid": "AllowGetObject",
      "Effect": "Allow",
      "Principal": {
        "AWS": aws_iam_role.IAMRoleCodePipeline.arn
      },
      "Action": "s3:*",
      "Resource": [
        aws_s3_bucket.S3Bucket.arn,
        "${aws_s3_bucket.S3Bucket.arn}/*"
      ]
    },
    {
      "Sid": "OrgGetObject",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": [
        aws_s3_bucket.S3Bucket.arn,
        "${aws_s3_bucket.S3Bucket.arn}/*"
      ]
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": "${data.aws_organizations_organization.awsorg.id}"
          }
        }
    },
    {
      "Sid": "DenyInsecureConnections",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "${aws_s3_bucket.S3Bucket.arn}/*",
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    }
    ]
  })
}

resource "aws_kms_grant" "compliancemonitor" {
  name              = "compliance-monitor"
  key_id            = aws_kms_key.compliancemonitor.key_id
  grantee_principal = aws_iam_role.IAMRoleSecHubDelAdminLambda.arn
  operations        = ["Encrypt", "Decrypt", "GenerateDataKey"]

  constraints {
    encryption_context_equals = {
      Department = "Finance"
    }
  }
}

resource "aws_s3_bucket_object" "object" {
  for_each = fileset("./artifacts/", "*")
  bucket = aws_s3_bucket.S3Bucket.id
  key    = "${var.codepipeline_project_variables.projectnameshort}/${each.value}"
  source = "./artifacts/${each.value}"
  etag = filemd5("./artifacts/${each.value}")
  tags = var.standard_tags
}

## CodePipeline Resources ##

resource "aws_codepipeline" "CodePipelinePipeline" {
    name = var.codepipeline_project_variables.projectname
    role_arn = aws_iam_role.IAMRoleCodePipeline.arn
    artifact_store {
        location = aws_s3_bucket.S3Bucket.id
        type = "S3"
    }
    stage {
        name = "Source"
        action {
                name = "SourceAction"
                category = "Source"
                owner = "AWS"
                configuration = {
                    PollForSourceChanges = "true"
                    S3Bucket = aws_s3_bucket.S3Bucket.id
                    S3ObjectKey = "${var.codepipeline_project_variables.projectnameshort}/${var.codepipeline_project_variables.artifactzip}"
                }
                provider = "S3"
                version = "1"
                output_artifacts = [
                    "SourceArtifact"
                ]
                run_order = 1
            }
    }
    stage {
        name = "SecurityHub-${var.codepipeline_project_variables.projectnameshort}"
        action {
                name = "SecurityHub_${var.codepipeline_project_variables.projectnameshort}"
                category = "Deploy"
                owner = "AWS"
                provider = "CloudFormationStackSet"
                version = "1"
                configuration = merge({
                    DeploymentTargets = data.aws_organizations_organization.awsorg.roots[0].id
                },var.stageparams_securityhub)
                input_artifacts = [
                    "SourceArtifact"
                ]
                run_order = 1
            }
    }
    stage {
        name = "ConfigSecHubIntegrator-${var.codepipeline_project_variables.projectnameshort}"
        action {
                name = "ConfigSecHubIntegrator_${var.codepipeline_project_variables.projectnameshort}"
                category = "Deploy"
                owner = "AWS"
                provider = "CloudFormationStackSet"
                version = "1"
                configuration = merge({
                    DeploymentTargets = data.aws_organizations_organization.awsorg.roots[0].id,
                    Parameters = "ParameterKey=S3Bucket,ParameterValue=${aws_s3_bucket.S3Bucket.id} ParameterKey=S3Key,ParameterValue=${var.codepipeline_project_variables.projectnameshort}/${var.codepipeline_project_variables.integratorzip} ParameterKey=LambdaHandler,ParameterValue=${var.codepipeline_project_variables.integratorlambdahandler}"
                },var.stageparams_config_sechub_integrator)
                input_artifacts = [
                    "SourceArtifact"
                ]
                run_order = 1
            }
    }
    stage {
        name = "ConfigRules-${var.codepipeline_project_variables.projectnameshort}"
        action {
                name = "ConfigRules-${var.codepipeline_project_variables.projectnameshort}"
                category = "Deploy"
                owner = "AWS"
                provider = "CloudFormationStackSet"
                version = "1"
                configuration = merge({
                    DeploymentTargets = data.aws_organizations_organization.awsorg.roots[0].id
                },var.stageparams_config_rules)
                input_artifacts = [
                    "SourceArtifact"
                ]
                run_order = 1
            }
    }
    ## MRA Stage disabled due to design requirements. Opt A) Single config-rules in CFN & create IAM Role for CFN vs Opt B) Create separate TF for config-rules, but manage config-rules in 2x locations.
    # stage {
    #     name = "ConfigRulesMRA-${var.codepipeline_project_variables.projectnameshort}"
    #     action {
    #             name = "ConfigRulesMRA-${var.codepipeline_project_variables.projectnameshort}"
    #             category = "Deploy"
    #             owner = "AWS"
    #             provider = "CloudFormation"
    #             version = "1"
    #             configuration = merge({
    #             },var.stageparams_config_rules_mra)
    #             input_artifacts = [
    #                 "SourceArtifact"
    #             ]
    #             run_order = 1
    #         }
    # }
    stage {
        name = "SecHubOrgAdmin-${var.codepipeline_project_variables.projectnameshort}"
        action {
                name = "SecHubOrgAdmin${var.codepipeline_project_variables.projectnameshort}"
                category = "Invoke"
                owner = "AWS"
                provider = "Lambda"
                version = "1"
                configuration = merge({
                    FunctionName = aws_lambda_function.sechub_enabler.function_name
                },var.stageparams_sechuborgadmin)
                run_order = 1
            }
    }
  tags = var.standard_tags
}

## Lambda Resources ##

resource "aws_lambda_function" "sechub_enabler" {
    depends_on = [
      aws_s3_bucket_object.object,
    ]
    description         = var.lambda_sechub_enabler.description
    function_name       = var.lambda_sechub_enabler.function_name
    handler             = var.lambda_sechub_enabler.handler
    s3_bucket           = aws_s3_bucket.S3Bucket.id
    s3_key              = "${var.codepipeline_project_variables.projectnameshort}/${var.codepipeline_project_variables.artifactzip}"
    memory_size         = var.lambda_sechub_enabler.memory_size
    role                = "${aws_iam_role.IAMRoleSecHubDelAdminLambda.arn}"
    runtime             = var.lambda_sechub_enabler.runtime
    timeout             = var.lambda_sechub_enabler.timeout
    tags = var.standard_tags
}

#####  OUTPUTS  ####

output "compliance_monitor_kms_key_arn" {
  value = aws_kms_key.compliancemonitor.arn
}

output "compliance_monitor_kms_key_alias" {
  value = aws_kms_alias.compliancemonitor.arn
}

output "compliance_monitor_s3_bucket" {
  value = aws_s3_bucket.S3Bucket
}

output "compliance_monitor_pipeline_arn" {
  value = aws_codepipeline.CodePipelinePipeline.arn
}

output "compliance_monitor_pipeline_id" {
  value = aws_codepipeline.CodePipelinePipeline.id
}