
resource "aws_iam_policy" "IAMManagedPolicy" {
  name   = "${var.department.uppercase}-${var.codepipeline_project_variables.projectname}-CodePipelineCFN"
  path   = "/"
  policy = file("./src/iam_policy_codepipelin.json")
}

resource "aws_iam_role" "IAMRoleCodePipeline" {
  path                 = "/"
  name                 = "${var.department.uppercase}-${var.codepipeline_project_variables.projectname}-CodePipeline"
  assume_role_policy   = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"codepipeline.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}"
  managed_policy_arns  = [aws_iam_policy.IAMManagedPolicy.arn]
  max_session_duration = 3600
}

resource "aws_iam_policy" "IAMManagedPolicySecHubDelAdminLambda" {
  name = "${var.department.uppercase}-securityhub-delegatedadmin-lambda"
  path = "/"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        "Sid" : "EnableSecurityHubDelegatedAdmin",
        "Effect" : "Allow",
        "Action" : [
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
        "Resource" : "*"
      },
      {
        "Sid" : "EnableDescribeRegions",
        "Effect" : "Allow",
        "Action" : "ec2:DescribeRegions",
        "Resource" : "*"
      },
      {
        "Action" : [
          "sts:AssumeRole"
        ],
        "Resource" : [
          "arn:aws:iam::*:role/AWSCloudFormationStackSetExecutionRole",
          "arn:aws:iam::*:role/securityhub-standards-manager"
        ],
        "Effect" : "Allow"
      },
      {
        "Action" : [
          "codepipeline:PutJobSuccessResult",
          "codepipeline:PutJobFailureResult"
        ]
        "Resource" : "*",
        "Effect" : "Allow"
      },
      {
        "Action" : [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        "Resource" : [
          "arn:aws:logs:ca-central-1:*:log-group:/aws/lambda/*"
        ],
        "Effect" : "Allow"
      },
    ]
  })
}

resource "aws_iam_role" "IAMRoleSecHubDelAdminLambda" {
  path                 = "/"
  name                 = "${var.department.uppercase}-securityhub-delegatedadmin-lambda"
  assume_role_policy   = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"lambda.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}"
  managed_policy_arns  = [aws_iam_policy.IAMManagedPolicySecHubDelAdminLambda.arn]
  max_session_duration = 3600
}