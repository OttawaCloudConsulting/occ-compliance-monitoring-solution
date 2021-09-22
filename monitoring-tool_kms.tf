## Update KMS Policy and correct IAM Roles for your organization
resource "aws_kms_key" "compliancemonitor" {
  description             = "Compliance Monitor Key"
  deletion_window_in_days = 10
  enable_key_rotation     = true
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Id" : "key-alz-1",
    "Statement" : [{
      "Sid" : "Allow administration of the key",
      "Effect" : "Allow",
      "Principal" : {
        "AWS" : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
      },
      "Action" : [
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
      "Resource" : "*"
      },
      {
        "Sid" : "Allow use of the key",
        "Effect" : "Allow",
        "Principal" : {
          "AWS" : [
            "${aws_iam_role.IAMRoleSecHubDelAdminLambda.arn}",
            "${aws_iam_role.IAMRoleCodePipeline.arn}"
          ]
        },
        "Action" : [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ],
        "Resource" : "*"
      },
      {
        "Sid" : "Allow organizational use of the key",
        "Effect" : "Allow",
        "Principal" : {
          "AWS" : "*"
        },
        "Action" : [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ],
        "Resource" : "*",
        "Condition" : {
          "ArnLike" : {
            "aws:PrincipalARN" : [
              "arn:aws:iam::*:role/AWSCloudFormationStackSetExecutionRole",
              "arn:aws:iam::*:role/stacksets-exec-*",
              "arn:aws:iam::*:role/aws-reserved/sso.amazonaws.com/*/AWSReservedSSO_AdministratorAccess_*",
            ]
          }
        }
      }
    ]
  })
}

resource "aws_kms_alias" "compliancemonitor" {
  name          = "alias/compliancemonitor"
  target_key_id = aws_kms_key.compliancemonitor.key_id
}

resource "aws_kms_grant" "compliancemonitor" {
  name              = "compliance-monitor"
  key_id            = aws_kms_key.compliancemonitor.key_id
  grantee_principal = aws_iam_role.IAMRoleSecHubDelAdminLambda.arn
  operations        = ["Encrypt", "Decrypt", "GenerateDataKey"]
}