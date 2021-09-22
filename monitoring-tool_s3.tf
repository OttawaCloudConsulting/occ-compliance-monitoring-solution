
resource "aws_s3_bucket" "S3Bucket" {
  bucket = "${var.department.lowercase}-${data.aws_caller_identity.current.account_id}-${var.codepipeline_project_variables.projectname}"
  acl    = "private"
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
}

resource "aws_s3_bucket_public_access_block" "S3Bucket" {
  bucket                  = aws_s3_bucket.S3Bucket.id
  block_public_acls       = var.s3bucket_public_block.block_public_acls
  block_public_policy     = var.s3bucket_public_block.block_public_policy
  restrict_public_buckets = var.s3bucket_public_block.restrict_public_buckets
  ignore_public_acls      = var.s3bucket_public_block.ignore_public_acls
}

resource "aws_s3_bucket_policy" "S3BucketPolicy" {
  depends_on = [
    aws_s3_bucket_public_access_block.S3Bucket,
    aws_iam_role.IAMRoleCodePipeline
  ]
  bucket = aws_s3_bucket.S3Bucket.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        "Sid" : "AllowGetObject",
        "Effect" : "Allow",
        "Principal" : {
          "AWS" : aws_iam_role.IAMRoleCodePipeline.arn
        },
        "Action" : "s3:*",
        "Resource" : [
          aws_s3_bucket.S3Bucket.arn,
          "${aws_s3_bucket.S3Bucket.arn}/*"
        ]
      },
      {
        "Sid" : "OrgGetObject",
        "Effect" : "Allow",
        "Principal" : "*",
        "Action" : ["s3:GetObject","s3:GetObjectVersion"],
        "Resource" : [
          aws_s3_bucket.S3Bucket.arn,
          "${aws_s3_bucket.S3Bucket.arn}/*"
        ]
        "Condition" : {
          "StringEquals" : {
            "aws:PrincipalOrgID" : "${data.aws_organizations_organization.awsorg.id}"
          }
        }
      },
      {
        "Sid" : "DenyInsecureConnections",
        "Effect" : "Deny",
        "Principal" : "*",
        "Action" : "s3:*",
        "Resource" : "${aws_s3_bucket.S3Bucket.arn}/*",
        "Condition" : {
          "Bool" : {
            "aws:SecureTransport" : "false"
          }
        }
      }
    ]
  })
}