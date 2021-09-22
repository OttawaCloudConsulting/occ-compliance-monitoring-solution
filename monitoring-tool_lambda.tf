
resource "aws_lambda_function" "sechub_enabler" {
  depends_on = [
    aws_s3_bucket_object.object,
  ]
  description   = var.lambda_sechub_enabler.description
  function_name = var.lambda_sechub_enabler.function_name
  handler       = var.lambda_sechub_enabler.handler
  s3_bucket     = aws_s3_bucket.S3Bucket.id
  s3_key        = "${var.codepipeline_project_variables.projectnameshort}/${var.codepipeline_project_variables.artifactzip}"
  memory_size   = var.lambda_sechub_enabler.memory_size
  role          = aws_iam_role.IAMRoleSecHubDelAdminLambda.arn
  runtime       = var.lambda_sechub_enabler.runtime
  timeout       = var.lambda_sechub_enabler.timeout
  tags = {
    Language         = "python",
    Language_Version = "3.8"
  }
}

resource "aws_lambda_function" "lambda_sechub_standards_manager" {
  depends_on = [
    aws_s3_bucket_object.object,
  ]
  description   = var.lambda_sechub_standards_manager.description
  function_name = var.lambda_sechub_standards_manager.function_name
  handler       = var.lambda_sechub_standards_manager.handler
  s3_bucket     = aws_s3_bucket.S3Bucket.id
  s3_key        = "${var.codepipeline_project_variables.projectnameshort}/${var.codepipeline_project_variables.artifactzip}"
  memory_size   = var.lambda_sechub_standards_manager.memory_size
  role          = aws_iam_role.IAMRoleSecHubDelAdminLambda.arn
  runtime       = var.lambda_sechub_standards_manager.runtime
  timeout       = var.lambda_sechub_standards_manager.timeout
  environment {
    variables = var.lambda_sechub_standards_manager_env
  }
  tags = {
    Language         = "python",
    Language_Version = "3.8"
  }
}