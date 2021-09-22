
resource "aws_codepipeline" "CodePipelinePipeline" {
  name     = var.codepipeline_project_variables.projectname
  role_arn = aws_iam_role.IAMRoleCodePipeline.arn
  artifact_store {
    location = aws_s3_bucket.S3Bucket.id
    type     = "S3"
  }
  stage {
    name = "Source"
    action {
      name     = "SourceAction"
      category = "Source"
      owner    = "AWS"
      configuration = {
        PollForSourceChanges = "true"
        S3Bucket             = aws_s3_bucket.S3Bucket.id
        S3ObjectKey          = "${var.codepipeline_project_variables.projectnameshort}/${var.codepipeline_project_variables.artifactzip}"
      }
      provider = "S3"
      version  = "1"
      output_artifacts = [
        "SourceArtifact"
      ]
      run_order = 1
    }
  }
  stage {
    name = "SecurityHub-${var.codepipeline_project_variables.projectnameshort}"
    action {
      name     = "SecurityHub_${var.codepipeline_project_variables.projectnameshort}"
      category = "Deploy"
      owner    = "AWS"
      provider = "CloudFormationStackSet"
      version  = "1"
      configuration = merge({
        DeploymentTargets = data.aws_organizations_organization.awsorg.roots[0].id,
        Parameters        = "ParameterKey=pDefaultRegion,ParameterValue=ca-central-1 ParameterKey=pDefaultAccountId,ParameterValue=${data.aws_caller_identity.current.account_id} ParameterKey=pLambdaRoleToTrust,ParameterValue=${aws_iam_role.IAMRoleSecHubDelAdminLambda.arn}"
      }, var.stageparams_securityhub)
      input_artifacts = [
        "SourceArtifact"
      ]
      run_order = 1
    }
  }
  stage {
    name = "ConfigSecHubIntegrator-${var.codepipeline_project_variables.projectnameshort}"
    action {
      name     = "ConfigSecHubIntegrator_${var.codepipeline_project_variables.projectnameshort}"
      category = "Deploy"
      owner    = "AWS"
      provider = "CloudFormationStackSet"
      version  = "1"
      configuration = merge({
        DeploymentTargets = data.aws_organizations_organization.awsorg.roots[0].id,
        Parameters        = "ParameterKey=S3Bucket,ParameterValue=${aws_s3_bucket.S3Bucket.id} ParameterKey=S3Key,ParameterValue=${var.codepipeline_project_variables.projectnameshort}/${var.codepipeline_project_variables.integratorzip} ParameterKey=LambdaHandler,ParameterValue=${var.codepipeline_project_variables.integratorlambdahandler} ParameterKey=pDefaultRegion,ParameterValue=ca-central-1 ParameterKey=pDefaultAccountId,ParameterValue=${data.aws_caller_identity.current.account_id} ParameterKey=pS3ObjectVersion,ParameterValue=${aws_s3_bucket_object.object["${var.codepipeline_project_variables.integratorzip}"].version_id}"
      }, var.stageparams_config_sechub_integrator)
      input_artifacts = [
        "SourceArtifact"
      ]
      run_order = 1
    }
  }
  stage {
    name = "ConfigRules-${var.codepipeline_project_variables.projectnameshort}"
    action {
      name     = "ConfigRules-${var.codepipeline_project_variables.projectnameshort}"
      category = "Deploy"
      owner    = "AWS"
      provider = "CloudFormationStackSet"
      version  = "1"
      configuration = merge({
        DeploymentTargets = data.aws_organizations_organization.awsorg.roots[0].id
      }, var.stageparams_config_rules)
      input_artifacts = [
        "SourceArtifact"
      ]
      run_order = 1
    }
  }
  stage {
    name = "SecHubOrgAdmin-${var.codepipeline_project_variables.projectnameshort}"
    action {
      name     = "SecHubOrgAdmin${var.codepipeline_project_variables.projectnameshort}"
      category = "Invoke"
      owner    = "AWS"
      provider = "Lambda"
      version  = "1"
      configuration = merge({
        FunctionName = aws_lambda_function.sechub_enabler.function_name
      }, var.stageparams_sechuborgadmin)
      run_order = 1
    }
  }
  stage {
    name = "SecHubStandardsManager-${var.codepipeline_project_variables.projectnameshort}"
    action {
      name     = "SecHubStandardsManager${var.codepipeline_project_variables.projectnameshort}"
      category = "Invoke"
      owner    = "AWS"
      provider = "Lambda"
      version  = "1"
      configuration = merge({
        FunctionName = aws_lambda_function.lambda_sechub_standards_manager.function_name
      }, var.stageparams_sechub_standards_manager)
      run_order = 1
    }
  }
}