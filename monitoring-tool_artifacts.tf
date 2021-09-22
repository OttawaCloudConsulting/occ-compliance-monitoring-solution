data "archive_file" "stackset_artifacts" {
  type        = "zip"
  source_dir  = "${path.module}/src/stackset_artifacts"
  output_path = "${path.module}/artifacts/${var.codepipeline_project_variables.integratorzip}"
}

data "archive_file" "pipeine_artifacts" {
  type        = "zip"
  source_dir  = "${path.module}/src/pipeline_artifacts"
  output_path = "${path.module}/artifacts/${var.codepipeline_project_variables.artifactzip}"
}

resource "aws_s3_bucket_object" "object" {
  for_each = fileset("./artifacts/", "*")
  bucket   = aws_s3_bucket.S3Bucket.id
  key      = "${var.codepipeline_project_variables.projectnameshort}/${each.value}"
  source   = "./artifacts/${each.value}"
  etag     = filemd5("./artifacts/${each.value}")
}