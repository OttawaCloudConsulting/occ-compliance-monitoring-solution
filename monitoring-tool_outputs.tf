
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