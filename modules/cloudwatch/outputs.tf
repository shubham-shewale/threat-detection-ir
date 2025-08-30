output "lambda_log_group_arn" {
  description = "ARN of the CloudWatch log group for Lambda triage"
  value       = aws_cloudwatch_log_group.lambda_triage.arn
}

output "stepfn_log_group_arn" {
  description = "ARN of the CloudWatch log group for Step Functions IR"
  value       = aws_cloudwatch_log_group.stepfn_ir.arn
}