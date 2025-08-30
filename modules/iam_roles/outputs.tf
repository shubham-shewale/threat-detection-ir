output "lambda_role_arn" {
  description = "ARN of the IAM role for Lambda triage function"
  value       = aws_iam_role.lambda_triage.arn
}

output "stepfn_role_arn" {
  description = "ARN of the IAM role for Step Functions IR state machine"
  value       = aws_iam_role.stepfn_ir.arn
}