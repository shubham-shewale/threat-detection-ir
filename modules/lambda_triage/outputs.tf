output "function_name" {
  description = "Name of the Lambda triage function"
  value       = aws_lambda_function.triage.function_name
}

output "function_arn" {
  description = "ARN of the Lambda triage function"
  value       = aws_lambda_function.triage.arn
}