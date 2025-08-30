output "rule_names" {
  description = "List of EventBridge rule names"
  value       = [aws_cloudwatch_event_rule.guardduty_findings.name]
}

output "target_arns" {
  description = "List of target ARNs"
  value       = [var.lambda_function_arn, var.state_machine_arn]
}