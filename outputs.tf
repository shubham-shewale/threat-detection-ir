output "guardduty_detector_ids" {
  description = "GuardDuty detector IDs"
  value       = try(module.guardduty.detector_ids, {})
}

output "securityhub_hub_arns" {
  description = "Security Hub hub ARNs"
  value       = try(module.securityhub.hub_arns, [])
}

output "s3_evidence_bucket_name" {
  description = "S3 evidence bucket name"
  value       = try(module.s3_evidence.bucket_name, "")
}

output "sns_topic_arn" {
  description = "SNS topic ARN for alerts"
  value       = try(module.sns_alerts.topic_arn, "")
}

output "eventbridge_rule_names" {
  description = "EventBridge rule names"
  value       = try(module.eventbridge.rule_names, [])
}

output "lambda_triage_function_name" {
  description = "Lambda triage function name"
  value       = try(module.lambda_triage.function_name, "")
}

output "stepfn_ir_state_machine_arn" {
  description = "Step Functions IR state machine ARN"
  value       = try(module.stepfn_ir.state_machine_arn, "")
}

output "network_quarantine_sg_id" {
  description = "Quarantine security group ID"
  value       = try(module.network_quarantine.quarantine_sg_id, "")
}

output "iam_lambda_role_arn" {
  description = "IAM role ARN for Lambda"
  value       = try(module.iam_roles.lambda_role_arn, "")
}

output "iam_stepfn_role_arn" {
  description = "IAM role ARN for Step Functions"
  value       = try(module.iam_roles.stepfn_role_arn, "")
}