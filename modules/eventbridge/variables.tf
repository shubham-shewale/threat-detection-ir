variable "lambda_function_arn" {
  description = "ARN of the Lambda triage function"
  type        = string
}

variable "state_machine_arn" {
  description = "ARN of the Step Functions IR state machine"
  type        = string
}

variable "finding_severity_threshold" {
  description = "Minimum severity threshold for findings (LOW, MEDIUM, HIGH, CRITICAL)"
  type        = string
}

variable "tags" {
  description = "Tags for EventBridge resources"
  type        = map(string)
  default     = {}
}