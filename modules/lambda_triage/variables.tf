variable "evidence_bucket_name" {
  description = "Name of the S3 evidence bucket"
  type        = string
}

variable "sns_topic_arn" {
  description = "ARN of the SNS topic for notifications"
  type        = string
}

variable "state_machine_arn" {
  description = "ARN of the Step Functions state machine"
  type        = string
}

variable "quarantine_sg_id" {
  description = "ID of the quarantine security group"
  type        = string
}

variable "iam_role_arn" {
  description = "ARN of the IAM role for Lambda"
  type        = string
}

variable "cloudwatch_log_group_arn" {
  description = "ARN of the CloudWatch log group"
  type        = string
}

variable "tags" {
  description = "Tags for Lambda resources"
  type        = map(string)
  default     = {}
}