variable "region" {
  description = "AWS region for primary resources"
  type        = string
  default     = "us-east-1"
}

variable "org_mode" {
  description = "Enable AWS Organizations mode for multi-account setup"
  type        = bool
  default     = false
}

variable "delegated_admin_account_id" {
  description = "AWS account ID for delegated admin (required if org_mode is true)"
  type        = string
  default     = ""
}

variable "enable_standards" {
  description = "Map of Security Hub standards to enable"
  type        = map(bool)
  default = {
    "aws-foundational-security-best-practices" = true
    "cis-aws-foundations-benchmark"            = true
    "nist-800-53-rev-5"                        = false
    "pci-dss"                                  = false
  }
}

variable "evidence_bucket_name" {
  description = "Name for the S3 evidence bucket"
  type        = string
  default     = "ir-evidence-bucket"
}

variable "kms_alias" {
  description = "KMS key alias for encryption"
  type        = string
  default     = "alias/ir-evidence-key"
}

variable "quarantine_sg_name" {
  description = "Name for the quarantine security group"
  type        = string
  default     = "quarantine-sg"
}

variable "sns_subscriptions" {
  description = "List of SNS subscriptions"
  type = list(object({
    protocol = string
    endpoint = string
  }))
  default = []
}

variable "finding_severity_threshold" {
  description = "Minimum severity threshold for findings (LOW, MEDIUM, HIGH, CRITICAL)"
  type        = string
  default     = "HIGH"
}

variable "regions" {
  description = "List of AWS regions to enable GuardDuty"
  type        = list(string)
  default     = ["us-east-1", "us-west-2", "eu-west-1"]
}

variable "tags" {
  description = "Common tags for all resources"
  type        = map(string)
  default = {
    Environment = "production"
    Project     = "threat-detection-ir"
  }
}