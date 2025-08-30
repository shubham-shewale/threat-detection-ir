variable "bucket_name" {
  description = "Name of the S3 evidence bucket"
  type        = string
}

variable "kms_alias" {
  description = "KMS key alias for encryption"
  type        = string
}

variable "tags" {
  description = "Tags for S3 resources"
  type        = map(string)
  default     = {}
}