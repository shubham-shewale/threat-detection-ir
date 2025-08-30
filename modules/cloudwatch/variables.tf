variable "tags" {
  description = "Tags for CloudWatch resources"
  type        = map(string)
  default     = {}
}