variable "subscriptions" {
  description = "List of SNS subscriptions"
  type = list(object({
    protocol = string
    endpoint = string
  }))
  default = []
}

variable "tags" {
  description = "Tags for SNS resources"
  type        = map(string)
  default     = {}
}