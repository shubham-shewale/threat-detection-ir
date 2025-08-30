variable "enable_standards" {
  description = "Map of Security Hub standards to enable"
  type        = map(bool)
}

variable "tags" {
  description = "Tags for Security Hub resources"
  type        = map(string)
  default     = {}
}