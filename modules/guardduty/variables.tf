variable "org_mode" {
  description = "Enable AWS Organizations mode"
  type        = bool
}

variable "delegated_admin_account_id" {
  description = "Delegated admin account ID for Organizations"
  type        = string
  default     = ""
}

variable "regions" {
  description = "List of regions to enable GuardDuty"
  type        = list(string)
}

variable "tags" {
  description = "Tags for GuardDuty resources"
  type        = map(string)
  default     = {}
}