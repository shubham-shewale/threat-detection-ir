variable "sg_name" {
  description = "Name of the quarantine security group"
  type        = string
}

variable "tags" {
  description = "Tags for the security group"
  type        = map(string)
  default     = {}
}