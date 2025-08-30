# Quarantine Security Group
resource "aws_security_group" "quarantine" {
  name        = var.sg_name
  description = "Security group for quarantining compromised resources - denies all inbound and outbound traffic"

  tags = var.tags

  # No ingress rules - deny all inbound traffic
  # No egress rules - deny all outbound traffic
}