output "quarantine_sg_id" {
  description = "ID of the quarantine security group"
  value       = aws_security_group.quarantine.id
}