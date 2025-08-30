output "detector_ids" {
  description = "Map of region to GuardDuty detector ID"
  value = {
    (data.aws_region.current.name) = aws_guardduty_detector.this.id
  }
}

output "admin_account_settings" {
  description = "Organization admin account settings"
  value = var.org_mode ? {
    admin_account_id = aws_guardduty_organization_admin_account.this[0].admin_account_id
  } : null
}