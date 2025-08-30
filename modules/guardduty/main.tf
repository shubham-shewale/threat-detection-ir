data "aws_region" "current" {}

# Enable GuardDuty detector
resource "aws_guardduty_detector" "this" {
  enable = true
  tags   = var.tags
}

# Organization settings if org_mode is enabled
resource "aws_guardduty_organization_admin_account" "this" {
  count = var.org_mode ? 1 : 0

  admin_account_id = var.delegated_admin_account_id
}

resource "aws_guardduty_organization_configuration" "this" {
  count = var.org_mode ? 1 : 0

  auto_enable_organization_members = "ALL"
  detector_id = aws_guardduty_detector.this.id
}