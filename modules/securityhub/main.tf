data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Enable Security Hub
resource "aws_securityhub_account" "this" {}

# Standards subscriptions
resource "aws_securityhub_standards_subscription" "aws_foundational" {
  count = var.enable_standards["aws-foundational-security-best-practices"] ? 1 : 0

  standards_arn = "arn:aws:securityhub:${data.aws_region.current.name}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.this]
}

resource "aws_securityhub_standards_subscription" "cis" {
  count = var.enable_standards["cis-aws-foundations-benchmark"] ? 1 : 0

  standards_arn = "arn:aws:securityhub:${data.aws_region.current.name}::standards/cis-aws-foundations-benchmark/v/3.0.0"
  depends_on    = [aws_securityhub_account.this]
}

resource "aws_securityhub_standards_subscription" "nist" {
  count = var.enable_standards["nist-800-53-rev-5"] ? 1 : 0

  standards_arn = "arn:aws:securityhub:${data.aws_region.current.name}::standards/nist-800-53-rev-5/v/1.0.0"
  depends_on    = [aws_securityhub_account.this]
}

resource "aws_securityhub_standards_subscription" "pci" {
  count = var.enable_standards["pci-dss"] ? 1 : 0

  standards_arn = "arn:aws:securityhub:${data.aws_region.current.name}::standards/pci-dss/v/3.2.1"
  depends_on    = [aws_securityhub_account.this]
}