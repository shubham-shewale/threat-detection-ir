output "hub_arns" {
  description = "List of Security Hub hub ARNs"
  value = [
    "arn:aws:securityhub:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:hub/default"
  ]
}

output "enabled_standards" {
  description = "List of enabled standards ARNs"
  value = concat(
    var.enable_standards["aws-foundational-security-best-practices"] ? [aws_securityhub_standards_subscription.aws_foundational[0].standards_arn] : [],
    var.enable_standards["cis-aws-foundations-benchmark"] ? [aws_securityhub_standards_subscription.cis[0].standards_arn] : [],
    var.enable_standards["nist-800-53-rev-5"] ? [aws_securityhub_standards_subscription.nist[0].standards_arn] : [],
    var.enable_standards["pci-dss"] ? [aws_securityhub_standards_subscription.pci[0].standards_arn] : []
  )
}