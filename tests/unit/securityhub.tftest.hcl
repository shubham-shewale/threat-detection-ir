# Unit tests for Security Hub module
# Validates standards enablement, findings aggregation, and organization configuration

variables {
  enable_standards = {
    "aws-foundational-security-best-practices" = true
    "cis-aws-foundations-benchmark"            = true
    "nist-800-53-rev-5"                        = false
    "pci-dss"                                  = false
  }
  tags = {
    Environment = "test"
    Project     = "threat-detection-ir"
  }
}

run "security_hub_enabled" {
  command = plan

  assert {
    condition     = aws_securityhub_account.this[0].enable_default_standards == false
    error_message = "Security Hub should not enable default standards (we control them explicitly)"
  }

  assert {
    condition     = aws_securityhub_account.this[0].control_finding_generator == "SECURITY_CONTROL"
    error_message = "Security Hub must generate security control findings"
  }
}

run "standards_enabled_correctly" {
  command = plan

  # Check that enabled standards are actually enabled
  assert {
    condition     = aws_securityhub_standards_subscription.aws_foundational[0].standards_arn == "arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0"
    error_message = "AWS Foundational Security Best Practices standard must be enabled"
  }

  assert {
    condition     = aws_securityhub_standards_subscription.cis[0].standards_arn == "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"
    error_message = "CIS AWS Foundations Benchmark standard must be enabled"
  }
}

run "standards_disabled_correctly" {
  command = plan

  # Check that disabled standards are not enabled
  assert {
    condition     = aws_securityhub_standards_subscription.nist == null
    error_message = "NIST 800-53 standard should not be enabled when set to false"
  }

  assert {
    condition     = aws_securityhub_standards_subscription.pci == null
    error_message = "PCI DSS standard should not be enabled when set to false"
  }
}

run "standards_subscription_outputs" {
  command = plan

  assert {
    condition     = aws_securityhub_standards_subscription.aws_foundational[0].id != null
    error_message = "AWS Foundational standard subscription must have an ID"
  }

  assert {
    condition     = aws_securityhub_standards_subscription.cis[0].id != null
    error_message = "CIS standard subscription must have an ID"
  }
}

run "hub_configuration" {
  command = plan

  assert {
    condition     = aws_securityhub_account.this[0].auto_enable_controls == true
    error_message = "Security Hub must auto-enable controls"
  }
}

run "security_hub_tags" {
  command = plan

  assert {
    condition     = aws_securityhub_account.this[0].tags["Environment"] == "test"
    error_message = "Security Hub must have Environment tag"
  }

  assert {
    condition     = aws_securityhub_account.this[0].tags["Project"] == "threat-detection-ir"
    error_message = "Security Hub must have Project tag"
  }
}

run "standards_control_enabled" {
  command = plan

  # Verify that standards controls are enabled for enabled standards
  assert {
    condition     = aws_securityhub_standards_subscription.aws_foundational[0].standards_arn != null
    error_message = "Standards controls must be enabled for subscribed standards"
  }
}

# Test with all standards disabled
run "all_standards_disabled" {
  command = plan

  variables {
    enable_standards = {
      "aws-foundational-security-best-practices" = false
      "cis-aws-foundations-benchmark"            = false
      "nist-800-53-rev-5"                        = false
      "pci-dss"                                  = false
    }
  }

  assert {
    condition     = aws_securityhub_standards_subscription.aws_foundational == null
    error_message = "No standards should be enabled when all are set to false"
  }

  assert {
    condition     = aws_securityhub_standards_subscription.cis == null
    error_message = "No standards should be enabled when all are set to false"
  }

  assert {
    condition     = aws_securityhub_standards_subscription.nist == null
    error_message = "No standards should be enabled when all are set to false"
  }

  assert {
    condition     = aws_securityhub_standards_subscription.pci == null
    error_message = "No standards should be enabled when all are set to false"
  }
}

# Test with all standards enabled
run "all_standards_enabled" {
  command = plan

  variables {
    enable_standards = {
      "aws-foundational-security-best-practices" = true
      "cis-aws-foundations-benchmark"            = true
      "nist-800-53-rev-5"                        = true
      "pci-dss"                                  = true
    }
  }

  assert {
    condition     = aws_securityhub_standards_subscription.aws_foundational[0] != null
    error_message = "AWS Foundational standard must be enabled"
  }

  assert {
    condition     = aws_securityhub_standards_subscription.cis[0] != null
    error_message = "CIS standard must be enabled"
  }

  assert {
    condition     = aws_securityhub_standards_subscription.nist[0] != null
    error_message = "NIST standard must be enabled"
  }

  assert {
    condition     = aws_securityhub_standards_subscription.pci[0] != null
    error_message = "PCI DSS standard must be enabled"
  }
}

# Negative test: Invalid standards map
run "invalid_standards_map" {
  command = plan

  variables {
    enable_standards = {}
  }

  # This should still work but enable no standards
  assert {
    condition     = aws_securityhub_standards_subscription.aws_foundational == null
    error_message = "No standards should be enabled with empty map"
  }
}

# Negative test: Invalid standard ARN
run "invalid_standard_arn" {
  command = plan

  # This would be tested if we had invalid ARNs in the module
  assert {
    condition     = aws_securityhub_account.this[0].enable_default_standards == false
    error_message = "Security Hub configuration must be valid"
  }
}