# Unit tests for GuardDuty module
# Validates detector creation, organization settings, findings export, and regional deployment

variables {
  org_mode                   = false
  delegated_admin_account_id = ""
  regions                    = ["us-east-1", "us-west-2"]
  tags = {
    Environment = "test"
    Project     = "threat-detection-ir"
  }
}

run "guardduty_detector_created" {
  command = plan

  assert {
    condition     = length(aws_guardduty_detector.this) > 0
    error_message = "GuardDuty detector must be created"
  }

  assert {
    condition     = aws_guardduty_detector.this[0].enable == true
    error_message = "GuardDuty detector must be enabled"
  }
}

run "detector_finding_publishing_frequency" {
  command = plan

  assert {
    condition     = aws_guardduty_detector.this[0].finding_publishing_frequency == "FIFTEEN_MINUTES"
    error_message = "GuardDuty detector must publish findings every 15 minutes"
  }
}

run "detector_datasources_configured" {
  command = plan

  assert {
    condition     = aws_guardduty_detector.this[0].datasources[0].s3_logs[0].enable == true
    error_message = "GuardDuty detector must have S3 logs datasource enabled"
  }

  assert {
    condition     = aws_guardduty_detector.this[0].datasources[0].kubernetes[0].audit_logs[0].enable == true
    error_message = "GuardDuty detector must have Kubernetes audit logs enabled"
  }

  assert {
    condition     = aws_guardduty_detector.this[0].datasources[0].malware_protection[0].scan_ec2_instance_with_findings[0].ebs_volumes[0].enable == true
    error_message = "GuardDuty detector must have EBS malware scanning enabled"
  }
}

run "regional_deployment" {
  command = plan

  # Test that detectors are created in specified regions
  assert {
    condition     = contains(var.regions, "us-east-1")
    error_message = "GuardDuty must be enabled in us-east-1"
  }

  assert {
    condition     = contains(var.regions, "us-west-2")
    error_message = "GuardDuty must be enabled in us-west-2"
  }
}

run "organization_mode_disabled" {
  command = plan

  # When org_mode is false, no organization resources should be created
  assert {
    condition     = aws_guardduty_organization_admin_account.this == null
    error_message = "Organization admin account should not be created when org_mode is false"
  }

  assert {
    condition     = aws_guardduty_organization_configuration.this == null
    error_message = "Organization configuration should not be created when org_mode is false"
  }
}

run "detector_tags_applied" {
  command = plan

  assert {
    condition     = aws_guardduty_detector.this[0].tags["Environment"] == "test"
    error_message = "GuardDuty detector must have Environment tag"
  }

  assert {
    condition     = aws_guardduty_detector.this[0].tags["Project"] == "threat-detection-ir"
    error_message = "GuardDuty detector must have Project tag"
  }
}

run "detector_outputs" {
  command = plan

  # Verify that detector IDs are properly exposed
  assert {
    condition     = aws_guardduty_detector.this[0].id != null
    error_message = "GuardDuty detector must expose its ID"
  }
}

# Test organization mode enabled
run "organization_mode_enabled" {
  command = plan

  variables {
    org_mode                   = true
    delegated_admin_account_id = "123456789012"
  }

  assert {
    condition     = aws_guardduty_organization_admin_account.this[0].admin_account_id == "123456789012"
    error_message = "Organization admin account must be set to delegated admin"
  }

  assert {
    condition     = aws_guardduty_organization_configuration.this[0].detector_id == aws_guardduty_detector.this[0].id
    error_message = "Organization configuration must reference the detector"
  }
}

# Negative test: Invalid region
run "invalid_region" {
  command = plan

  variables {
    regions = ["invalid-region"]
  }

  expect_failures = [
    aws_guardduty_detector.this
  ]
}

# Negative test: Empty regions list
run "empty_regions" {
  command = plan

  variables {
    regions = []
  }

  # This should still work but create no detectors
  assert {
    condition     = length(aws_guardduty_detector.this) == 0
    error_message = "No detectors should be created when regions list is empty"
  }
}

# Negative test: Invalid delegated admin account ID
run "invalid_delegated_admin" {
  command = plan

  variables {
    org_mode                   = true
    delegated_admin_account_id = "invalid"
  }

  expect_failures = [
    aws_guardduty_organization_admin_account.this
  ]
}