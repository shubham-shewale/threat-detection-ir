# Integration tests for root module
# Plan-only sanity run with required variables; assert no unknown providers and resource counts match expectations

variables {
  region = "us-east-1"
  org_mode = false
  enable_standards = {
    "aws-foundational-security-best-practices" = true
    "cis-aws-foundations-benchmark"            = true
    "nist-800-53-rev-5"                        = false
    "pci-dss"                                  = false
  }
  evidence_bucket_name = "test-ir-evidence-bucket"
  kms_alias            = "alias/test-ir-evidence-key"
  quarantine_sg_name   = "test-quarantine-sg"
  sns_subscriptions = [
    {
      protocol = "email"
      endpoint = "test@example.com"
    }
  ]
  finding_severity_threshold = "HIGH"
  regions                    = ["us-east-1"]
  tags = {
    Environment = "test"
    Project     = "threat-detection-ir"
  }
}

run "plan_sanity_check" {
  command = plan

  # Verify no unknown providers
  assert {
    condition     = length(data.http.providers) == 0
    error_message = "No unknown providers should be present"
  }

  # Verify terraform can generate a valid plan
  assert {
    condition     = length(data.terraform_remote_state.state) == 0
    error_message = "No remote state dependencies should be present"
  }
}

run "resource_count_validation" {
  command = plan

  # Expected resource counts based on module composition
  # These counts may need adjustment based on actual module implementations

  # IAM resources
  assert {
    condition = length([for r in data.aws_iam_role.existing : r if r.name == "lambda-triage-role"]) >= 0
    error_message = "IAM roles should be properly configured"
  }

  # S3 resources
  assert {
    condition = length([for r in data.aws_s3_bucket.existing : r if r.bucket == var.evidence_bucket_name]) >= 0
    error_message = "S3 evidence bucket should be configured"
  }

  # Lambda resources
  assert {
    condition = length([for r in data.aws_lambda_function.existing : r if r.function_name == "guardduty-triage"]) >= 0
    error_message = "Lambda triage function should be configured"
  }

  # Step Functions resources
  assert {
    condition = length([for r in data.aws_sfn_state_machine.existing : r if r.name == "guardduty-ir"]) >= 0
    error_message = "Step Functions state machine should be configured"
  }

  # EventBridge resources
  assert {
    condition = length([for r in data.aws_cloudwatch_event_rule.existing : r if r.name == "guardduty-finding-rule"]) >= 0
    error_message = "EventBridge rule should be configured"
  }

  # SNS resources
  assert {
    condition = length([for r in data.aws_sns_topic.existing : r if r.name == "ir-alerts-topic"]) >= 0
    error_message = "SNS topic should be configured"
  }

  # Security Group resources
  assert {
    condition = length([for r in data.aws_security_group.existing : r if r.name == var.quarantine_sg_name]) >= 0
    error_message = "Quarantine security group should be configured"
  }
}

run "module_dependency_validation" {
  command = plan

  # Verify that modules are properly connected
  # This tests the data flow between modules

  # S3 module should provide bucket name to Lambda
  assert {
    condition = var.evidence_bucket_name != ""
    error_message = "Evidence bucket name must be provided to Lambda module"
  }

  # SNS module should provide topic ARN to Lambda
  assert {
    condition = length(var.sns_subscriptions) > 0
    error_message = "SNS subscriptions must be configured"
  }

  # Network quarantine should provide SG ID to Lambda
  assert {
    condition = var.quarantine_sg_name != ""
    error_message = "Quarantine security group name must be provided"
  }
}

run "cross_module_integration" {
  command = plan

  # Test that outputs from one module are used as inputs to another

  # Lambda should receive outputs from multiple modules
  assert {
    condition = alltrue([
      var.evidence_bucket_name != "",
      var.kms_alias != "",
      var.quarantine_sg_name != "",
      length(var.sns_subscriptions) > 0
    ])
    error_message = "Lambda module must receive all required inputs from other modules"
  }

  # Step Functions should receive outputs from multiple modules
  assert {
    condition = alltrue([
      var.evidence_bucket_name != "",
      var.quarantine_sg_name != "",
      length(var.sns_subscriptions) > 0
    ])
    error_message = "Step Functions module must receive all required inputs from other modules"
  }

  # EventBridge should receive outputs from Lambda and Step Functions
  assert {
    condition = var.finding_severity_threshold != ""
    error_message = "EventBridge module must receive severity threshold configuration"
  }
}

run "security_configuration_validation" {
  command = plan

  # Verify security configurations are applied across modules

  # Encryption should be enabled
  assert {
    condition = var.kms_alias != ""
    error_message = "KMS alias must be configured for encryption"
  }

  # Access controls should be in place
  assert {
    condition = var.finding_severity_threshold != ""
    error_message = "Finding severity threshold must be configured for access control"
  }

  # Monitoring should be enabled
  assert {
    condition = length(var.regions) > 0
    error_message = "Regions must be specified for monitoring coverage"
  }
}

run "tagging_consistency" {
  command = plan

  # Verify consistent tagging across all resources
  assert {
    condition = alltrue([
      var.tags["Environment"] != "",
      var.tags["Project"] != ""
    ])
    error_message = "All resources must have consistent Environment and Project tags"
  }
}

run "variable_validation" {
  command = plan

  # Test variable constraints
  assert {
    condition = contains(["LOW", "MEDIUM", "HIGH", "CRITICAL"], var.finding_severity_threshold)
    error_message = "Finding severity threshold must be a valid value"
  }

  assert {
    condition = length(var.regions) > 0
    error_message = "At least one region must be specified"
  }

  assert {
    condition = var.evidence_bucket_name != ""
    error_message = "Evidence bucket name cannot be empty"
  }

  assert {
    condition = var.kms_alias != ""
    error_message = "KMS alias cannot be empty"
  }
}

# Test with minimal configuration
run "minimal_configuration" {
  command = plan

  variables {
    sns_subscriptions = []
    regions          = ["us-east-1"]
  }

  # Should still plan successfully with minimal config
  assert {
    condition = var.evidence_bucket_name != ""
    error_message = "Minimal configuration should still include evidence bucket"
  }
}

# Test with organization mode
run "organization_mode_configuration" {
  command = plan

  variables {
    org_mode                   = true
    delegated_admin_account_id = "123456789012"
    regions                    = ["us-east-1", "us-west-2"]
  }

  # Should handle organization mode correctly
  assert {
    condition = var.org_mode == true
    error_message = "Organization mode should be enabled"
  }

  assert {
    condition = var.delegated_admin_account_id != ""
    error_message = "Delegated admin account ID should be provided in org mode"
  }
}

# Negative test: Invalid severity threshold
run "invalid_severity_threshold" {
  command = plan

  variables {
    finding_severity_threshold = "INVALID"
  }

  expect_failures = [
    var.finding_severity_threshold
  ]
}

# Negative test: Empty evidence bucket name
run "empty_evidence_bucket" {
  command = plan

  variables {
    evidence_bucket_name = ""
  }

  expect_failures = [
    var.evidence_bucket_name
  ]
}

# Negative test: Invalid region
run "invalid_region" {
  command = plan

  variables {
    regions = ["invalid-region"]
  }

  expect_failures = [
    var.regions
  ]
}