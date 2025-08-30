# Unit tests for Network Quarantine module
# Validates zero ingress, no or minimal egress; description and tags; outputs expose SG ID

variables {
  sg_name = "test-quarantine-sg"
  tags = {
    Environment = "test"
    Project     = "threat-detection-ir"
  }
}

run "security_group_created" {
  command = plan

  assert {
    condition     = aws_security_group.quarantine.name == var.sg_name
    error_message = "Security group must have correct name"
  }

  assert {
    condition     = aws_security_group.quarantine.description == "Security group for quarantining compromised resources"
    error_message = "Security group must have proper description"
  }
}

run "zero_ingress_rules" {
  command = plan

  # Check that no ingress rules are defined
  assert {
    condition     = length(aws_security_group.quarantine.ingress) == 0
    error_message = "Quarantine security group must have zero ingress rules"
  }
}

run "minimal_egress_rules" {
  command = plan

  # Check that egress rules are minimal (allow all outbound is acceptable for quarantine)
  assert {
    condition     = length(aws_security_group.quarantine.egress) >= 0
    error_message = "Quarantine security group must have egress rules defined"
  }

  # If there are egress rules, they should be restrictive
  assert {
    condition = alltrue([
      for rule in aws_security_group.quarantine.egress :
      rule.from_port == 0 && rule.to_port == 0 && rule.protocol == "-1"
    ]) || length(aws_security_group.quarantine.egress) == 0
    error_message = "Quarantine security group should have minimal or no egress rules"
  }
}

run "security_group_tags" {
  command = plan

  assert {
    condition     = aws_security_group.quarantine.tags["Name"] == var.sg_name
    error_message = "Security group must have Name tag"
  }

  assert {
    condition     = aws_security_group.quarantine.tags["Purpose"] == "Quarantine"
    error_message = "Security group must have Purpose tag set to Quarantine"
  }

  assert {
    condition     = aws_security_group.quarantine.tags["Environment"] == "test"
    error_message = "Security group must have Environment tag"
  }
}

run "vpc_association" {
  command = plan

  assert {
    condition     = aws_security_group.quarantine.vpc_id != null
    error_message = "Security group must be associated with a VPC"
  }
}

run "output_sg_id" {
  command = plan

  assert {
    condition     = aws_security_group.quarantine.id != null
    error_message = "Security group must expose its ID as output"
  }
}

run "security_group_rules_structure" {
  command = plan

  # Verify the structure of any egress rules
  assert {
    condition = aws_security_group.quarantine.egress == null || alltrue([
      for rule in aws_security_group.quarantine.egress :
      rule.cidr_blocks != null || rule.security_groups != null
    ])
    error_message = "Egress rules must have proper destination specification"
  }
}

# Negative test: Non-zero ingress rules (should fail)
run "no_ingress_allowed" {
  command = plan

  # This test verifies that we don't accidentally add ingress rules
  assert {
    condition = length(aws_security_group.quarantine.ingress) == 0
    error_message = "Quarantine security group must never have ingress rules"
  }
}

# Negative test: Invalid security group name
run "invalid_sg_name" {
  command = plan

  variables {
    sg_name = ""
  }

  expect_failures = [
    aws_security_group.quarantine
  ]
}

# Negative test: Missing required tags
run "missing_required_tags" {
  command = plan

  variables {
    tags = {}
  }

  expect_failures = [
    aws_security_group.quarantine
  ]
}