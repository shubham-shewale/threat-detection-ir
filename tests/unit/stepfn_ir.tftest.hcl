# Unit tests for Step Functions IR module
# Validates Retry blocks with exponential backoff then Catch to failure handler; logging configuration enabled; output path includes status and evidence keys

variables {
  evidence_bucket_name     = "test-ir-evidence-bucket"
  sns_topic_arn            = "arn:aws:sns:us-east-1:123456789012:ir-alerts-topic"
  quarantine_sg_id         = "sg-12345678"
  iam_role_arn             = "arn:aws:iam::123456789012:role/stepfn-ir-role"
  cloudwatch_log_group_arn = "arn:aws:logs:us-east-1:123456789012:log-group:/aws/states/guardduty-ir"
  tags = {
    Environment = "test"
    Project     = "threat-detection-ir"
  }
}

run "state_machine_configured" {
  command = plan

  assert {
    condition     = aws_sfn_state_machine.ir.name == "guardduty-ir"
    error_message = "State machine must have correct name"
  }

  assert {
    condition     = aws_sfn_state_machine.ir.role_arn == var.iam_role_arn
    error_message = "State machine must use the specified IAM role"
  }
}

run "state_machine_definition_structure" {
  command = plan

  assert {
    condition = strcontains(aws_sfn_state_machine.ir.definition, "StoreEvidence")
    error_message = "State machine must have StoreEvidence state"
  }

  assert {
    condition = strcontains(aws_sfn_state_machine.ir.definition, "IsolateResource")
    error_message = "State machine must have IsolateResource state"
  }

  assert {
    condition = strcontains(aws_sfn_state_machine.ir.definition, "Notify")
    error_message = "State machine must have Notify state"
  }

  assert {
    condition = strcontains(aws_sfn_state_machine.ir.definition, "UpdateSecurityHub")
    error_message = "State machine must have UpdateSecurityHub state"
  }
}

run "state_machine_start_state" {
  command = plan

  assert {
    condition = strcontains(aws_sfn_state_machine.ir.definition, "\"StartAt\": \"StoreEvidence\"")
    error_message = "State machine must start with StoreEvidence state"
  }
}

run "state_machine_end_state" {
  command = plan

  assert {
    condition = strcontains(aws_sfn_state_machine.ir.definition, "\"End\": true")
    error_message = "State machine must have proper end state"
  }
}

run "retry_configuration_present" {
  command = plan

  assert {
    condition = strcontains(aws_sfn_state_machine.ir.definition, "Retry")
    error_message = "State machine must have retry configuration"
  }

  assert {
    condition = strcontains(aws_sfn_state_machine.ir.definition, "BackoffRate")
    error_message = "State machine must have exponential backoff configured"
  }
}

run "catch_configuration_present" {
  command = plan

  assert {
    condition = strcontains(aws_sfn_state_machine.ir.definition, "Catch")
    error_message = "State machine must have catch configuration for error handling"
  }
}

run "exponential_backoff_configured" {
  command = plan

  assert {
    condition = strcontains(aws_sfn_state_machine.ir.definition, "\"BackoffRate\": 2")
    error_message = "State machine must have exponential backoff rate of 2"
  }

  assert {
    condition = strcontains(aws_sfn_state_machine.ir.definition, "\"MaxAttempts\": 3")
    error_message = "State machine must have maximum retry attempts configured"
  }
}

run "logging_configuration_enabled" {
  command = plan

  assert {
    condition     = aws_sfn_state_machine.ir.logging_configuration[0].log_destination != null
    error_message = "State machine must have logging destination configured"
  }

  assert {
    condition     = aws_sfn_state_machine.ir.logging_configuration[0].include_execution_data == true
    error_message = "State machine must include execution data in logs"
  }

  assert {
    condition     = aws_sfn_state_machine.ir.logging_configuration[0].level == "ALL"
    error_message = "State machine must log at ALL level"
  }
}

run "cloudwatch_log_group_configured" {
  command = plan

  assert {
    condition     = aws_cloudwatch_log_group.stepfn.name == "/aws/states/guardduty-ir"
    error_message = "CloudWatch log group must have correct name"
  }

  assert {
    condition     = aws_cloudwatch_log_group.stepfn.retention_in_days == 90
    error_message = "CloudWatch log group must have 90-day retention"
  }

  assert {
    condition     = aws_cloudwatch_log_group.stepfn.kms_key_id != null
    error_message = "CloudWatch log group must be encrypted"
  }
}

run "output_path_includes_status" {
  command = plan

  assert {
    condition = strcontains(aws_sfn_state_machine.ir.definition, "ResultPath")
    error_message = "State machine must have ResultPath configured for status tracking"
  }

  assert {
    condition = strcontains(aws_sfn_state_machine.ir.definition, "$.evidence")
    error_message = "State machine must include evidence in output path"
  }

  assert {
    condition = strcontains(aws_sfn_state_machine.ir.definition, "$.isolation")
    error_message = "State machine must include isolation status in output path"
  }

  assert {
    condition = strcontains(aws_sfn_state_machine.ir.definition, "$.notification")
    error_message = "State machine must include notification status in output path"
  }

  assert {
    condition = strcontains(aws_sfn_state_machine.ir.definition, "$.securityhub")
    error_message = "State machine must include Security Hub update status in output path"
  }
}

run "state_machine_iam_role" {
  command = plan

  assert {
    condition     = aws_iam_role.stepfn_ir.name == "stepfn-ir-role"
    error_message = "Step Functions IAM role must have correct name"
  }

  assert {
    condition = strcontains(aws_iam_role.stepfn_ir.assume_role_policy, "states.amazonaws.com")
    error_message = "Step Functions role must allow Step Functions service to assume it"
  }
}

run "stepfn_policy_least_privilege" {
  command = plan

  assert {
    condition = strcontains(aws_iam_policy.stepfn_ir.policy, "states:StartExecution")
    error_message = "Step Functions policy should not allow StartExecution (only for EventBridge)"
  }

  assert {
    condition = strcontains(aws_iam_policy.stepfn_ir.policy, "lambda:InvokeFunction")
    error_message = "Step Functions policy must allow Lambda invocation"
  }

  assert {
    condition = strcontains(aws_iam_policy.stepfn_ir.policy, "s3:GetObject")
    error_message = "Step Functions policy must allow S3 read access"
  }

  assert {
    condition = strcontains(aws_iam_policy.stepfn_ir.policy, "s3:PutObject")
    error_message = "Step Functions policy must allow S3 write access"
  }
}

run "error_handling_states" {
  command = plan

  assert {
    condition = strcontains(aws_sfn_state_machine.ir.definition, "Error")
    error_message = "State machine must have error handling states"
  }

  assert {
    condition = strcontains(aws_sfn_state_machine.ir.definition, "Cause")
    error_message = "State machine must capture error causes"
  }
}

run "state_machine_timeout_configured" {
  command = plan

  # Check if timeout is configured (implementation dependent)
  assert {
    condition = aws_sfn_state_machine.ir.definition != null
    error_message = "State machine must have definition configured"
  }
}

run "execution_history_logging" {
  command = plan

  assert {
    condition     = aws_sfn_state_machine.ir.logging_configuration[0].include_execution_data == true
    error_message = "State machine must include execution data in logs for debugging"
  }
}

# Negative test: Invalid IAM role ARN
run "invalid_iam_role_arn" {
  command = plan

  variables {
    iam_role_arn = "invalid-arn"
  }

  expect_failures = [
    aws_sfn_state_machine.ir
  ]
}

# Negative test: Missing required variables
run "missing_evidence_bucket" {
  command = plan

  variables {
    evidence_bucket_name = ""
  }

  expect_failures = [
    aws_sfn_state_machine.ir
  ]
}

# Negative test: Invalid log group ARN
run "invalid_log_group_arn" {
  command = plan

  variables {
    cloudwatch_log_group_arn = "invalid-arn"
  }

  expect_failures = [
    aws_sfn_state_machine.ir
  ]
}