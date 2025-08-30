# Unit tests for EventBridge module
# Validates event pattern JSON for GuardDuty finding severities and specific types; assert dead-letter queue wiring and retry policy on targets

variables {
  lambda_function_arn        = "arn:aws:lambda:us-east-1:123456789012:function:guardduty-triage"
  state_machine_arn          = "arn:aws:states:us-east-1:123456789012:stateMachine:guardduty-ir"
  finding_severity_threshold = "HIGH"
  tags = {
    Environment = "test"
    Project     = "threat-detection-ir"
  }
}

run "eventbridge_rule_created" {
  command = plan

  assert {
    condition     = aws_cloudwatch_event_rule.guardduty_finding.name == "guardduty-finding-rule"
    error_message = "EventBridge rule must be created with correct name"
  }

  assert {
    condition     = aws_cloudwatch_event_rule.guardduty_finding.description == "Rule for GuardDuty finding events"
    error_message = "EventBridge rule must have proper description"
  }
}

run "event_pattern_high_severity" {
  command = plan

  assert {
    condition = strcontains(aws_cloudwatch_event_rule.guardduty_finding.event_pattern, "HIGH")
    error_message = "Event pattern must include HIGH severity findings"
  }

  assert {
    condition = strcontains(aws_cloudwatch_event_rule.guardduty_finding.event_pattern, "CRITICAL")
    error_message = "Event pattern must include CRITICAL severity findings"
  }
}

run "event_pattern_guardduty_source" {
  command = plan

  assert {
    condition = strcontains(aws_cloudwatch_event_rule.guardduty_finding.event_pattern, "aws.guardduty")
    error_message = "Event pattern must match GuardDuty source"
  }

  assert {
    condition = strcontains(aws_cloudwatch_event_rule.guardduty_finding.event_pattern, "GuardDuty Finding")
    error_message = "Event pattern must match GuardDuty finding detail-type"
  }
}

run "lambda_target_configured" {
  command = plan

  assert {
    condition     = aws_cloudwatch_event_target.lambda_target.rule == aws_cloudwatch_event_rule.guardduty_finding.name
    error_message = "Lambda target must be attached to the GuardDuty rule"
  }

  assert {
    condition     = aws_cloudwatch_event_target.lambda_target.arn == var.lambda_function_arn
    error_message = "Lambda target must use the correct function ARN"
  }
}

run "stepfn_target_configured" {
  command = plan

  assert {
    condition     = aws_cloudwatch_event_target.stepfn_target.rule == aws_cloudwatch_event_rule.guardduty_finding.name
    error_message = "Step Functions target must be attached to the GuardDuty rule"
  }

  assert {
    condition     = aws_cloudwatch_event_target.stepfn_target.arn == var.state_machine_arn
    error_message = "Step Functions target must use the correct state machine ARN"
  }
}

run "lambda_target_retry_policy" {
  command = plan

  assert {
    condition     = aws_cloudwatch_event_target.lambda_target.retry_policy[0].maximum_retry_attempts == 3
    error_message = "Lambda target must have 3 maximum retry attempts"
  }

  assert {
    condition     = aws_cloudwatch_event_target.lambda_target.retry_policy[0].maximum_event_age_in_seconds == 3600
    error_message = "Lambda target must have 1 hour maximum event age"
  }
}

run "stepfn_target_retry_policy" {
  command = plan

  assert {
    condition     = aws_cloudwatch_event_target.stepfn_target.retry_policy[0].maximum_retry_attempts == 2
    error_message = "Step Functions target must have 2 maximum retry attempts"
  }

  assert {
    condition     = aws_cloudwatch_event_target.stepfn_target.retry_policy[0].maximum_event_age_in_seconds == 3600
    error_message = "Step Functions target must have 1 hour maximum event age"
  }
}

run "dead_letter_queue_configured" {
  command = plan

  assert {
    condition     = aws_cloudwatch_event_target.lambda_target.dead_letter_config[0].arn != null
    error_message = "Lambda target must have dead letter queue configured"
  }

  assert {
    condition     = aws_cloudwatch_event_target.stepfn_target.dead_letter_config[0].arn != null
    error_message = "Step Functions target must have dead letter queue configured"
  }
}

run "sqs_dlq_encrypted" {
  command = plan

  assert {
    condition     = aws_sqs_queue.dlq.sqs_managed_sse_enabled == true
    error_message = "Dead letter queue must have server-side encryption enabled"
  }
}

run "sqs_dlq_policy_configured" {
  command = plan

  assert {
    condition     = aws_sqs_queue_policy.dlq_policy.queue_url == aws_sqs_queue.dlq.url
    error_message = "DLQ policy must be attached to the correct queue"
  }

  assert {
    condition = strcontains(aws_sqs_queue_policy.dlq_policy.policy, "events.amazonaws.com")
    error_message = "DLQ policy must allow EventBridge to send messages"
  }
}

run "lambda_target_permissions" {
  command = plan

  assert {
    condition     = aws_lambda_permission.allow_eventbridge.function_name == "guardduty-triage"
    error_message = "Lambda permission must be for the correct function"
  }

  assert {
    condition     = aws_lambda_permission.allow_eventbridge.principal == "events.amazonaws.com"
    error_message = "Lambda permission must allow EventBridge principal"
  }

  assert {
    condition     = aws_lambda_permission.allow_eventbridge.action == "lambda:InvokeFunction"
    error_message = "Lambda permission must allow InvokeFunction action"
  }
}

run "stepfn_target_permissions" {
  command = plan

  assert {
    condition     = aws_iam_role_policy_attachment.stepfn_eventbridge.role == "guardduty-ir-role"
    error_message = "Step Functions must have EventBridge permissions"
  }

  assert {
    condition = strcontains(aws_iam_policy.stepfn_eventbridge.policy, "states:StartExecution")
    error_message = "Step Functions EventBridge policy must allow StartExecution"
  }
}

run "severity_threshold_filtering" {
  command = plan

  # Test HIGH threshold (should include HIGH and CRITICAL)
  assert {
    condition = strcontains(aws_cloudwatch_event_rule.guardduty_finding.event_pattern, "HIGH")
    error_message = "HIGH threshold must include HIGH severity"
  }

  assert {
    condition = strcontains(aws_cloudwatch_event_rule.guardduty_finding.event_pattern, "CRITICAL")
    error_message = "HIGH threshold must include CRITICAL severity"
  }

  assert {
    condition = !strcontains(aws_cloudwatch_event_rule.guardduty_finding.event_pattern, "MEDIUM")
    error_message = "HIGH threshold must exclude MEDIUM severity"
  }

  assert {
    condition = !strcontains(aws_cloudwatch_event_rule.guardduty_finding.event_pattern, "LOW")
    error_message = "HIGH threshold must exclude LOW severity"
  }
}

# Negative test: Invalid severity threshold
run "invalid_severity_threshold" {
  command = plan

  variables {
    finding_severity_threshold = "INVALID"
  }

  expect_failures = [
    aws_cloudwatch_event_rule.guardduty_finding
  ]
}

# Negative test: Empty lambda function ARN
run "empty_lambda_arn" {
  command = plan

  variables {
    lambda_function_arn = ""
  }

  expect_failures = [
    aws_cloudwatch_event_target.lambda_target
  ]
}

# Negative test: Empty state machine ARN
run "empty_state_machine_arn" {
  command = plan

  variables {
    state_machine_arn = ""
  }

  expect_failures = [
    aws_cloudwatch_event_target.stepfn_target
  ]
}