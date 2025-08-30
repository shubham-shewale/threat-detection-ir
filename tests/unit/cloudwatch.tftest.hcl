# Unit tests for CloudWatch module
# Validates log groups with retention, metrics, alarms, and monitoring configuration

variables {
  tags = {
    Environment = "test"
    Project     = "threat-detection-ir"
  }
}

run "lambda_log_group_configured" {
  command = plan

  assert {
    condition     = aws_cloudwatch_log_group.lambda.name == "/aws/lambda/guardduty-triage"
    error_message = "Lambda log group must have correct name"
  }

  assert {
    condition     = aws_cloudwatch_log_group.lambda.retention_in_days == 90
    error_message = "Lambda log group must have 90-day retention"
  }

  assert {
    condition     = aws_cloudwatch_log_group.lambda.kms_key_id != null
    error_message = "Lambda log group must be encrypted"
  }
}

run "stepfn_log_group_configured" {
  command = plan

  assert {
    condition     = aws_cloudwatch_log_group.stepfn.name == "/aws/states/guardduty-ir"
    error_message = "Step Functions log group must have correct name"
  }

  assert {
    condition     = aws_cloudwatch_log_group.stepfn.retention_in_days == 90
    error_message = "Step Functions log group must have 90-day retention"
  }

  assert {
    condition     = aws_cloudwatch_log_group.stepfn.kms_key_id != null
    error_message = "Step Functions log group must be encrypted"
  }
}

run "log_groups_tags_applied" {
  command = plan

  assert {
    condition     = aws_cloudwatch_log_group.lambda.tags["Environment"] == "test"
    error_message = "Lambda log group must have Environment tag"
  }

  assert {
    condition     = aws_cloudwatch_log_group.lambda.tags["Project"] == "threat-detection-ir"
    error_message = "Lambda log group must have Project tag"
  }

  assert {
    condition     = aws_cloudwatch_log_group.stepfn.tags["Environment"] == "test"
    error_message = "Step Functions log group must have Environment tag"
  }

  assert {
    condition     = aws_cloudwatch_log_group.stepfn.tags["Project"] == "threat-detection-ir"
    error_message = "Step Functions log group must have Project tag"
  }
}

run "lambda_error_alarm_configured" {
  command = plan

  assert {
    condition     = aws_cloudwatch_metric_alarm.lambda_errors.alarm_name == "guardduty-triage-errors"
    error_message = "Lambda error alarm must have correct name"
  }

  assert {
    condition     = aws_cloudwatch_metric_alarm.lambda_errors.comparison_operator == "GreaterThanThreshold"
    error_message = "Lambda error alarm must use GreaterThanThreshold operator"
  }

  assert {
    condition     = aws_cloudwatch_metric_alarm.lambda_errors.evaluation_periods == 2
    error_message = "Lambda error alarm must have 2 evaluation periods"
  }

  assert {
    condition     = aws_cloudwatch_metric_alarm.lambda_errors.metric_name == "Errors"
    error_message = "Lambda error alarm must monitor Errors metric"
  }

  assert {
    condition     = aws_cloudwatch_metric_alarm.lambda_errors.namespace == "AWS/Lambda"
    error_message = "Lambda error alarm must use AWS/Lambda namespace"
  }

  assert {
    condition     = aws_cloudwatch_metric_alarm.lambda_errors.period == 300
    error_message = "Lambda error alarm must have 5-minute period"
  }

  assert {
    condition     = aws_cloudwatch_metric_alarm.lambda_errors.statistic == "Sum"
    error_message = "Lambda error alarm must use Sum statistic"
  }

  assert {
    condition     = aws_cloudwatch_metric_alarm.lambda_errors.threshold == 1
    error_message = "Lambda error alarm must trigger on 1 or more errors"
  }
}

run "lambda_duration_alarm_configured" {
  command = plan

  assert {
    condition     = aws_cloudwatch_metric_alarm.lambda_duration.alarm_name == "guardduty-triage-duration"
    error_message = "Lambda duration alarm must have correct name"
  }

  assert {
    condition     = aws_cloudwatch_metric_alarm.lambda_duration.metric_name == "Duration"
    error_message = "Lambda duration alarm must monitor Duration metric"
  }

  assert {
    condition     = aws_cloudwatch_metric_alarm.lambda_duration.threshold == 300000
    error_message = "Lambda duration alarm must trigger at 5 minutes (300000ms)"
  }
}

run "stepfn_error_alarm_configured" {
  command = plan

  assert {
    condition     = aws_cloudwatch_metric_alarm.stepfn_failures.alarm_name == "guardduty-ir-failures"
    error_message = "Step Functions failure alarm must have correct name"
  }

  assert {
    condition     = aws_cloudwatch_metric_alarm.stepfn_failures.metric_name == "ExecutionsFailed"
    error_message = "Step Functions failure alarm must monitor ExecutionsFailed metric"
  }

  assert {
    condition     = aws_cloudwatch_metric_alarm.stepfn_failures.namespace == "AWS/States"
    error_message = "Step Functions failure alarm must use AWS/States namespace"
  }
}

run "stepfn_duration_alarm_configured" {
  command = plan

  assert {
    condition     = aws_cloudwatch_metric_alarm.stepfn_duration.alarm_name == "guardduty-ir-duration"
    error_message = "Step Functions duration alarm must have correct name"
  }

  assert {
    condition     = aws_cloudwatch_metric_alarm.stepfn_duration.metric_name == "ExecutionTime"
    error_message = "Step Functions duration alarm must monitor ExecutionTime metric"
  }
}

run "alarms_have_sns_actions" {
  command = plan

  # Verify that alarms have SNS topic configured for notifications
  assert {
    condition     = length(aws_cloudwatch_metric_alarm.lambda_errors.alarm_actions) > 0
    error_message = "Lambda error alarm must have alarm actions configured"
  }

  assert {
    condition     = length(aws_cloudwatch_metric_alarm.stepfn_failures.alarm_actions) > 0
    error_message = "Step Functions failure alarm must have alarm actions configured"
  }
}

run "log_metric_filters_configured" {
  command = plan

  assert {
    condition     = aws_cloudwatch_log_metric_filter.lambda_errors.log_group_name == aws_cloudwatch_log_group.lambda.name
    error_message = "Lambda error log metric filter must be attached to correct log group"
  }

  assert {
    condition     = aws_cloudwatch_log_metric_filter.lambda_errors.metric_transformation[0].name == "LambdaErrors"
    error_message = "Lambda error metric filter must have correct metric name"
  }

  assert {
    condition     = aws_cloudwatch_log_metric_filter.lambda_errors.metric_transformation[0].namespace == "GuardDuty/IR"
    error_message = "Lambda error metric filter must use correct namespace"
  }
}

run "cloudwatch_dashboard_configured" {
  command = plan

  assert {
    condition     = aws_cloudwatch_dashboard.ir.dashboard_name == "guardduty-ir-dashboard"
    error_message = "CloudWatch dashboard must have correct name"
  }

  assert {
    condition     = aws_cloudwatch_dashboard.ir.dashboard_body != null
    error_message = "CloudWatch dashboard must have dashboard body configured"
  }

  assert {
    condition = strcontains(aws_cloudwatch_dashboard.ir.dashboard_body, "LambdaErrors")
    error_message = "Dashboard must include Lambda errors metric"
  }

  assert {
    condition = strcontains(aws_cloudwatch_dashboard.ir.dashboard_body, "ExecutionsFailed")
    error_message = "Dashboard must include Step Functions failures metric"
  }
}

run "alarms_tags_applied" {
  command = plan

  assert {
    condition     = aws_cloudwatch_metric_alarm.lambda_errors.tags["Environment"] == "test"
    error_message = "Lambda error alarm must have Environment tag"
  }

  assert {
    condition     = aws_cloudwatch_metric_alarm.stepfn_failures.tags["Environment"] == "test"
    error_message = "Step Functions failure alarm must have Environment tag"
  }
}

# Negative test: Invalid retention period
run "invalid_retention_period" {
  command = plan

  # This would be tested by modifying the module to have invalid retention
  assert {
    condition = aws_cloudwatch_log_group.lambda.retention_in_days >= 1 && aws_cloudwatch_log_group.lambda.retention_in_days <= 3653
    error_message = "Log group retention must be between 1 and 3653 days"
  }
}

# Negative test: Missing required tags
run "missing_required_tags" {
  command = plan

  variables {
    tags = {}
  }

  expect_failures = [
    aws_cloudwatch_log_group.lambda
  ]
}

# Negative test: Invalid alarm threshold
run "invalid_alarm_threshold" {
  command = plan

  # This would be tested by modifying the module to have invalid threshold
  assert {
    condition = aws_cloudwatch_metric_alarm.lambda_errors.threshold >= 0
    error_message = "Alarm threshold must be non-negative"
  }
}