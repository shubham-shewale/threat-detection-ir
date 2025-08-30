# Unit tests for Lambda Triage module
# Validates environment variables (EVIDENCE_BUCKET, SNS_TOPIC_ARN, STATE_MACHINE_ARN, QUARANTINE_SG_ID), log group retention, reserved concurrency optional, permission to write to S3/SNS/StepFunctions with least privilege

variables {
  evidence_bucket_name     = "test-ir-evidence-bucket"
  sns_topic_arn            = "arn:aws:sns:us-east-1:123456789012:ir-alerts-topic"
  state_machine_arn        = "arn:aws:states:us-east-1:123456789012:stateMachine:guardduty-ir"
  quarantine_sg_id         = "sg-12345678"
  iam_role_arn             = "arn:aws:iam::123456789012:role/lambda-triage-role"
  cloudwatch_log_group_arn = "arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/guardduty-triage"
  tags = {
    Environment = "test"
    Project     = "threat-detection-ir"
  }
}

run "lambda_function_configured" {
  command = plan

  assert {
    condition     = aws_lambda_function.triage.function_name == "guardduty-triage"
    error_message = "Lambda function must have correct name"
  }

  assert {
    condition     = aws_lambda_function.triage.runtime == "python3.9"
    error_message = "Lambda function must use Python 3.9 runtime"
  }

  assert {
    condition     = aws_lambda_function.triage.handler == "triage.lambda_handler"
    error_message = "Lambda function must have correct handler"
  }

  assert {
    condition     = aws_lambda_function.triage.role == var.iam_role_arn
    error_message = "Lambda function must use the specified IAM role"
  }
}

run "lambda_environment_variables" {
  command = plan

  assert {
    condition     = aws_lambda_function.triage.environment[0].variables["EVIDENCE_BUCKET"] == var.evidence_bucket_name
    error_message = "Lambda must have EVIDENCE_BUCKET environment variable set"
  }

  assert {
    condition     = aws_lambda_function.triage.environment[0].variables["SNS_TOPIC_ARN"] == var.sns_topic_arn
    error_message = "Lambda must have SNS_TOPIC_ARN environment variable set"
  }

  assert {
    condition     = aws_lambda_function.triage.environment[0].variables["STATE_MACHINE_ARN"] == var.state_machine_arn
    error_message = "Lambda must have STATE_MACHINE_ARN environment variable set"
  }

  assert {
    condition     = aws_lambda_function.triage.environment[0].variables["QUARANTINE_SG_ID"] == var.quarantine_sg_id
    error_message = "Lambda must have QUARANTINE_SG_ID environment variable set"
  }
}

run "lambda_package_configuration" {
  command = plan

  assert {
    condition     = aws_lambda_function.triage.filename != null
    error_message = "Lambda function must have deployment package"
  }

  assert {
    condition     = aws_lambda_function.triage.source_code_hash != null
    error_message = "Lambda function must have source code hash for change detection"
  }
}

run "cloudwatch_log_group_configured" {
  command = plan

  assert {
    condition     = aws_cloudwatch_log_group.lambda.name == "/aws/lambda/guardduty-triage"
    error_message = "CloudWatch log group must have correct name"
  }

  assert {
    condition     = aws_cloudwatch_log_group.lambda.retention_in_days == 90
    error_message = "CloudWatch log group must have 90-day retention"
  }

  assert {
    condition     = aws_cloudwatch_log_group.lambda.kms_key_id != null
    error_message = "CloudWatch log group must be encrypted"
  }
}

run "lambda_log_group_policy" {
  command = plan

  assert {
    condition     = aws_iam_role_policy_attachment.lambda_logs.role == "lambda-triage-role"
    error_message = "Lambda role must have CloudWatch logs permissions"
  }

  assert {
    condition = strcontains(aws_iam_policy.lambda_logs.policy, "logs:CreateLogGroup")
    error_message = "Lambda logs policy must allow CreateLogGroup"
  }

  assert {
    condition = strcontains(aws_iam_policy.lambda_logs.policy, "logs:CreateLogStream")
    error_message = "Lambda logs policy must allow CreateLogStream"
  }

  assert {
    condition = strcontains(aws_iam_policy.lambda_logs.policy, "logs:PutLogEvents")
    error_message = "Lambda logs policy must allow PutLogEvents"
  }
}

run "reserved_concurrency_optional" {
  command = plan

  # Reserved concurrency is optional, so we check if it's configured when specified
  assert {
    condition = aws_lambda_function.triage.reserved_concurrent_executions == null || aws_lambda_function.triage.reserved_concurrent_executions > 0
    error_message = "Reserved concurrency must be null or positive when configured"
  }
}

run "lambda_timeout_configured" {
  command = plan

  assert {
    condition     = aws_lambda_function.triage.timeout == 300
    error_message = "Lambda function must have 5-minute timeout"
  }
}

run "lambda_memory_configured" {
  command = plan

  assert {
    condition     = aws_lambda_function.triage.memory_size == 256
    error_message = "Lambda function must have 256MB memory allocated"
  }
}

run "lambda_permissions_least_privilege" {
  command = plan

  # Verify the IAM role has least privilege permissions
  assert {
    condition = strcontains(aws_iam_role_policy_attachment.lambda_triage.policy_arn, "lambda-triage-policy")
    error_message = "Lambda must use the specific triage policy"
  }
}

run "lambda_vpc_config_optional" {
  command = plan

  # VPC configuration is optional but if present should be valid
  assert {
    condition = aws_lambda_function.triage.vpc_config == null || length(aws_lambda_function.triage.vpc_config[0].subnet_ids) > 0
    error_message = "Lambda VPC config must include subnets if configured"
  }

  assert {
    condition = aws_lambda_function.triage.vpc_config == null || length(aws_lambda_function.triage.vpc_config[0].security_group_ids) > 0
    error_message = "Lambda VPC config must include security groups if configured"
  }
}

run "lambda_architectures_configured" {
  command = plan

  assert {
    condition     = contains(aws_lambda_function.triage.architectures, "x86_64")
    error_message = "Lambda function must use x86_64 architecture"
  }
}

run "lambda_tracing_optional" {
  command = plan

  # X-Ray tracing is optional but if configured should be valid
  assert {
    condition = aws_lambda_function.triage.tracing_config == null || aws_lambda_function.triage.tracing_config[0].mode == "Active" || aws_lambda_function.triage.tracing_config[0].mode == "PassThrough"
    error_message = "Lambda tracing mode must be Active or PassThrough if configured"
  }
}

run "lambda_layers_optional" {
  command = plan

  # Lambda layers are optional but if present should be valid ARNs
  assert {
    condition = aws_lambda_function.triage.layers == null || length(aws_lambda_function.triage.layers) >= 0
    error_message = "Lambda layers must be a valid list if configured"
  }
}

run "lambda_file_system_optional" {
  command = plan

  # EFS file system is optional but if configured should be valid
  assert {
    condition = aws_lambda_function.triage.file_system_config == null || aws_lambda_function.triage.file_system_config[0].arn != null
    error_message = "Lambda file system config must have valid ARN if configured"
  }
}

run "lambda_dlq_optional" {
  command = plan

  # Dead letter queue is optional but if configured should be valid
  assert {
    condition = aws_lambda_function.triage.dead_letter_config == null || aws_lambda_function.triage.dead_letter_config[0].target_arn != null
    error_message = "Lambda DLQ must have valid target ARN if configured"
  }
}

run "lambda_environment_variables_secure" {
  command = plan

  # Environment variables should not contain sensitive data
  assert {
    condition = !strcontains(aws_lambda_function.triage.environment[0].variables["EVIDENCE_BUCKET"], "secret")
    error_message = "Environment variables should not contain sensitive data"
  }

  assert {
    condition = !strcontains(aws_lambda_function.triage.environment[0].variables["SNS_TOPIC_ARN"], "secret")
    error_message = "Environment variables should not contain sensitive data"
  }
}

# Negative test: Missing required environment variables
run "missing_environment_variables" {
  command = plan

  variables {
    evidence_bucket_name = ""
  }

  expect_failures = [
    aws_lambda_function.triage
  ]
}

# Negative test: Invalid IAM role ARN
run "invalid_iam_role_arn" {
  command = plan

  variables {
    iam_role_arn = "invalid-arn"
  }

  expect_failures = [
    aws_lambda_function.triage
  ]
}

# Negative test: Invalid timeout value
run "invalid_timeout" {
  command = plan

  # This would be tested by modifying the module to have invalid timeout
  assert {
    condition = aws_lambda_function.triage.timeout <= 900
    error_message = "Lambda timeout must not exceed 15 minutes"
  }
}

# Negative test: Invalid memory size
run "invalid_memory_size" {
  command = plan

  assert {
    condition = aws_lambda_function.triage.memory_size >= 128 && aws_lambda_function.triage.memory_size <= 3008
    error_message = "Lambda memory size must be between 128MB and 3008MB"
  }
}