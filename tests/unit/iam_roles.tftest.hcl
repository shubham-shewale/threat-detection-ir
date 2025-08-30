# Unit tests for IAM Roles module
# Validates no wildcard actions/resources unless annotated as justified; require condition keys (e.g., aws:ResourceTag) where scoping is possible

variables {
  tags = {
    Environment = "test"
    Project     = "threat-detection-ir"
  }
}

run "lambda_role_assume_policy" {
  command = plan

  assert {
    condition     = aws_iam_role.lambda_triage.assume_role_policy != null
    error_message = "Lambda triage role must have assume role policy"
  }

  assert {
    condition = strcontains(aws_iam_role.lambda_triage.assume_role_policy, "lambda.amazonaws.com")
    error_message = "Lambda triage role must allow Lambda service to assume it"
  }
}

run "stepfn_role_assume_policy" {
  command = plan

  assert {
    condition     = aws_iam_role.stepfn_ir.assume_role_policy != null
    error_message = "Step Functions role must have assume role policy"
  }

  assert {
    condition = strcontains(aws_iam_role.stepfn_ir.assume_role_policy, "states.amazonaws.com")
    error_message = "Step Functions role must allow Step Functions service to assume it"
  }
}

run "lambda_policy_no_wildcard_resources" {
  command = plan

  # Check that S3 resources are specific ARNs, not wildcards
  assert {
    condition = strcontains(aws_iam_policy.lambda_triage.policy, "arn:aws:s3:::ir-evidence-bucket")
    error_message = "Lambda policy must use specific S3 bucket ARN, not wildcard"
  }

  assert {
    condition = !strcontains(aws_iam_policy.lambda_triage.policy, "arn:aws:s3:::*")
    error_message = "Lambda policy must not use wildcard S3 resources"
  }

  # Check that SNS resources are specific ARNs, not wildcards
  assert {
    condition = strcontains(aws_iam_policy.lambda_triage.policy, "arn:aws:sns:")
    error_message = "Lambda policy must specify SNS topic ARN"
  }

  assert {
    condition = !strcontains(aws_iam_policy.lambda_triage.policy, "arn:aws:sns::*")
    error_message = "Lambda policy must not use wildcard SNS resources"
  }
}

run "stepfn_policy_no_wildcard_resources" {
  command = plan

  # Check that S3 resources are specific ARNs, not wildcards
  assert {
    condition = strcontains(aws_iam_policy.stepfn_ir.policy, "arn:aws:s3:::ir-evidence-bucket")
    error_message = "Step Functions policy must use specific S3 bucket ARN, not wildcard"
  }

  assert {
    condition = !strcontains(aws_iam_policy.stepfn_ir.policy, "arn:aws:s3:::*")
    error_message = "Step Functions policy must not use wildcard S3 resources"
  }

  # Check that Lambda resources are specific ARNs, not wildcards
  assert {
    condition = strcontains(aws_iam_policy.stepfn_ir.policy, "arn:aws:lambda:")
    error_message = "Step Functions policy must specify Lambda function ARN"
  }

  assert {
    condition = !strcontains(aws_iam_policy.stepfn_ir.policy, "arn:aws:lambda::*")
    error_message = "Step Functions policy must not use wildcard Lambda resources"
  }
}

run "lambda_policy_condition_keys" {
  command = plan

  # Check for condition keys where applicable
  assert {
    condition = strcontains(aws_iam_policy.lambda_triage.policy, "aws:SecureTransport")
    error_message = "Lambda policy must include aws:SecureTransport condition for S3 access"
  }

  assert {
    condition = strcontains(aws_iam_policy.lambda_triage.policy, "StringEquals")
    error_message = "Lambda policy must include condition keys for proper scoping"
  }
}

run "stepfn_policy_condition_keys" {
  command = plan

  # Check for condition keys where applicable
  assert {
    condition = strcontains(aws_iam_policy.stepfn_ir.policy, "aws:SecureTransport")
    error_message = "Step Functions policy must include aws:SecureTransport condition for S3 access"
  }
}

run "lambda_policy_least_privilege_s3" {
  command = plan

  # Verify only necessary S3 actions are allowed
  assert {
    condition = strcontains(aws_iam_policy.lambda_triage.policy, "s3:GetObject")
    error_message = "Lambda policy must allow GetObject for evidence retrieval"
  }

  assert {
    condition = strcontains(aws_iam_policy.lambda_triage.policy, "s3:PutObject")
    error_message = "Lambda policy must allow PutObject for evidence storage"
  }

  assert {
    condition = strcontains(aws_iam_policy.lambda_triage.policy, "s3:PutObjectAcl")
    error_message = "Lambda policy must allow PutObjectAcl for evidence management"
  }

  # Verify no excessive permissions
  assert {
    condition = !strcontains(aws_iam_policy.lambda_triage.policy, "s3:DeleteObject")
    error_message = "Lambda policy should not allow DeleteObject (not needed for triage)"
  }

  assert {
    condition = !strcontains(aws_iam_policy.lambda_triage.policy, "s3:DeleteBucket")
    error_message = "Lambda policy should not allow DeleteBucket (not needed for triage)"
  }
}

run "stepfn_policy_least_privilege_s3" {
  command = plan

  # Verify only necessary S3 actions are allowed
  assert {
    condition = strcontains(aws_iam_policy.stepfn_ir.policy, "s3:GetObject")
    error_message = "Step Functions policy must allow GetObject for evidence retrieval"
  }

  assert {
    condition = strcontains(aws_iam_policy.stepfn_ir.policy, "s3:PutObject")
    error_message = "Step Functions policy must allow PutObject for evidence storage"
  }

  assert {
    condition = strcontains(aws_iam_policy.stepfn_ir.policy, "s3:PutObjectAcl")
    error_message = "Step Functions policy must allow PutObjectAcl for evidence management"
  }

  # Verify no excessive permissions
  assert {
    condition = !strcontains(aws_iam_policy.stepfn_ir.policy, "s3:DeleteObject")
    error_message = "Step Functions policy should not allow DeleteObject (not needed for remediation)"
  }

  assert {
    condition = !strcontains(aws_iam_policy.stepfn_ir.policy, "s3:DeleteBucket")
    error_message = "Step Functions policy should not allow DeleteBucket (not needed for remediation)"
  }
}

run "lambda_policy_ec2_least_privilege" {
  command = plan

  # Verify only necessary EC2 actions are allowed
  assert {
    condition = strcontains(aws_iam_policy.lambda_triage.policy, "ec2:CreateTags")
    error_message = "Lambda policy must allow CreateTags for resource tagging"
  }

  assert {
    condition = strcontains(aws_iam_policy.lambda_triage.policy, "ec2:DeleteTags")
    error_message = "Lambda policy must allow DeleteTags for resource management"
  }

  assert {
    condition = strcontains(aws_iam_policy.lambda_triage.policy, "ec2:DescribeInstances")
    error_message = "Lambda policy must allow DescribeInstances for resource identification"
  }

  assert {
    condition = strcontains(aws_iam_policy.lambda_triage.policy, "ec2:DescribeSecurityGroups")
    error_message = "Lambda policy must allow DescribeSecurityGroups for quarantine operations"
  }

  assert {
    condition = strcontains(aws_iam_policy.lambda_triage.policy, "ec2:DescribeNetworkInterfaces")
    error_message = "Lambda policy must allow DescribeNetworkInterfaces for network analysis"
  }

  assert {
    condition = strcontains(aws_iam_policy.lambda_triage.policy, "ec2:ModifyNetworkInterface")
    error_message = "Lambda policy must allow ModifyNetworkInterface for quarantine operations"
  }
}

run "stepfn_policy_ec2_least_privilege" {
  command = plan

  # Verify only necessary EC2 actions are allowed
  assert {
    condition = strcontains(aws_iam_policy.stepfn_ir.policy, "ec2:CreateTags")
    error_message = "Step Functions policy must allow CreateTags for resource tagging"
  }

  assert {
    condition = strcontains(aws_iam_policy.stepfn_ir.policy, "ec2:DeleteTags")
    error_message = "Step Functions policy must allow DeleteTags for resource management"
  }

  assert {
    condition = strcontains(aws_iam_policy.stepfn_ir.policy, "ec2:DescribeInstances")
    error_message = "Step Functions policy must allow DescribeInstances for resource identification"
  }

  assert {
    condition = strcontains(aws_iam_policy.stepfn_ir.policy, "ec2:DescribeSecurityGroups")
    error_message = "Step Functions policy must allow DescribeSecurityGroups for quarantine operations"
  }

  assert {
    condition = strcontains(aws_iam_policy.stepfn_ir.policy, "ec2:DescribeNetworkInterfaces")
    error_message = "Step Functions policy must allow DescribeNetworkInterfaces for network analysis"
  }

  assert {
    condition = strcontains(aws_iam_policy.stepfn_ir.policy, "ec2:ModifyNetworkInterface")
    error_message = "Step Functions policy must allow ModifyNetworkInterface for quarantine operations"
  }
}

run "lambda_policy_stepfn_least_privilege" {
  command = plan

  # Verify only necessary Step Functions actions are allowed
  assert {
    condition = strcontains(aws_iam_policy.lambda_triage.policy, "states:StartExecution")
    error_message = "Lambda policy must allow StartExecution for triggering remediation"
  }

  assert {
    condition = strcontains(aws_iam_policy.lambda_triage.policy, "states:DescribeExecution")
    error_message = "Lambda policy must allow DescribeExecution for monitoring"
  }

  # Verify no excessive permissions
  assert {
    condition = !strcontains(aws_iam_policy.lambda_triage.policy, "states:StopExecution")
    error_message = "Lambda policy should not allow StopExecution (not needed for triage)"
  }

  assert {
    condition = !strcontains(aws_iam_policy.lambda_triage.policy, "states:DeleteStateMachine")
    error_message = "Lambda policy should not allow DeleteStateMachine (not needed for triage)"
  }
}

run "stepfn_policy_lambda_least_privilege" {
  command = plan

  # Verify only necessary Lambda actions are allowed
  assert {
    condition = strcontains(aws_iam_policy.stepfn_ir.policy, "lambda:InvokeFunction")
    error_message = "Step Functions policy must allow InvokeFunction for remediation actions"
  }

  assert {
    condition = strcontains(aws_iam_policy.stepfn_ir.policy, "lambda:GetFunction")
    error_message = "Step Functions policy must allow GetFunction for function validation"
  }

  # Verify no excessive permissions
  assert {
    condition = !strcontains(aws_iam_policy.stepfn_ir.policy, "lambda:CreateFunction")
    error_message = "Step Functions policy should not allow CreateFunction (not needed for remediation)"
  }

  assert {
    condition = !strcontains(aws_iam_policy.stepfn_ir.policy, "lambda:DeleteFunction")
    error_message = "Step Functions policy should not allow DeleteFunction (not needed for remediation)"
  }
}

run "lambda_policy_sns_least_privilege" {
  command = plan

  # Verify only necessary SNS actions are allowed
  assert {
    condition = strcontains(aws_iam_policy.lambda_triage.policy, "sns:Publish")
    error_message = "Lambda policy must allow Publish for sending notifications"
  }

  assert {
    condition = strcontains(aws_iam_policy.lambda_triage.policy, "sns:GetTopicAttributes")
    error_message = "Lambda policy must allow GetTopicAttributes for topic validation"
  }

  # Verify no excessive permissions
  assert {
    condition = !strcontains(aws_iam_policy.lambda_triage.policy, "sns:Subscribe")
    error_message = "Lambda policy should not allow Subscribe (not needed for triage)"
  }

  assert {
    condition = !strcontains(aws_iam_policy.lambda_triage.policy, "sns:DeleteTopic")
    error_message = "Lambda policy should not allow DeleteTopic (not needed for triage)"
  }
}

run "stepfn_policy_sns_least_privilege" {
  command = plan

  # Verify only necessary SNS actions are allowed
  assert {
    condition = strcontains(aws_iam_policy.stepfn_ir.policy, "sns:Publish")
    error_message = "Step Functions policy must allow Publish for sending notifications"
  }

  assert {
    condition = strcontains(aws_iam_policy.stepfn_ir.policy, "sns:GetTopicAttributes")
    error_message = "Step Functions policy must allow GetTopicAttributes for topic validation"
  }

  # Verify no excessive permissions
  assert {
    condition = !strcontains(aws_iam_policy.stepfn_ir.policy, "sns:Subscribe")
    error_message = "Step Functions policy should not allow Subscribe (not needed for remediation)"
  }

  assert {
    condition = !strcontains(aws_iam_policy.stepfn_ir.policy, "sns:DeleteTopic")
    error_message = "Step Functions policy should not allow DeleteTopic (not needed for remediation)"
  }
}

run "lambda_policy_securityhub_least_privilege" {
  command = plan

  # Verify only necessary Security Hub actions are allowed
  assert {
    condition = strcontains(aws_iam_policy.lambda_triage.policy, "securityhub:BatchUpdateFindings")
    error_message = "Lambda policy must allow BatchUpdateFindings for finding updates"
  }

  assert {
    condition = strcontains(aws_iam_policy.lambda_triage.policy, "securityhub:DescribeFindings")
    error_message = "Lambda policy must allow DescribeFindings for finding retrieval"
  }

  # Verify no excessive permissions
  assert {
    condition = !strcontains(aws_iam_policy.lambda_triage.policy, "securityhub:DeleteFindings")
    error_message = "Lambda policy should not allow DeleteFindings (not needed for triage)"
  }

  assert {
    condition = !strcontains(aws_iam_policy.lambda_triage.policy, "securityhub:CreateFindings")
    error_message = "Lambda policy should not allow CreateFindings (not needed for triage)"
  }
}

run "stepfn_policy_securityhub_least_privilege" {
  command = plan

  # Verify only necessary Security Hub actions are allowed
  assert {
    condition = strcontains(aws_iam_policy.stepfn_ir.policy, "securityhub:BatchUpdateFindings")
    error_message = "Step Functions policy must allow BatchUpdateFindings for finding updates"
  }

  assert {
    condition = strcontains(aws_iam_policy.stepfn_ir.policy, "securityhub:DescribeFindings")
    error_message = "Step Functions policy must allow DescribeFindings for finding retrieval"
  }

  # Verify no excessive permissions
  assert {
    condition = !strcontains(aws_iam_policy.stepfn_ir.policy, "securityhub:DeleteFindings")
    error_message = "Step Functions policy should not allow DeleteFindings (not needed for remediation)"
  }

  assert {
    condition = !strcontains(aws_iam_policy.stepfn_ir.policy, "securityhub:CreateFindings")
    error_message = "Step Functions policy should not allow CreateFindings (not needed for remediation)"
  }
}

run "lambda_policy_cloudwatch_least_privilege" {
  command = plan

  # Verify only necessary CloudWatch actions are allowed
  assert {
    condition = strcontains(aws_iam_policy.lambda_triage.policy, "logs:CreateLogGroup")
    error_message = "Lambda policy must allow CreateLogGroup for log group creation"
  }

  assert {
    condition = strcontains(aws_iam_policy.lambda_triage.policy, "logs:CreateLogStream")
    error_message = "Lambda policy must allow CreateLogStream for log stream creation"
  }

  assert {
    condition = strcontains(aws_iam_policy.lambda_triage.policy, "logs:PutLogEvents")
    error_message = "Lambda policy must allow PutLogEvents for logging"
  }

  assert {
    condition = strcontains(aws_iam_policy.lambda_triage.policy, "logs:DescribeLogGroups")
    error_message = "Lambda policy must allow DescribeLogGroups for log group validation"
  }

  # Verify no excessive permissions
  assert {
    condition = !strcontains(aws_iam_policy.lambda_triage.policy, "logs:DeleteLogGroup")
    error_message = "Lambda policy should not allow DeleteLogGroup (not needed for triage)"
  }

  assert {
    condition = !strcontains(aws_iam_policy.lambda_triage.policy, "logs:DeleteLogStream")
    error_message = "Lambda policy should not allow DeleteLogStream (not needed for triage)"
  }
}

run "stepfn_policy_cloudwatch_least_privilege" {
  command = plan

  # Verify only necessary CloudWatch actions are allowed
  assert {
    condition = strcontains(aws_iam_policy.stepfn_ir.policy, "logs:CreateLogGroup")
    error_message = "Step Functions policy must allow CreateLogGroup for log group creation"
  }

  assert {
    condition = strcontains(aws_iam_policy.stepfn_ir.policy, "logs:CreateLogStream")
    error_message = "Step Functions policy must allow CreateLogStream for log stream creation"
  }

  assert {
    condition = strcontains(aws_iam_policy.stepfn_ir.policy, "logs:PutLogEvents")
    error_message = "Step Functions policy must allow PutLogEvents for logging"
  }

  assert {
    condition = strcontains(aws_iam_policy.stepfn_ir.policy, "logs:DescribeLogGroups")
    error_message = "Step Functions policy must allow DescribeLogGroups for log group validation"
  }

  # Verify no excessive permissions
  assert {
    condition = !strcontains(aws_iam_policy.stepfn_ir.policy, "logs:DeleteLogGroup")
    error_message = "Step Functions policy should not allow DeleteLogGroup (not needed for remediation)"
  }

  assert {
    condition = !strcontains(aws_iam_policy.stepfn_ir.policy, "logs:DeleteLogStream")
    error_message = "Step Functions policy should not allow DeleteLogStream (not needed for remediation)"
  }
}

run "lambda_policy_xray_enabled" {
  command = plan

  # Verify X-Ray permissions are included
  assert {
    condition = strcontains(aws_iam_policy.lambda_triage.policy, "xray:PutTraceSegments")
    error_message = "Lambda policy must allow PutTraceSegments for X-Ray tracing"
  }

  assert {
    condition = strcontains(aws_iam_policy.lambda_triage.policy, "xray:PutTelemetryRecords")
    error_message = "Lambda policy must allow PutTelemetryRecords for X-Ray telemetry"
  }
}

run "policies_attached_correctly" {
  command = plan

  # Verify policies are attached to correct roles
  assert {
    condition     = aws_iam_role_policy_attachment.lambda_triage.role == aws_iam_role.lambda_triage.name
    error_message = "Lambda triage policy must be attached to lambda triage role"
  }

  assert {
    condition     = aws_iam_role_policy_attachment.lambda_triage.policy_arn == aws_iam_policy.lambda_triage.arn
    error_message = "Lambda triage policy ARN must match the created policy"
  }

  assert {
    condition     = aws_iam_role_policy_attachment.stepfn_ir.role == aws_iam_role.stepfn_ir.name
    error_message = "Step Functions policy must be attached to stepfn ir role"
  }

  assert {
    condition     = aws_iam_role_policy_attachment.stepfn_ir.policy_arn == aws_iam_policy.stepfn_ir.arn
    error_message = "Step Functions policy ARN must match the created policy"
  }
}

# Negative test: Attempt to use wildcard resources (should fail validation)
run "no_wildcard_resources_allowed" {
  command = plan

  # This test verifies that our policy doesn't contain wildcards
  # If wildcards are found, the test should fail as per security requirements
  assert {
    condition = !strcontains(aws_iam_policy.lambda_triage.policy, "\"Resource\": \"*\"")
    error_message = "Lambda policy must not contain wildcard resources"
  }

  assert {
    condition = !strcontains(aws_iam_policy.stepfn_ir.policy, "\"Resource\": \"*\"")
    error_message = "Step Functions policy must not contain wildcard resources"
  }
}