# Unit tests for SNS Alerts module
# Validates KMS master key set, enforce encryption-required policy, topic policy restricts publishing to allowed principals, subscriptions configurable

variables {
  subscriptions = [
    {
      protocol = "email"
      endpoint = "security@company.com"
    },
    {
      protocol = "https"
      endpoint = "https://webhook.company.com/alerts"
    }
  ]
  tags = {
    Environment = "test"
    Project     = "threat-detection-ir"
  }
}

run "topic_encryption_enabled" {
  command = plan

  assert {
    condition     = aws_sns_topic.alerts.server_side_encryption[0].enabled == true
    error_message = "SNS topic must have server-side encryption enabled"
  }

  assert {
    condition     = aws_sns_topic.alerts.server_side_encryption[0].encryption_key_type == "KMS"
    error_message = "SNS topic must use KMS encryption"
  }
}

run "kms_master_key_configured" {
  command = plan

  assert {
    condition     = aws_sns_topic.alerts.server_side_encryption[0].kms_master_key_id == aws_kms_key.alerts.arn
    error_message = "SNS topic must use the dedicated KMS key"
  }
}

run "topic_policy_restricts_publishers" {
  command = plan

  assert {
    condition = strcontains(aws_sns_topic_policy.alerts.policy, "Allow")
    error_message = "Topic policy must allow publishing from authorized principals"
  }

  assert {
    condition = strcontains(aws_sns_topic_policy.alerts.policy, "lambda-triage-role")
    error_message = "Topic policy must allow Lambda triage role to publish"
  }

  assert {
    condition = strcontains(aws_sns_topic_policy.alerts.policy, "stepfn-ir-role")
    error_message = "Topic policy must allow Step Functions role to publish"
  }
}

run "encryption_required_policy" {
  command = plan

  assert {
    condition = strcontains(aws_sns_topic_policy.alerts.policy, "Deny")
    error_message = "Topic policy must deny unencrypted publishes"
  }

  assert {
    condition = strcontains(aws_sns_topic_policy.alerts.policy, "aws:SecureTransport")
    error_message = "Topic policy must enforce secure transport"
  }
}

run "subscriptions_configured" {
  command = plan

  assert {
    condition     = length(aws_sns_topic_subscription.email) == 1
    error_message = "Email subscription must be configured"
  }

  assert {
    condition     = aws_sns_topic_subscription.email[0].protocol == "email"
    error_message = "Email subscription must use email protocol"
  }

  assert {
    condition     = aws_sns_topic_subscription.email[0].endpoint == "security@company.com"
    error_message = "Email subscription must use correct endpoint"
  }

  assert {
    condition     = length(aws_sns_topic_subscription.https) == 1
    error_message = "HTTPS subscription must be configured"
  }

  assert {
    condition     = aws_sns_topic_subscription.https[0].protocol == "https"
    error_message = "HTTPS subscription must use https protocol"
  }

  assert {
    condition     = aws_sns_topic_subscription.https[0].endpoint == "https://webhook.company.com/alerts"
    error_message = "HTTPS subscription must use correct endpoint"
  }
}

run "kms_key_rotation_enabled" {
  command = plan

  assert {
    condition     = aws_kms_key.alerts.enable_key_rotation == true
    error_message = "KMS key must have automatic rotation enabled"
  }

  assert {
    condition     = aws_kms_key.alerts.deletion_window_in_days == 30
    error_message = "KMS key must have 30-day deletion window"
  }
}

run "kms_alias_configured" {
  command = plan

  assert {
    condition     = aws_kms_alias.alerts.name == "alias/sns-alerts-key"
    error_message = "KMS alias must be correctly named"
  }

  assert {
    condition     = aws_kms_alias.alerts.target_key_id == aws_kms_key.alerts.key_id
    error_message = "KMS alias must point to the correct key"
  }
}

run "topic_delivery_policy_configured" {
  command = plan

  assert {
    condition     = aws_sns_topic.alerts.delivery_policy != null
    error_message = "SNS topic must have delivery policy configured"
  }
}

run "topic_display_name_set" {
  command = plan

  assert {
    condition     = aws_sns_topic.alerts.display_name == "IR-Alerts"
    error_message = "SNS topic must have display name set"
  }
}

# Negative test: Empty subscriptions
run "empty_subscriptions" {
  command = plan

  variables {
    subscriptions = []
  }

  assert {
    condition     = length(aws_sns_topic_subscription.email) == 0
    error_message = "No email subscriptions should be created when list is empty"
  }

  assert {
    condition     = length(aws_sns_topic_subscription.https) == 0
    error_message = "No HTTPS subscriptions should be created when list is empty"
  }
}

# Negative test: Invalid protocol
run "invalid_protocol" {
  command = plan

  variables {
    subscriptions = [
      {
        protocol = "invalid"
        endpoint = "test@example.com"
      }
    ]
  }

  expect_failures = [
    aws_sns_topic_subscription.email
  ]
}

# Negative test: Invalid endpoint format
run "invalid_endpoint" {
  command = plan

  variables {
    subscriptions = [
      {
        protocol = "email"
        endpoint = "invalid-email"
      }
    ]
  }

  expect_failures = [
    aws_sns_topic_subscription.email
  ]
}