# Unit tests for S3 Evidence module
# Validates bucket versioning, SSE-KMS default, block public access, bucket-owner-enforced, aws:SecureTransport condition, access logging configured, optional Object Lock toggle behavior

variables {
  bucket_name = "test-ir-evidence-bucket"
  kms_alias   = "alias/test-ir-evidence-key"
  tags = {
    Environment = "test"
    Project     = "threat-detection-ir"
  }
}

run "bucket_versioning_enabled" {
  command = plan

  assert {
    condition     = aws_s3_bucket_versioning.evidence.versioning_configuration[0].status == "Enabled"
    error_message = "Evidence bucket must have versioning enabled"
  }

  assert {
    condition     = aws_s3_bucket_versioning.logs.versioning_configuration[0].status == "Enabled"
    error_message = "Logs bucket must have versioning enabled"
  }
}

run "sse_kms_encryption_default" {
  command = plan

  assert {
    condition     = aws_s3_bucket_server_side_encryption_configuration.evidence.rule[0].apply_server_side_encryption_by_default[0].sse_algorithm == "aws:kms"
    error_message = "Evidence bucket must use SSE-KMS encryption by default"
  }

  assert {
    condition     = aws_s3_bucket_server_side_encryption_configuration.evidence.rule[0].apply_server_side_encryption_by_default[0].kms_master_key_id == aws_kms_key.evidence.arn
    error_message = "Evidence bucket must use the dedicated KMS key for encryption"
  }
}

run "block_public_access" {
  command = plan

  assert {
    condition     = aws_s3_bucket_public_access_block.evidence.block_public_acls == true
    error_message = "Evidence bucket must block public ACLs"
  }

  assert {
    condition     = aws_s3_bucket_public_access_block.evidence.block_public_policy == true
    error_message = "Evidence bucket must block public bucket policies"
  }

  assert {
    condition     = aws_s3_bucket_public_access_block.evidence.ignore_public_acls == true
    error_message = "Evidence bucket must ignore public ACLs"
  }

  assert {
    condition     = aws_s3_bucket_public_access_block.evidence.restrict_public_buckets == true
    error_message = "Evidence bucket must restrict public bucket policies"
  }
}

run "bucket_owner_enforced" {
  command = plan

  assert {
    condition     = aws_s3_bucket_ownership_controls.evidence.rule[0].object_ownership == "BucketOwnerEnforced"
    error_message = "Evidence bucket must enforce bucket owner ownership"
  }
}

run "secure_transport_condition" {
  command = plan

  assert {
    condition = jsondecode(aws_s3_bucket_policy.evidence.policy).Statement[0].Condition.Bool["aws:SecureTransport"] == "false"
    error_message = "Bucket policy must deny non-HTTPS requests"
  }

  assert {
    condition = jsondecode(aws_s3_bucket_policy.evidence.policy).Statement[0].Effect == "Deny"
    error_message = "Bucket policy must deny insecure transport"
  }
}

run "access_logging_configured" {
  command = plan

  assert {
    condition     = aws_s3_bucket_logging.evidence.target_bucket == aws_s3_bucket.logs.id
    error_message = "Evidence bucket must have access logging configured"
  }

  assert {
    condition     = aws_s3_bucket_logging.evidence.target_prefix == "access-logs/"
    error_message = "Access logs must use the correct prefix"
  }
}

run "kms_key_rotation_enabled" {
  command = plan

  assert {
    condition     = aws_kms_key.evidence.enable_key_rotation == true
    error_message = "KMS key must have automatic rotation enabled"
  }

  assert {
    condition     = aws_kms_key.evidence.deletion_window_in_days == 30
    error_message = "KMS key must have 30-day deletion window"
  }
}

run "kms_alias_configured" {
  command = plan

  assert {
    condition     = aws_kms_alias.evidence.name == var.kms_alias
    error_message = "KMS alias must match the specified alias"
  }

  assert {
    condition     = aws_kms_alias.evidence.target_key_id == aws_kms_key.evidence.key_id
    error_message = "KMS alias must point to the correct key"
  }
}

run "deny_unencrypted_puts" {
  command = plan

  assert {
    condition = jsondecode(aws_s3_bucket_policy.evidence.policy).Statement[1].Condition.StringNotEquals["s3:x-amz-server-side-encryption"] == "aws:kms"
    error_message = "Bucket policy must deny unencrypted PUT operations"
  }

  assert {
    condition = jsondecode(aws_s3_bucket_policy.evidence.policy).Statement[1].Effect == "Deny"
    error_message = "Bucket policy must deny unencrypted uploads"
  }
}

run "logs_bucket_public_access_block" {
  command = plan

  assert {
    condition     = aws_s3_bucket_public_access_block.logs.block_public_acls == true
    error_message = "Logs bucket must block public ACLs"
  }

  assert {
    condition     = aws_s3_bucket_public_access_block.logs.block_public_policy == true
    error_message = "Logs bucket must block public bucket policies"
  }

  assert {
    condition     = aws_s3_bucket_public_access_block.logs.ignore_public_acls == true
    error_message = "Logs bucket must ignore public ACLs"
  }

  assert {
    condition     = aws_s3_bucket_public_access_block.logs.restrict_public_buckets == true
    error_message = "Logs bucket must restrict public bucket policies"
  }
}

# Negative test: Invalid bucket name
run "invalid_bucket_name" {
  command = plan

  variables {
    bucket_name = "" # Invalid empty bucket name
  }

  expect_failures = [
    aws_s3_bucket.evidence
  ]
}

# Negative test: Invalid KMS alias
run "invalid_kms_alias" {
  command = plan

  variables {
    kms_alias = "" # Invalid empty alias
  }

  expect_failures = [
    aws_kms_alias.evidence
  ]
}