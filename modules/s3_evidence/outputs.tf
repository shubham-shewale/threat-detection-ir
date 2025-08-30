output "bucket_name" {
  description = "Name of the S3 evidence bucket"
  value       = aws_s3_bucket.evidence.bucket
}

output "kms_key_arn" {
  description = "ARN of the KMS key for S3 encryption"
  value       = aws_kms_key.evidence.arn
}