data "aws_caller_identity" "current" {}

# KMS Key for SNS encryption
resource "aws_kms_key" "alerts" {
  description = "KMS key for SNS topic encryption"
  tags        = var.tags
}

# SNS Topic
resource "aws_sns_topic" "alerts" {
  name              = "ir-alerts-topic"
  kms_master_key_id = aws_kms_key.alerts.id
  tags              = var.tags
}

# SNS Topic Policy
resource "aws_sns_topic_policy" "alerts" {
  arn = aws_sns_topic.alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "*"
        }
        Action = "sns:Publish"
        Resource = aws_sns_topic.alerts.arn
        Condition = {
          StringEquals = {
            "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

# SNS Subscriptions
resource "aws_sns_topic_subscription" "alerts" {
  for_each = { for idx, sub in var.subscriptions : idx => sub }

  topic_arn = aws_sns_topic.alerts.arn
  protocol  = each.value.protocol
  endpoint  = each.value.endpoint
}