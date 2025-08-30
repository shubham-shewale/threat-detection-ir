resource "aws_sfn_state_machine" "ir" {
  name     = "guardduty-ir"
  role_arn = var.iam_role_arn

  definition = jsonencode({
    Comment = "State machine for GuardDuty Incident Response"
    StartAt = "StoreEvidence"
    States = {
      StoreEvidence = {
        Type       = "Pass"
        Result     = "Evidence stored in S3"
        ResultPath = "$.evidence"
        Next       = "IsolateResource"
      }
      IsolateResource = {
        Type       = "Pass"
        Result     = "Resource isolated with quarantine security group"
        ResultPath = "$.isolation"
        Next       = "Notify"
      }
      Notify = {
        Type       = "Pass"
        Result     = "Notification sent via SNS"
        ResultPath = "$.notification"
        Next       = "UpdateSecurityHub"
      }
      UpdateSecurityHub = {
        Type       = "Pass"
        Result     = "Finding marked as resolved in Security Hub"
        ResultPath = "$.securityhub"
        End        = true
      }
    }
  })

  logging_configuration {
    log_destination        = "${var.cloudwatch_log_group_arn}:*"
    include_execution_data = true
    level                  = "ALL"
  }

  tags = var.tags
}