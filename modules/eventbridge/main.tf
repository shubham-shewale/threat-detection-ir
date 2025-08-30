locals {
  severity_numeric = {
    "LOW"      = 1
    "MEDIUM"   = 4
    "HIGH"     = 7
    "CRITICAL" = 9
  }
}

# Dead-letter queue for failed events
resource "aws_sqs_queue" "dlq" {
  name = "guardduty-finding-dlq"

  # Enable server-side encryption
  sqs_managed_sse_enabled = true

  tags = var.tags
}

# EventBridge rule for GuardDuty findings
resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name        = "guardduty-finding-rule"
  description = "Rule for GuardDuty findings above severity threshold"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [{ "numeric": [">=", local.severity_numeric[var.finding_severity_threshold]] }]
    }
  })

  tags = var.tags
}

# Target: Lambda triage function
resource "aws_cloudwatch_event_target" "lambda_triage" {
  rule = aws_cloudwatch_event_rule.guardduty_findings.name
  arn  = var.lambda_function_arn

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
}

# Target: Step Functions IR state machine
resource "aws_cloudwatch_event_target" "stepfn_ir" {
  rule = aws_cloudwatch_event_rule.guardduty_findings.name
  arn  = var.state_machine_arn

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
}

# Permission for EventBridge to invoke Lambda
resource "aws_lambda_permission" "eventbridge_invoke" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = var.lambda_function_arn
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_findings.arn
}

# Permission for EventBridge to start Step Functions execution
resource "aws_iam_role_policy" "eventbridge_stepfn" {
  name = "eventbridge-stepfn-policy"
  role = aws_iam_role.eventbridge_stepfn.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "states:StartExecution"
        Resource = var.state_machine_arn
      }
    ]
  })
}

resource "aws_iam_role" "eventbridge_stepfn" {
  name = "eventbridge-stepfn-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
      }
    ]
  })

  tags = var.tags
}