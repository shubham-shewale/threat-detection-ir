data "archive_file" "triage" {
  type        = "zip"
  source_file = "${path.module}/lambda-src/triage.py"
  output_path = "${path.module}/triage.zip"
}

resource "aws_lambda_function" "triage" {
  function_name = "guardduty-triage"
  runtime       = "python3.9"
  handler       = "triage.lambda_handler"
  role          = var.iam_role_arn

  filename         = data.archive_file.triage.output_path
  source_code_hash = data.archive_file.triage.output_base64sha256

  environment {
    variables = {
      EVIDENCE_BUCKET   = var.evidence_bucket_name
      SNS_TOPIC_ARN     = var.sns_topic_arn
      STATE_MACHINE_ARN = var.state_machine_arn
      QUARANTINE_SG_ID  = var.quarantine_sg_id
    }
  }

  tags = var.tags
}