# CloudWatch Log Group for Lambda Triage
resource "aws_cloudwatch_log_group" "lambda_triage" {
  name              = "/aws/lambda/triage"
  retention_in_days = 90
  tags              = var.tags
}

# CloudWatch Log Group for Step Functions IR
resource "aws_cloudwatch_log_group" "stepfn_ir" {
  name              = "/aws/states/stepfn-ir"
  retention_in_days = 90
  tags              = var.tags
}