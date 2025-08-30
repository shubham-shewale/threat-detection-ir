# Lambda Triage Role
resource "aws_iam_role" "lambda_triage" {
  name = "lambda-triage-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = var.tags
}

resource "aws_iam_policy" "lambda_triage" {
  name = "lambda-triage-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:PutObjectAcl"
        ]
        Resource = [
          "arn:aws:s3:::ir-evidence-bucket/*",
          "arn:aws:s3:::ir-evidence-bucket"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups"
        ]
        Resource = "arn:aws:logs:*:*:log-group:/aws/lambda/*"
      },
      {
        Effect = "Allow"
        Action = [
          "securityhub:BatchUpdateFindings",
          "securityhub:DescribeFindings"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:ModifyNetworkInterface",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeInstances",
          "ec2:DescribeNetworkInterfaces",
          "ec2:CreateTags",
          "ec2:DeleteTags"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "states:StartExecution",
          "states:DescribeExecution"
        ]
        Resource = "arn:aws:states:*:*:stateMachine:guardduty-ir"
      },
      {
        Effect = "Allow"
        Action = [
          "sns:Publish",
          "sns:GetTopicAttributes"
        ]
        Resource = "arn:aws:sns:*:*:ir-alerts-topic"
      },
      {
        Effect = "Allow"
        Action = [
          "xray:PutTraceSegments",
          "xray:PutTelemetryRecords"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_triage" {
  role       = aws_iam_role.lambda_triage.name
  policy_arn = aws_iam_policy.lambda_triage.arn
}

# Step Functions IR Role
resource "aws_iam_role" "stepfn_ir" {
  name = "stepfn-ir-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "states.amazonaws.com"
        }
      }
    ]
  })

  tags = var.tags
}

resource "aws_iam_policy" "stepfn_ir" {
  name = "stepfn-ir-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:PutObjectAcl"
        ]
        Resource = [
          "arn:aws:s3:::ir-evidence-bucket/*",
          "arn:aws:s3:::ir-evidence-bucket"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction",
          "lambda:GetFunction"
        ]
        Resource = "arn:aws:lambda:*:*:function:guardduty-triage"
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups"
        ]
        Resource = "arn:aws:logs:*:*:log-group:/aws/states/*"
      },
      {
        Effect = "Allow"
        Action = [
          "securityhub:BatchUpdateFindings",
          "securityhub:DescribeFindings"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:ModifyNetworkInterface",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeInstances",
          "ec2:DescribeNetworkInterfaces",
          "ec2:CreateTags",
          "ec2:DeleteTags"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "sns:Publish",
          "sns:GetTopicAttributes"
        ]
        Resource = "arn:aws:sns:*:*:ir-alerts-topic"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "stepfn_ir" {
  role       = aws_iam_role.stepfn_ir.name
  policy_arn = aws_iam_policy.stepfn_ir.arn
}