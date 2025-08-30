# IAM Roles module - must be first as others depend on it
module "iam_roles" {
  source = "./modules/iam_roles"

  tags = var.tags
}

# S3 Evidence bucket
module "s3_evidence" {
  source = "./modules/s3_evidence"

  bucket_name = var.evidence_bucket_name
  kms_alias   = var.kms_alias
  tags        = var.tags
}

# SNS Alerts topic
module "sns_alerts" {
  source = "./modules/sns_alerts"

  subscriptions = var.sns_subscriptions
  tags          = var.tags
}

# Network Quarantine security group
module "network_quarantine" {
  source = "./modules/network_quarantine"

  sg_name = var.quarantine_sg_name
  tags    = var.tags
}

# GuardDuty setup
module "guardduty" {
  source = "./modules/guardduty"

  org_mode                   = var.org_mode
  delegated_admin_account_id = var.delegated_admin_account_id
  regions                    = var.regions
  tags                       = var.tags
}

# Security Hub setup
module "securityhub" {
  source = "./modules/securityhub"

  enable_standards = var.enable_standards
  tags             = var.tags
}

# CloudWatch logs
module "cloudwatch" {
  source = "./modules/cloudwatch"

  tags = var.tags
}

# Lambda Triage function
module "lambda_triage" {
  source = "./modules/lambda_triage"

  evidence_bucket_name     = module.s3_evidence.bucket_name
  sns_topic_arn            = module.sns_alerts.topic_arn
  state_machine_arn        = module.stepfn_ir.state_machine_arn
  quarantine_sg_id         = module.network_quarantine.quarantine_sg_id
  iam_role_arn             = module.iam_roles.lambda_role_arn
  cloudwatch_log_group_arn = module.cloudwatch.lambda_log_group_arn
  tags                     = var.tags
}

# Step Functions IR state machine
module "stepfn_ir" {
  source = "./modules/stepfn_ir"

  evidence_bucket_name     = module.s3_evidence.bucket_name
  sns_topic_arn            = module.sns_alerts.topic_arn
  quarantine_sg_id         = module.network_quarantine.quarantine_sg_id
  iam_role_arn             = module.iam_roles.stepfn_role_arn
  cloudwatch_log_group_arn = module.cloudwatch.stepfn_log_group_arn
  tags                     = var.tags
}

# EventBridge rules
module "eventbridge" {
  source = "./modules/eventbridge"

  lambda_function_arn        = module.lambda_triage.function_arn
  state_machine_arn          = module.stepfn_ir.state_machine_arn
  finding_severity_threshold = var.finding_severity_threshold
  tags                       = var.tags
}