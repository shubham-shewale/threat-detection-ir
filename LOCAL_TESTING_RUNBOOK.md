# Local Testing Runbook: AWS Threat Detection & Incident Response Stack

**Version:** 1.0.0
**Last Updated:** 2025-08-30
**Test Environment:** Local Development

## Prerequisites

### System Requirements
- Terraform >= 1.0.0
- AWS CLI v2
- Python 3.9+
- Git
- Docker (optional, for isolated testing)

### AWS Setup
```bash
# Configure AWS CLI with test account
aws configure --profile threat-detection-test

# Verify configuration
aws sts get-caller-identity --profile threat-detection-test
```

### Environment Variables
```bash
export AWS_PROFILE=threat-detection-test
export AWS_DEFAULT_REGION=us-east-1
export TF_VAR_region=us-east-1
```

## Test Scenarios

### 1. Basic Infrastructure Deployment

#### Objective
Verify core infrastructure deploys without errors

#### Steps
```bash
# 1. Clone and navigate to project
cd threat-detection-ir

# 2. Initialize Terraform
terraform init

# 3. Validate configuration
terraform validate

# 4. Plan deployment (single account)
terraform plan -var-file=single.tfvars -out=tfplan

# 5. Review plan output
terraform show tfplan

# 6. Deploy infrastructure
terraform apply tfplan
```

#### Expected Results
- All resources created successfully
- No Terraform errors
- Outputs display correct values
- AWS console shows created resources

#### Verification Commands
```bash
# Check S3 buckets
aws s3 ls

# Check Lambda functions
aws lambda list-functions --query 'Functions[?FunctionName==`guardduty-triage`]'

# Check Step Functions
aws stepfunctions list-state-machines --query 'stateMachines[?name==`guardduty-ir`]'

# Check EventBridge rules
aws events list-rules --name-prefix guardduty
```

### 2. IAM Permissions Test

#### Objective
Verify least privilege IAM policies work correctly

#### Steps
```bash
# Test Lambda execution role
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::ACCOUNT-ID:role/lambda-triage-role \
  --action-names s3:GetObject s3:PutObject \
  --resource-arns arn:aws:s3:::ir-evidence-bucket/*

# Test Step Functions role
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::ACCOUNT-ID:role/stepfn-ir-role \
  --action-names lambda:InvokeFunction \
  --resource-arns arn:aws:lambda:REGION:ACCOUNT-ID:function:guardduty-triage
```

#### Expected Results
- All allowed actions return "allowed": true
- All denied actions return "allowed": false

### 3. Event Flow Simulation

#### Objective
Test end-to-end event processing

#### Steps
```bash
# 1. Create test GuardDuty finding event
cat > test-finding.json << EOF
{
  "source": "aws.guardduty",
  "detail-type": "GuardDuty Finding",
  "detail": {
    "id": "test-finding-12345",
    "severity": 8.5,
    "title": "Test UnauthorizedAccess:EC2/SSHBruteForce",
    "resource": {
      "resourceType": "Instance",
      "instanceDetails": {
        "instanceId": "i-1234567890abcdef0"
      }
    }
  }
}
EOF

# 2. Send test event to EventBridge
aws events put-events \
  --entries '[{"Source": "aws.guardduty", "DetailType": "GuardDuty Finding", "Detail": "{\"id\": \"test-finding-12345\", \"severity\": 8.5}"}]'

# 3. Check Lambda logs
aws logs tail /aws/lambda/triage --follow

# 4. Check Step Functions execution
aws stepfunctions list-executions \
  --state-machine-arn $(terraform output -raw stepfn_ir_state_machine_arn)

# 5. Verify evidence storage
aws s3 ls s3://ir-evidence-bucket/findings/
```

#### Expected Results
- EventBridge rule triggers
- Lambda function executes
- Evidence stored in S3
- Step Functions state machine starts
- Logs show successful processing

### 4. Security Configuration Test

#### Objective
Verify security controls are properly configured

#### Steps
```bash
# Test S3 encryption
aws s3api get-bucket-encryption --bucket ir-evidence-bucket

# Test S3 public access block
aws s3api get-public-access-block --bucket ir-evidence-bucket

# Test KMS key rotation
aws kms describe-key --key-id $(terraform output -raw s3_evidence_kms_key_arn) \
  --query 'KeyMetadata.KeyRotationEnabled'

# Test SNS encryption
aws sns get-topic-attributes \
  --topic-arn $(terraform output -raw sns_topic_arn) \
  --query 'Attributes.KmsMasterKeyId'
```

#### Expected Results
- S3 encryption: SSE-KMS enabled
- Public access: All blocks enabled
- KMS rotation: Enabled
- SNS encryption: KMS key configured

### 5. Error Handling Test

#### Objective
Verify system handles errors gracefully

#### Steps
```bash
# 1. Test with malformed event
aws events put-events \
  --entries '[{"Source": "aws.guardduty", "DetailType": "GuardDuty Finding", "Detail": "invalid-json"}]'

# 2. Check DLQ for failed messages
aws sqs get-queue-attributes \
  --queue-url $(aws sqs get-queue-url --queue-name guardduty-finding-dlq --query 'QueueUrl' --output text) \
  --attribute-names ApproximateNumberOfMessages

# 3. Test Lambda timeout scenario
# (Modify Lambda timeout to 1 second, send large payload)

# 4. Verify error logging
aws logs filter-log-events \
  --log-group-name /aws/lambda/triage \
  --filter-pattern "ERROR"
```

#### Expected Results
- Malformed events sent to DLQ
- Error messages logged appropriately
- System continues processing valid events

### 6. Load Testing

#### Objective
Verify system performance under load

#### Steps
```bash
# Send multiple events simultaneously
for i in {1..10}; do
  aws events put-events \
    --entries "[{\"Source\": \"aws.guardduty\", \"DetailType\": \"GuardDuty Finding\", \"Detail\": \"{\\\"id\\\": \\\"test-finding-$i\\\", \\\"severity\\\": 8.0}\"}]" &
done

# Monitor Lambda concurrency
aws lambda get-function-concurrency \
  --function-name guardduty-triage

# Check Step Functions executions
aws stepfunctions list-executions \
  --state-machine-arn $(terraform output -raw stepfn_ir_state_machine_arn) \
  --query 'executions[?status==`SUCCEEDED`] | length(@)'
```

#### Expected Results
- All events processed successfully
- No concurrency limits exceeded
- All executions complete

## Cleanup Procedures

### Post-Test Cleanup
```bash
# Destroy infrastructure
terraform destroy -var-file=single.tfvars

# Clean up test data
aws s3 rm s3://ir-evidence-bucket --recursive
aws logs delete-log-group --log-group-name /aws/lambda/triage
aws logs delete-log-group --log-group-name /aws/states/stepfn-ir
```

### Emergency Cleanup
```bash
# Force destroy if normal destroy fails
terraform destroy -var-file=single.tfvars -auto-approve

# Manual resource cleanup
aws lambda delete-function --function-name guardduty-triage
aws stepfunctions delete-state-machine --state-machine-arn $(terraform output -raw stepfn_ir_state_machine_arn)
aws events delete-rule --name guardduty-finding-rule
```

## Troubleshooting

### Common Issues

#### Terraform Init Fails
```bash
# Clear cache and retry
rm -rf .terraform
terraform init
```

#### AWS Permissions Error
```bash
# Verify AWS credentials
aws sts get-caller-identity

# Check IAM permissions
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::ACCOUNT-ID:user/USERNAME \
  --action-names iam:CreateRole
```

#### Lambda Deployment Fails
```bash
# Check Lambda package size
ls -lh triage.zip

# Validate Python code
python3 -m py_compile lambda-src/triage.py
```

#### EventBridge Not Triggering
```bash
# Check rule configuration
aws events describe-rule --name guardduty-finding-rule

# Test rule with sample event
aws events test-event-pattern --event-pattern file://test-pattern.json
```

## Test Data

### Sample GuardDuty Finding
```json
{
  "source": "aws.guardduty",
  "detail-type": "GuardDuty Finding",
  "detail": {
    "id": "sample-finding-001",
    "severity": 8.0,
    "title": "UnauthorizedAccess:EC2/SSHBruteForce",
    "description": "Multiple SSH brute force attacks detected",
    "resource": {
      "resourceType": "Instance",
      "instanceDetails": {
        "instanceId": "i-1234567890abcdef0",
        "instanceType": "t3.micro",
        "launchTime": "2023-08-30T10:00:00Z",
        "platform": "Linux/Unix",
        "networkInterfaces": [
          {
            "networkInterfaceId": "eni-12345678",
            "privateIpAddress": "10.0.1.100",
            "publicIp": "203.0.113.1"
          }
        ]
      }
    },
    "service": {
      "serviceName": "guardduty",
      "detectorId": "detector-id",
      "action": {
        "actionType": "NETWORK_CONNECTION",
        "networkConnectionAction": {
          "connectionDirection": "INBOUND",
          "protocol": "TCP",
          "blocked": false,
          "localPortDetails": {
            "port": 22,
            "portName": "SSH"
          }
        }
      }
    }
  }
}
```

## Success Criteria

- [ ] All Terraform commands execute without errors
- [ ] Infrastructure deploys in < 10 minutes
- [ ] Event processing completes in < 30 seconds
- [ ] All security controls validated
- [ ] Error scenarios handled gracefully
- [ ] Logs show expected behavior
- [ ] Cleanup completes successfully

## Performance Benchmarks

- **Deployment Time:** < 10 minutes
- **Event Processing:** < 30 seconds
- **Concurrent Events:** 10 simultaneous
- **Error Rate:** < 1%
- **Resource Utilization:** < 80% of limits