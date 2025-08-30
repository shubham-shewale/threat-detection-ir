# Automated Threat Detection and Incident Response Stack

This Terraform project implements an event-driven threat detection and incident response (IR) system on AWS using GuardDuty, Security Hub, and related services.

## Architecture

The stack consists of the following components:

- **GuardDuty**: Detects threats and generates findings
- **Security Hub**: Aggregates and manages security findings
- **EventBridge**: Routes GuardDuty findings to Lambda for triage
- **Lambda Triage**: Parses findings, tags resources, stores evidence, triggers Step Functions
- **Step Functions IR**: Orchestrates remediation actions (isolation, notification, Security Hub updates)
- **S3 Evidence**: Stores finding evidence with encryption and access logging
- **SNS Alerts**: Sends notifications for IR events
- **Network Quarantine**: Security group for isolating compromised resources
- **IAM Roles**: Least-privilege roles for all components
- **CloudWatch**: Logging and monitoring

## Prerequisites

- AWS CLI configured with appropriate permissions
- Terraform >= 1.0
- AWS account with necessary permissions (see below)

## Required Permissions

The deploying user/role needs:

- GuardDuty: Enable, configure organization settings
- Security Hub: Enable, manage standards
- IAM: Create roles and policies
- S3: Create buckets and policies
- Lambda: Create functions
- Step Functions: Create state machines
- EventBridge: Create rules and targets
- SNS: Create topics and subscriptions
- EC2: Create security groups
- CloudWatch: Create log groups

## Deployment

### Single Account Deployment

1. Initialize Terraform:
   ```bash
   terraform init
   ```

2. Review the plan:
   ```bash
   terraform plan -var-file=single.tfvars
   ```

3. Apply the configuration:
   ```bash
   terraform apply -var-file=single.tfvars
   ```

### Organization Deployment

For multi-account setup:

1. Set `org_mode = true` in your tfvars file
2. Provide `delegated_admin_account_id`
3. Ensure the deploying account has organization permissions
4. Deploy in the management account

```bash
terraform apply -var-file=org.tfvars
```

## Configuration Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `org_mode` | Enable AWS Organizations mode | `false` |
| `delegated_admin_account_id` | Delegated admin account ID | `""` |
| `enable_standards` | Security Hub standards to enable | See variables.tf |
| `evidence_bucket_name` | S3 bucket for evidence | `"ir-evidence-bucket"` |
| `kms_alias` | KMS key alias | `"alias/ir-evidence-key"` |
| `quarantine_sg_name` | Quarantine security group name | `"quarantine-sg"` |
| `sns_subscriptions` | SNS subscriptions list | `[]` |
| `finding_severity_threshold` | Minimum severity (LOW/MEDIUM/HIGH/CRITICAL) | `"HIGH"` |
| `regions` | Regions to enable GuardDuty | `["us-east-1", "us-west-2", "eu-west-1"]` |
| `tags` | Common tags | See variables.tf |

## Testing

This project includes a comprehensive test suite with unit tests, integration tests, end-to-end tests, and CI/CD automation. The test suite validates functionality, security, and failure behavior across all components.

### Test Structure

```
tests/
├── unit/                          # Unit tests for individual modules
│   ├── s3_evidence.tftest.hcl     # S3 bucket configuration tests
│   ├── sns_alerts.tftest.hcl      # SNS topic and encryption tests
│   ├── iam_roles.tftest.hcl       # IAM least privilege validation
│   ├── eventbridge.tftest.hcl     # Event routing and filtering tests
│   ├── lambda_triage.tftest.hcl   # Lambda function configuration tests
│   ├── stepfn_ir.tftest.hcl       # Step Functions workflow tests
│   ├── network_quarantine.tftest.hcl # Security group isolation tests
│   ├── guardduty.tftest.hcl       # GuardDuty detector tests
│   ├── securityhub.tftest.hcl     # Security Hub standards tests
│   └── cloudwatch.tftest.hcl      # Monitoring and alerting tests
├── integration/                   # Integration tests
│   └── root_apply.tftest.hcl      # Root module integration tests
└── mocks/                         # Provider and data source mocks

test/
├── e2e/                          # End-to-end tests (Go/Terratest)
│   ├── e2e_guardduty_flow_test.go    # Complete GuardDuty flow tests
│   ├── e2e_error_paths_test.go       # Error handling and chaos tests
│   └── e2e_security_controls_test.go # Runtime security validation
└── helpers/                       # Test utilities and helpers
    ├── aws.go                     # AWS SDK helpers
    ├── events.go                  # Sample GuardDuty events
    └── assert.go                  # Custom assertions
```

### Prerequisites

- **Terraform** >= 1.5.0
- **Go** >= 1.21 (for E2E tests)
- **AWS CLI** configured with test account
- **Terratest** dependencies (installed via `go mod download`)

### Running Tests Locally

#### Quick Start

```bash
# Run all tests
make test-all

# Run unit tests only
make test-unit

# Run integration tests
make test-integration

# Run end-to-end tests
make test-e2e

# Run with coverage
make test-coverage
```

#### Individual Test Execution

```bash
# Unit tests
terraform test tests/unit/s3_evidence.tftest.hcl
terraform test tests/unit/iam_roles.tftest.hcl

# Integration tests
cd tests/integration && terraform test -var-file=../../single.tfvars

# E2E tests
cd test/e2e && go test -v -run TestGuardDutyFlowEndToEnd -timeout 30m

# Specific test
make test-specific TEST=TestSecurityControlsRuntime
```

#### Environment Setup

```bash
# Set AWS credentials
export AWS_PROFILE=threat-detection-test
export AWS_REGION=us-east-1

# Install dependencies
make setup

# Validate environment
make validate
```

### Test Categories

#### 1. Unit Tests (`tests/unit/`)

**Purpose**: Validate individual module configurations and security controls

**Coverage**:
- S3 Evidence: Bucket versioning, SSE-KMS encryption, public access blocks, access logging
- SNS Alerts: KMS encryption, topic policies, subscription validation
- IAM Roles: Least privilege validation, no wildcard permissions, condition keys
- EventBridge: Event pattern matching, dead letter queues, retry policies
- Lambda Triage: Environment variables, log retention, reserved concurrency
- Step Functions: Retry logic, error handling, state transitions
- Network Quarantine: Zero ingress rules, minimal egress
- GuardDuty: Detector configuration, regional deployment
- Security Hub: Standards enablement, compliance validation
- CloudWatch: Log groups, metrics, alarms

**Example**:
```bash
terraform test tests/unit/iam_roles.tftest.hcl
```

#### 2. Integration Tests (`tests/integration/`)

**Purpose**: Validate cross-module interactions and data flow

**Coverage**:
- Root module configuration validation
- Module dependency resolution
- Cross-module data flow
- Variable validation
- Security configuration consistency

**Example**:
```bash
cd tests/integration && terraform test -var-file=../../single.tfvars
```

#### 3. End-to-End Tests (`test/e2e/`)

**Purpose**: Validate complete system behavior in AWS environment

**Test Scenarios**:
- **GuardDuty Flow**: Complete event processing from detection to resolution
- **Error Paths**: Failure handling, retries, dead letter queues
- **Security Controls**: Runtime validation of security configurations
- **Performance**: Concurrent event processing, latency validation
- **Chaos Engineering**: Service failures, network issues, resource constraints

**Example**:
```bash
cd test/e2e && go test -v -run TestGuardDutyFlowEndToEnd -timeout 30m
```

### Security Testing

#### Automated Security Validation

```bash
# Run security scans
make security-scan

# Validate IAM policies
make test-security

# Check encryption configurations
cd test/e2e && go test -v -run TestSecurityControlsRuntime
```

#### Security Test Coverage

- **Encryption**: S3 SSE-KMS, SNS encryption, CloudWatch log encryption
- **Access Control**: IAM least privilege, S3 bucket policies, security groups
- **Network Security**: HTTPS enforcement, public access blocks
- **Data Protection**: KMS key rotation, secure transport policies
- **Monitoring**: CloudWatch alarms, log retention validation

### Performance Testing

#### Load Testing

```bash
# Run performance tests
make test-performance

# Test concurrent events
cd test/e2e && go test -v -run TestConcurrentEvents -timeout 45m
```

#### Performance Benchmarks

- **Event Processing**: < 30 seconds end-to-end
- **Concurrent Events**: Support for 10+ simultaneous events
- **Resource Utilization**: < 80% of allocated limits
- **Error Rate**: < 1% under normal conditions

### CI/CD Integration

#### GitHub Actions Workflow

The CI/CD pipeline includes:

1. **Code Quality**: Terraform validation, formatting, Go vet
2. **Security Scanning**: Checkov, TFSec, dependency scanning
3. **Unit Tests**: All module unit tests
4. **Integration Tests**: Cross-module validation
5. **E2E Tests**: Full system testing in staging
6. **Performance Tests**: Load and concurrency validation
7. **Deployment**: Automated staging and production deployment

#### Pipeline Stages

```yaml
# Key stages from .github/workflows/ci.yml
- code-quality        # Static analysis
- unit-tests         # Module validation
- integration-tests  # Cross-module testing
- e2e-tests          # System validation
- performance-tests  # Load testing
- deploy-staging     # Staging deployment
- deploy-production  # Production deployment
```

#### Required Secrets

```bash
# GitHub repository secrets
AWS_ACCESS_KEY_ID_STAGING
AWS_SECRET_ACCESS_KEY_STAGING
AWS_ACCESS_KEY_ID_PROD
AWS_SECRET_ACCESS_KEY_PROD
SLACK_WEBHOOK_URL
MANUAL_APPROVAL_TOKEN
```

### Test Data and Samples

#### Sample GuardDuty Events

Located in `test/helpers/events.go`:

```go
// High severity SSH brute force
SampleGuardDutyEvents["high-severity-ssh-brute-force"] = GuardDutyFinding{
    ID:       "sample-finding-001",
    Severity: 8.5,
    Type:     "UnauthorizedAccess:EC2/SSHBruteForce",
    Resource: map[string]interface{}{
        "resourceType": "Instance",
        "instanceDetails": map[string]interface{}{
            "instanceId": "i-1234567890abcdef0",
        },
    },
}
```

#### Malformed Events for Error Testing

```go
MalformedEventSamples = map[string]string{
    "invalid-json": `{"source": "aws.guardduty", "detail": {invalid-json}}`,
    "missing-fields": `{"source": "aws.guardduty"}`,
    "wrong-source": `{"source": "aws.ec2", "detail-type": "GuardDuty Finding"}`,
}
```

### Troubleshooting Tests

#### Common Issues

```bash
# Check test environment
make troubleshoot

# View test logs
tail -f test-results/test-results.json

# Debug specific test
cd test/e2e && go test -v -run TestGuardDutyFlowEndToEnd -args -test.v
```

#### Test Debugging

```bash
# Run with verbose output
make test-verbose

# Run with race detection
make test-race

# Generate coverage report
make test-coverage
```

### Test Results and Reporting

#### Local Results

```bash
# View test summary
make stats

# Generate test report
make test-report

# View coverage
open test/e2e/coverage.html
```

#### CI/CD Results

- **GitHub Actions**: Test results in workflow artifacts
- **Coverage Reports**: HTML coverage reports
- **Security Scans**: SARIF files for security findings
- **Performance Metrics**: Custom performance dashboards

### Contributing to Tests

#### Adding New Tests

1. **Unit Tests**: Add `*.tftest.hcl` files in `tests/unit/`
2. **Integration Tests**: Modify `tests/integration/root_apply.tftest.hcl`
3. **E2E Tests**: Add `*_test.go` files in `test/e2e/`
4. **Helpers**: Extend functions in `test/helpers/`

#### Test Best Practices

- Use descriptive test names
- Include both positive and negative test cases
- Mock external dependencies where possible
- Clean up resources after tests
- Document test scenarios and expected outcomes

### Success Criteria

- [ ] All unit tests pass
- [ ] Integration tests validate cross-module functionality
- [ ] E2E tests confirm end-to-end behavior
- [ ] Security scans pass with no critical findings
- [ ] Performance benchmarks met
- [ ] CI/CD pipeline completes successfully
- [ ] Test coverage > 80%

### Commands Summary

```bash
# Complete test suite
make test-all

# Individual test types
make test-unit
make test-integration
make test-e2e

# Quality checks
make validate
make lint
make security-scan

# Utilities
make setup
make clean
make stats
make troubleshoot
```

## Outputs

The stack outputs important resource ARNs and IDs for integration and monitoring.

## Security Considerations

- All S3 buckets enforce SSL/TLS
- Evidence is encrypted with KMS
- IAM roles follow least-privilege principle
- Quarantine SG blocks all traffic
- CloudWatch logging enabled for all components

## Cleanup

To destroy the stack:

```bash
terraform destroy -var-file=single.tfvars
```

Note: Some resources may need manual cleanup (e.g., S3 objects, CloudWatch logs).

## Troubleshooting

- Check Terraform state for errors
- Review CloudWatch logs for Lambda/Step Functions
- Verify IAM permissions
- Ensure KMS keys are accessible
- Check EventBridge rule targets

## Contributing

1. Follow Terraform best practices
2. Use descriptive variable names
3. Include comments in complex logic
4. Test changes thoroughly
5. Update documentation as needed