# CI/CD Runbook: AWS Threat Detection & Incident Response Stack

**Version:** 1.0.0
**Last Updated:** 2025-08-30
**CI/CD Platform:** GitHub Actions

## Pipeline Overview

The CI/CD pipeline implements a secure, automated deployment process with comprehensive testing, security scanning, and compliance validation.

### Pipeline Stages

1. **Code Quality & Security**
2. **Infrastructure Testing**
3. **Security Scanning**
4. **Compliance Validation**
5. **Deployment Preparation**
6. **Staged Deployment**
7. **Post-Deployment Validation**

## GitHub Actions Workflow Configuration

### Main Pipeline (`.github/workflows/main.yml`)

```yaml
name: Threat Detection IR Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

env:
  AWS_REGION: us-east-1
  TERRAFORM_VERSION: 1.5.0

jobs:
  # Code Quality & Security
  code-quality:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: ${{ env.TERRAFORM_VERSION }}

      - name: Terraform Format Check
        run: terraform fmt -check -recursive

      - name: Terraform Validate
        run: terraform validate

      - name: Checkov Security Scan
        uses: bridgecrewio/checkov-action@v12
        with:
          framework: terraform
          output_format: cli
          output_file_path: checkov-results.txt

      - name: Upload Checkov Results
        uses: actions/upload-artifact@v3
        with:
          name: checkov-results
          path: checkov-results.txt

  # Infrastructure Testing
  infrastructure-test:
    needs: code-quality
    runs-on: ubuntu-latest
    environment: test
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: ${{ env.AWS_REGION }}

      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: ${{ env.TERRAFORM_VERSION }}

      - name: Terraform Init
        run: terraform init

      - name: Terraform Plan
        run: |
          terraform plan -var-file=single.tfvars -out=tfplan
          terraform show -json tfplan > tfplan.json

      - name: Upload Terraform Plan
        uses: actions/upload-artifact@v3
        with:
          name: tfplan
          path: tfplan.json

      - name: Infracost Estimate
        uses: infracost/infracost-github-action@v0.0.1
        env:
          INFRACOST_API_KEY: ${{ secrets.INFRACOST_API_KEY }}
        with:
          path: .
          terraform_plan_flags: -var-file=single.tfvars

  # Security Scanning
  security-scan:
    needs: infrastructure-test
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Run Trivy Vulnerability Scan
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          scan-ref: '.'
          format: 'sarif'
          output: 'trivy-results.sarif'

      - name: Upload Trivy Results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: trivy-results.sarif

      - name: Run Snyk IaC Scan
        uses: snyk/actions/iac@v0.4.0
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          file: .

  # Compliance Validation
  compliance-check:
    needs: security-scan
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'

      - name: Install compliance tools
        run: |
          pip install checkov
          pip install tfsec

      - name: Run TFSec
        uses: tfsec/tfsec-sarif-action@v1.1.0
        with:
          sarif_file: tfsec-results.sarif

      - name: Upload TFSec Results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: tfsec-results.sarif

  # Deployment Preparation
  deploy-prep:
    needs: [code-quality, infrastructure-test, security-scan, compliance-check]
    runs-on: ubuntu-latest
    environment: staging
    if: github.ref == 'refs/heads/main'
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID_STAGING }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY_STAGING }}
          aws-region: ${{ env.AWS_REGION }}

      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: ${{ env.TERRAFORM_VERSION }}

      - name: Terraform Init
        run: terraform init

      - name: Terraform Plan (Staging)
        run: terraform plan -var-file=single.tfvars -out=tfplan-staging

      - name: Terraform Apply (Staging)
        run: terraform apply -auto-approve tfplan-staging

  # Integration Testing
  integration-test:
    needs: deploy-prep
    runs-on: ubuntu-latest
    environment: staging
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID_STAGING }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY_STAGING }}
          aws-region: ${{ env.AWS_REGION }}

      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'

      - name: Install test dependencies
        run: pip install boto3 pytest

      - name: Run integration tests
        run: python -m pytest tests/integration/ -v

      - name: Generate test report
        run: |
          mkdir -p test-results
          python -m pytest tests/integration/ --junitxml=test-results/junit.xml

      - name: Upload test results
        uses: actions/upload-artifact@v3
        with:
          name: test-results
          path: test-results/

  # Production Deployment
  production-deploy:
    needs: integration-test
    runs-on: ubuntu-latest
    environment: production
    if: github.ref == 'refs/heads/main' && github.event_name == 'push'
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID_PROD }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY_PROD }}
          aws-region: ${{ env.AWS_REGION }}

      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: ${{ env.TERRAFORM_VERSION }}

      - name: Terraform Init
        run: terraform init

      - name: Terraform Plan (Production)
        run: terraform plan -var-file=org.tfvars -out=tfplan-prod

      - name: Manual Approval Gate
        uses: trstringer/manual-approval@v1
        with:
          secret: ${{ secrets.MANUAL_APPROVAL_TOKEN }}
          approvers: security-team,platform-team
          minimum-approvals: 2
          issue-title: "Production Deployment Approval Required"
          issue-body: "Please review and approve production deployment of threat detection stack"

      - name: Terraform Apply (Production)
        run: terraform apply -auto-approve tfplan-prod

  # Post-Deployment Validation
  post-deploy-validation:
    needs: production-deploy
    runs-on: ubuntu-latest
    environment: production
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID_PROD }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY_PROD }}
          aws-region: ${{ env.AWS_REGION }}

      - name: Run health checks
        run: |
          # Check Lambda function
          aws lambda get-function --function-name guardduty-triage

          # Check Step Functions
          aws stepfunctions describe-state-machine \
            --state-machine-arn $(terraform output -raw stepfn_ir_state_machine_arn)

          # Check S3 buckets
          aws s3 ls s3://ir-evidence-bucket

          # Check EventBridge rules
          aws events list-rules --name-prefix guardduty

      - name: Send deployment notification
        run: |
          # Send Slack notification
          curl -X POST -H 'Content-type: application/json' \
            --data '{"text":"Threat Detection Stack deployed successfully to production"}' \
            ${{ secrets.SLACK_WEBHOOK_URL }}
```

## Required Secrets

### GitHub Repository Secrets

```bash
# AWS Credentials
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
AWS_ACCESS_KEY_ID_STAGING
AWS_SECRET_ACCESS_KEY_STAGING
AWS_ACCESS_KEY_ID_PROD
AWS_SECRET_ACCESS_KEY_PROD

# Security Scanning
SNYK_TOKEN
INFRACOST_API_KEY

# Notifications
SLACK_WEBHOOK_URL
MANUAL_APPROVAL_TOKEN
```

## Environment Configuration

### Staging Environment
- **Purpose:** Pre-production testing
- **Resources:** Minimal instance types
- **Data:** Test data only
- **Monitoring:** Basic alerts

### Production Environment
- **Purpose:** Live incident response
- **Resources:** Production-grade sizing
- **Data:** Real security events
- **Monitoring:** Full alerting and dashboards

## Branch Protection Rules

### Main Branch
```yaml
required_status_checks:
  contexts:
    - code-quality
    - infrastructure-test
    - security-scan
    - compliance-check

required_pull_request_reviews:
  required_approving_review_count: 2
  dismiss_stale_reviews: true
  require_code_owner_reviews: true

restrictions:
  - enforce_admins: true
  - allow_force_pushes: false
  - allow_deletions: false
```

## Quality Gates

### Code Quality
- [ ] Terraform formatting check passes
- [ ] Terraform validation passes
- [ ] No critical Checkov findings
- [ ] Test coverage > 80%

### Security
- [ ] No high/critical vulnerabilities
- [ ] IAM policies follow least privilege
- [ ] Encryption enabled for all data at rest/transit
- [ ] No public access to sensitive resources

### Infrastructure
- [ ] Cost estimation within budget
- [ ] Resource limits not exceeded
- [ ] Dependencies properly configured
- [ ] Backup/recovery configured

### Compliance
- [ ] CIS AWS Foundations compliance
- [ ] NIST 800-53 controls implemented
- [ ] SOC 2 requirements met
- [ ] GDPR/data protection compliance

## Rollback Procedures

### Automated Rollback
```yaml
# Trigger rollback on failure
- name: Rollback on Failure
  if: failure()
  run: |
    terraform plan -destroy -var-file=org.tfvars -out=rollback-plan
    terraform apply -auto-approve rollback-plan
```

### Manual Rollback
```bash
# Emergency rollback
terraform destroy -var-file=org.tfvars -auto-approve

# Gradual rollback (feature flags)
aws lambda update-function-configuration \
  --function-name guardduty-triage \
  --environment Variables={ROLLBACK_MODE=true}
```

## Monitoring and Alerting

### Pipeline Metrics
- Deployment success rate
- Test pass rate
- Security scan results
- Performance benchmarks

### Application Metrics
- Event processing latency
- Error rates
- Resource utilization
- Incident response time

### Alerting Rules
```yaml
# Pipeline failure alert
- name: Pipeline Failure
  condition: job.status == 'failure'
  channels: [slack, email]

# Security vulnerability alert
- name: High Severity Vulnerability
  condition: checkov.severity >= 'HIGH'
  channels: [slack, pager-duty]

# Deployment delay alert
- name: Deployment Delay
  condition: job.duration > 30m
  channels: [slack]
```

## Troubleshooting

### Common Pipeline Issues

#### Terraform Init Fails
```bash
# Check AWS credentials
aws sts get-caller-identity

# Verify S3 backend access
aws s3 ls s3://terraform-state-bucket
```

#### Security Scan Fails
```bash
# Review scan results
cat checkov-results.txt

# Check false positives
checkov --framework terraform --check CKV_AWS_1,CKV_AWS_2
```

#### Deployment Times Out
```bash
# Check AWS service limits
aws service-quotas get-service-quota \
  --service-code lambda \
  --quota-code L-2D04C406

# Monitor CloudWatch logs
aws logs tail /aws/codebuild/project-name
```

## Performance Optimization

### Build Time Optimization
- Use Terraform workspaces for parallel deployments
- Cache Terraform providers and modules
- Parallelize security scans
- Use build matrices for multi-region testing

### Cost Optimization
- Use spot instances for CI runners
- Implement resource tagging for cost tracking
- Set up budget alerts
- Clean up test resources automatically

## Security Considerations

### Pipeline Security
- OIDC authentication for AWS access
- Least privilege IAM roles
- Secret rotation policies
- Audit logging enabled

### Code Security
- SAST scanning on every commit
- Dependency vulnerability scanning
- Container image scanning
- Secrets detection

### Access Control
- Branch protection rules
- Required reviews for changes
- Manual approval for production
- Audit trails for all actions

## Success Metrics

- **Deployment Frequency:** Multiple per day
- **Lead Time:** < 1 hour
- **Change Failure Rate:** < 5%
- **MTTR:** < 15 minutes
- **Security Scan Pass Rate:** > 95%