# Threat Detection IR Test Suite Makefile
# Comprehensive test automation for the AWS threat detection and incident response stack

.PHONY: help test test-unit test-integration test-e2e test-all clean setup validate lint security-scan

# Default target
help:
	@echo "Threat Detection IR Test Suite"
	@echo ""
	@echo "Available targets:"
	@echo "  help              Show this help message"
	@echo "  setup             Install dependencies and setup environment"
	@echo "  validate          Run Terraform validation"
	@echo "  lint              Run linting checks"
	@echo "  security-scan     Run security scanning"
	@echo "  test-unit         Run unit tests"
	@echo "  test-integration  Run integration tests"
	@echo "  test-e2e          Run end-to-end tests"
	@echo "  test-all          Run all tests"
	@echo "  test-performance  Run performance tests"
	@echo "  test-security     Run security validation tests"
	@echo "  clean             Clean up test artifacts"
	@echo ""
	@echo "Environment variables:"
	@echo "  AWS_PROFILE       AWS profile to use (default: default)"
	@echo "  AWS_REGION        AWS region (default: us-east-1)"
	@echo "  TEST_ENV          Test environment (staging|production)"

# Environment variables
AWS_PROFILE ?= default
AWS_REGION ?= us-east-1
TEST_ENV ?= staging
TERRAFORM_VERSION ?= 1.5.0
GO_VERSION ?= 1.21

# Setup environment
setup:
	@echo "Setting up test environment..."
	@echo "Installing Terraform $(TERRAFORM_VERSION)..."
	@curl -fsSL https://releases.hashicorp.com/terraform/$(TERRAFORM_VERSION)/terraform_$(TERRAFORM_VERSION)_linux_amd64.zip -o terraform.zip
	@unzip -o terraform.zip
	@chmod +x terraform
	@sudo mv terraform /usr/local/bin/
	@echo "Installing Go $(GO_VERSION)..."
	@curl -fsSL https://golang.org/dl/go$(GO_VERSION).linux-amd64.tar.gz -o go.tar.gz
	@sudo tar -C /usr/local -xzf go.tar.gz
	@export PATH=$$PATH:/usr/local/go/bin
	@echo "Installing Terratest dependencies..."
	@cd test/e2e && go mod download
	@echo "Setup complete!"

# Terraform validation
validate:
	@echo "Running Terraform validation..."
	@terraform init
	@terraform validate
	@terraform fmt -check -recursive

# Linting
lint:
	@echo "Running linting checks..."
	@terraform fmt -check -recursive
	@cd test/e2e && go vet ./...
	@cd test/e2e && go fmt ./...

# Security scanning
security-scan:
	@echo "Running security scans..."
	@command -v checkov >/dev/null 2>&1 || { echo "Checkov not found, installing..."; pip install checkov; }
	@checkov -f . --framework terraform --quiet
	@command -v tfsec >/dev/null 2>&1 || { echo "TFSec not found, installing..."; curl -fsSL https://github.com/aquasecurity/tfsec/releases/latest/download/tfsec-linux-amd64 -o tfsec && chmod +x tfsec && sudo mv tfsec /usr/local/bin/; }
	@tfsec .

# Unit tests
test-unit:
	@echo "Running unit tests..."
	@find tests/unit -name "*.tftest.hcl" -exec echo "Running {}" \; -exec terraform test {} \;

# Integration tests
test-integration:
	@echo "Running integration tests..."
	@cd tests/integration && terraform test -var-file=../../single.tfvars

# End-to-end tests
test-e2e:
	@echo "Running end-to-end tests..."
	@cd test/e2e && go test -v -timeout 30m ./...

# Performance tests
test-performance:
	@echo "Running performance tests..."
	@cd test/e2e && go test -v -run TestConcurrentEvents -timeout 45m

# Security validation tests
test-security:
	@echo "Running security validation tests..."
	@cd test/e2e && go test -v -run TestSecurityControlsRuntime -timeout 30m

# Run all tests
test-all: validate lint security-scan test-unit test-integration test-e2e test-performance test-security
	@echo "All tests completed successfully!"

# Quick test (unit + integration only)
test:
	@echo "Running quick tests (unit + integration)..."
	@make test-unit
	@make test-integration

# Clean up
clean:
	@echo "Cleaning up test artifacts..."
	@rm -rf .terraform/
	@rm -rf terraform.tfstate*
	@rm -rf test-results/
	@rm -rf *.log
	@rm -rf .test-data/
	@find . -name "*.tmp" -delete
	@find . -name "*.swp" -delete
	@cd test/e2e && go clean -cache -testcache

# Setup test data
setup-test-data:
	@echo "Setting up test data..."
	@mkdir -p test-data/
	@echo "Test data setup complete"

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	@cd test/e2e && go test -v -cover -coverprofile=coverage.out ./...
	@cd test/e2e && go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: test/e2e/coverage.html"

# Run tests in parallel
test-parallel:
	@echo "Running tests in parallel..."
	@cd test/e2e && go test -v -parallel 4 ./...

# Run specific test
test-specific:
	@echo "Usage: make test-specific TEST=TestName"
	@if [ -z "$(TEST)" ]; then echo "Please specify TEST variable"; exit 1; fi
	@cd test/e2e && go test -v -run $(TEST) -timeout 30m

# Run tests with verbose output
test-verbose:
	@echo "Running tests with verbose output..."
	@cd test/e2e && go test -v -timeout 30m ./...

# Run tests with race detection
test-race:
	@echo "Running tests with race detection..."
	@cd test/e2e && go test -v -race -timeout 30m ./...

# Generate test report
test-report:
	@echo "Generating test report..."
	@mkdir -p test-results/
	@cd test/e2e && go test -v -json ./... > ../test-results/test-results.json
	@echo "Test report generated: test-results/test-results.json"

# CI/CD targets
ci-setup:
	@echo "Setting up CI environment..."
	@make setup
	@make validate

ci-test:
	@echo "Running CI tests..."
	@make test-all
	@make test-report

ci-deploy-staging:
	@echo "Deploying to staging..."
	@terraform init
	@terraform plan -var-file=single.tfvars -out=tfplan-staging
	@terraform apply -auto-approve tfplan-staging

ci-deploy-production:
	@echo "Deploying to production..."
	@terraform init
	@terraform plan -var-file=org.tfvars -out=tfplan-prod
	@terraform apply -auto-approve tfplan-prod

# Health checks
health-check:
	@echo "Running health checks..."
	@aws lambda list-functions --query 'Functions[?FunctionName==`guardduty-triage`]' --region $(AWS_REGION)
	@aws stepfunctions list-state-machines --query 'stateMachines[?name==`guardduty-ir`]' --region $(AWS_REGION)
	@aws s3 ls --region $(AWS_REGION)

# Troubleshooting
troubleshoot:
	@echo "Troubleshooting information:"
	@echo "AWS Profile: $(AWS_PROFILE)"
	@echo "AWS Region: $(AWS_REGION)"
	@echo "Test Environment: $(TEST_ENV)"
	@echo ""
	@echo "Recent Terraform state:"
	@terraform state list 2>/dev/null || echo "No Terraform state found"
	@echo ""
	@echo "Recent CloudWatch logs:"
	@aws logs describe-log-groups --region $(AWS_REGION) --query 'logGroups[?starts_with(logGroupName, `/aws/lambda/guardduty-triage`) || starts_with(logGroupName, `/aws/states/guardduty-ir`)].logGroupName' 2>/dev/null || echo "Unable to fetch log groups"

# Show test statistics
stats:
	@echo "Test Statistics:"
	@echo "Unit tests: $$(find tests/unit -name "*.tftest.hcl" | wc -l)"
	@echo "Integration tests: $$(find tests/integration -name "*.tftest.hcl" | wc -l)"
	@echo "E2E tests: $$(find test/e2e -name "*_test.go" | wc -l)"
	@echo "Helper files: $$(find test/helpers -name "*.go" | wc -l)"
	@echo ""
	@echo "Lines of test code:"
	@find tests/ test/ -name "*.hcl" -o -name "*.go" | xargs wc -l | tail -1

# Show available tests
list-tests:
	@echo "Available unit tests:"
	@find tests/unit -name "*.tftest.hcl" | sed 's|tests/unit/||'
	@echo ""
	@echo "Available integration tests:"
	@find tests/integration -name "*.tftest.hcl" | sed 's|tests/integration/||'
	@echo ""
	@echo "Available E2E tests:"
	@cd test/e2e && find . -name "*_test.go" | sed 's|./||' | sed 's|_test.go||'

# Show test dependencies
deps:
	@echo "Test dependencies:"
	@cd test/e2e && go list -m all
	@echo ""
	@echo "System dependencies:"
	@terraform version
	@go version
	@aws --version

# Emergency cleanup
emergency-cleanup:
	@echo "Performing emergency cleanup..."
	@terraform destroy -auto-approve -var-file=single.tfvars || true
	@aws lambda delete-function --function-name guardduty-triage --region $(AWS_REGION) || true
	@aws stepfunctions delete-state-machine --state-machine-arn $$(aws stepfunctions list-state-machines --query 'stateMachines[?name==`guardduty-ir`].stateMachineArn' --output text --region $(AWS_REGION)) || true
	@make clean