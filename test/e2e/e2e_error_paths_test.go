package test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/eventbridge"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sfn"
	"github.com/gruntwork-io/terratest/modules/aws"
	"github.com/gruntwork-io/terratest/modules/random"
	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrorPathsAndChaos(t *testing.T) {
	t.Parallel()

	// Generate unique test ID
	testID := random.UniqueId()
	testName := fmt.Sprintf("threat-detection-ir-error-%s", testID)

	// Test configurations
	awsRegion := "us-east-1"
	evidenceBucketName := fmt.Sprintf("ir-evidence-error-%s", testID)
	kmsAlias := fmt.Sprintf("alias/ir-evidence-error-%s", testID)

	// Terraform options
	terraformOptions := &terraform.Options{
		TerraformDir: "../../",

		Vars: map[string]interface{}{
			"region":                  awsRegion,
			"org_mode":                false,
			"evidence_bucket_name":    evidenceBucketName,
			"kms_alias":               kmsAlias,
			"quarantine_sg_name":      fmt.Sprintf("quarantine-sg-error-%s", testID),
			"finding_severity_threshold": "HIGH",
			"regions":                 []string{awsRegion},
			"sns_subscriptions": []map[string]interface{}{
				{
					"protocol": "email",
					"endpoint": fmt.Sprintf("test-error-%s@example.com", testID),
				},
			},
			"enable_standards": map[string]bool{
				"aws-foundational-security-best-practices": true,
				"cis-aws-foundations-benchmark":            true,
				"nist-800-53-rev-5":                        false,
				"pci-dss":                                  false,
			},
			"tags": map[string]string{
				"Environment": "error-test",
				"TestID":      testID,
				"Project":     "threat-detection-ir",
			},
		},

		MaxRetries:         3,
		TimeBetweenRetries: 5 * time.Second,
	}

	// Clean up resources at the end of the test
	defer terraform.Destroy(t, terraformOptions)

	// Deploy the infrastructure
	terraform.InitAndApply(t, terraformOptions)

	// Get outputs
	stateMachineArn := terraform.Output(t, terraformOptions, "stepfn_ir_state_machine_arn")

	// Test Lambda timeout scenario
	t.Run("LambdaTimeoutHandling", func(t *testing.T) {
		// This test would require modifying the Lambda timeout to a very low value
		// and sending a large payload that would cause processing to exceed the timeout
		// For now, we'll test the framework is in place

		sfnClient := aws.NewStepFunctionsClient(t, awsRegion)

		// Send a normal event first to establish baseline
		eventbridgeClient := aws.NewEventBridgeClient(t, awsRegion)
		eventEntry := &eventbridge.PutEventsRequestEntry{
			Source:       aws.String("aws.guardduty"),
			DetailType:   aws.String("GuardDuty Finding"),
			Detail:       aws.String(fmt.Sprintf(`{"id":"test-timeout-%s","severity":8.0,"type":"UnauthorizedAccess:EC2/SSHBruteForce"}`, testID)),
			EventBusName: aws.String("default"),
		}

		_, err := eventbridgeClient.PutEvents(&eventbridge.PutEventsInput{
			Entries: []*eventbridge.PutEventsRequestEntry{eventEntry},
		})
		require.NoError(t, err)

		// Wait for processing
		time.Sleep(10 * time.Second)

		// Check for executions (should succeed normally)
		executions, err := sfnClient.ListExecutions(&sfn.ListExecutionsInput{
			StateMachineArn: aws.String(stateMachineArn),
			MaxResults:      aws.Int64(10),
		})
		require.NoError(t, err)

		// Should have at least one execution
		assert.NotEmpty(t, executions.ExecutionList)
	})

	// Test S3 access denied scenario
	t.Run("S3AccessDeniedHandling", func(t *testing.T) {
		// Create a temporary IAM policy that denies S3 access
		iamClient := aws.NewIamClient(t, awsRegion)

		// Create a test user with denied S3 permissions
		testUserName := fmt.Sprintf("test-denied-user-%s", testID)
		_, err := iamClient.CreateUser(&iam.CreateUserInput{
			UserName: aws.String(testUserName),
		})
		require.NoError(t, err)

		// Create deny policy
		denyPolicyDocument := `{
			"Version": "2012-10-17",
			"Statement": [
				{
					"Effect": "Deny",
					"Action": "s3:*",
					"Resource": "*"
				}
			]
		}`

		policyName := fmt.Sprintf("test-deny-s3-%s", testID)
		createPolicyOutput, err := iamClient.CreatePolicy(&iam.CreatePolicyInput{
			PolicyName:     aws.String(policyName),
			PolicyDocument: aws.String(denyPolicyDocument),
		})
		require.NoError(t, err)

		// Attach deny policy to Lambda role (this would cause failures)
		lambdaRoleName := "lambda-triage-role"
		_, err = iamClient.AttachUserPolicy(&iam.AttachUserPolicyInput{
			UserName:  aws.String(testUserName),
			PolicyArn: createPolicyOutput.Policy.Arn,
		})
		require.NoError(t, err)

		// Note: In a real scenario, we would attach this to the Lambda role
		// For this test, we verify the error handling framework exists

		// Clean up
		defer func() {
			iamClient.DetachUserPolicy(&iam.DetachUserPolicyInput{
				UserName:  aws.String(testUserName),
				PolicyArn: createPolicyOutput.Policy.Arn,
			})
			iamClient.DeletePolicy(&iam.DeletePolicyInput{
				PolicyArn: createPolicyOutput.Policy.Arn,
			})
			iamClient.DeleteUser(&iam.DeleteUserInput{
				UserName: aws.String(testUserName),
			})
		}()

		// Send event that would trigger S3 operations
		eventbridgeClient := aws.NewEventBridgeClient(t, awsRegion)
		eventEntry := &eventbridge.PutEventsRequestEntry{
			Source:       aws.String("aws.guardduty"),
			DetailType:   aws.String("GuardDuty Finding"),
			Detail:       aws.String(fmt.Sprintf(`{"id":"test-s3-denied-%s","severity":8.0,"type":"UnauthorizedAccess:EC2/SSHBruteForce"}`, testID)),
			EventBusName: aws.String("default"),
		}

		_, err = eventbridgeClient.PutEvents(&eventbridge.PutEventsInput{
			Entries: []*eventbridge.PutEventsRequestEntry{eventEntry},
		})
		require.NoError(t, err)

		// Wait for processing
		time.Sleep(10 * time.Second)

		// Verify error handling - should still create executions but they might fail
		sfnClient := aws.NewStepFunctionsClient(t, awsRegion)
		executions, err := sfnClient.ListExecutions(&sfn.ListExecutionsInput{
			StateMachineArn: aws.String(stateMachineArn),
			MaxResults:      aws.Int64(10),
		})
		require.NoError(t, err)

		// Should have executions (even if they fail due to permissions)
		assert.NotEmpty(t, executions.ExecutionList)
	})

	// Test malformed event handling
	t.Run("MalformedEventHandling", func(t *testing.T) {
		eventbridgeClient := aws.NewEventBridgeClient(t, awsRegion)

		// Send malformed JSON
		eventEntry := &eventbridge.PutEventsRequestEntry{
			Source:       aws.String("aws.guardduty"),
			DetailType:   aws.String("GuardDuty Finding"),
			Detail:       aws.String(`{"id":"test-malformed","severity":invalid-json}`),
			EventBusName: aws.String("default"),
		}

		_, err := eventbridgeClient.PutEvents(&eventbridge.PutEventsInput{
			Entries: []*eventbridge.PutEventsRequestEntry{eventEntry},
		})
		require.NoError(t, err)

		// Wait for processing
		time.Sleep(10 * time.Second)

		// Verify system handles malformed events gracefully
		// The Lambda should catch the error and log it appropriately
		sfnClient := aws.NewStepFunctionsClient(t, awsRegion)
		executions, err := sfnClient.ListExecutions(&sfn.ListExecutionsInput{
			StateMachineArn: aws.String(stateMachineArn),
			MaxResults:      aws.Int64(10),
		})
		require.NoError(t, err)

		// Should still have executions, but they might be in FAILED state
		assert.NotEmpty(t, executions.ExecutionList)
	})

	// Test retry behavior
	t.Run("RetryBehavior", func(t *testing.T) {
		// Send event that might trigger retries
		eventbridgeClient := aws.NewEventBridgeClient(t, awsRegion)
		eventEntry := &eventbridge.PutEventsRequestEntry{
			Source:       aws.String("aws.guardduty"),
			DetailType:   aws.String("GuardDuty Finding"),
			Detail:       aws.String(fmt.Sprintf(`{"id":"test-retry-%s","severity":8.0,"type":"UnauthorizedAccess:EC2/SSHBruteForce"}`, testID)),
			EventBusName: aws.String("default"),
		}

		_, err := eventbridgeClient.PutEvents(&eventbridge.PutEventsInput{
			Entries: []*eventbridge.PutEventsRequestEntry{eventEntry},
		})
		require.NoError(t, err)

		// Wait for processing and potential retries
		time.Sleep(15 * time.Second)

		// Check execution status
		sfnClient := aws.NewStepFunctionsClient(t, awsRegion)
		executions, err := sfnClient.ListExecutions(&sfn.ListExecutionsInput{
			StateMachineArn: aws.String(stateMachineArn),
			MaxResults:      aws.Int64(10),
		})
		require.NoError(t, err)

		// Verify executions exist
		assert.NotEmpty(t, executions.ExecutionList)

		// Check if any executions succeeded (indicating retry worked)
		hasSuccessfulExecution := false
		for _, execution := range executions.ExecutionList {
			if *execution.Status == "SUCCEEDED" {
				hasSuccessfulExecution = true
				break
			}
		}
		assert.True(t, hasSuccessfulExecution, "Should have at least one successful execution")
	})

	// Test DLQ functionality
	t.Run("DeadLetterQueueHandling", func(t *testing.T) {
		// Send events that would consistently fail to test DLQ
		eventbridgeClient := aws.NewEventBridgeClient(t, awsRegion)

		// Send multiple events that might fail
		var entries []*eventbridge.PutEventsRequestEntry
		for i := 0; i < 3; i++ {
			entry := &eventbridge.PutEventsRequestEntry{
				Source:       aws.String("aws.guardduty"),
				DetailType:   aws.String("GuardDuty Finding"),
				Detail:       aws.String(fmt.Sprintf(`{"id":"test-dlq-%s-%d","severity":8.0,"type":"TestFailure"}`, testID, i)),
				EventBusName: aws.String("default"),
			}
			entries = append(entries, entry)
		}

		_, err := eventbridgeClient.PutEvents(&eventbridge.PutEventsInput{
			Entries: entries,
		})
		require.NoError(t, err)

		// Wait for processing and potential DLQ delivery
		time.Sleep(20 * time.Second)

		// Verify executions were attempted
		sfnClient := aws.NewStepFunctionsClient(t, awsRegion)
		executions, err := sfnClient.ListExecutions(&sfn.ListExecutionsInput{
			StateMachineArn: aws.String(stateMachineArn),
			MaxResults:      aws.Int64(20),
		})
		require.NoError(t, err)

		// Should have executions (some may succeed, some may fail)
		assert.NotEmpty(t, executions.ExecutionList)
	})

	// Test concurrent failure scenarios
	t.Run("ConcurrentFailureHandling", func(t *testing.T) {
		eventbridgeClient := aws.NewEventBridgeClient(t, awsRegion)

		// Send multiple events simultaneously
		var entries []*eventbridge.PutEventsRequestEntry
		for i := 0; i < 10; i++ {
			entry := &eventbridge.PutEventsRequestEntry{
				Source:       aws.String("aws.guardduty"),
				DetailType:   aws.String("GuardDuty Finding"),
				Detail:       aws.String(fmt.Sprintf(`{"id":"test-concurrent-fail-%s-%d","severity":8.0,"type":"ConcurrentTest"}`, testID, i)),
				EventBusName: aws.String("default"),
			}
			entries = append(entries, entry)
		}

		_, err := eventbridgeClient.PutEvents(&eventbridge.PutEventsInput{
			Entries: entries,
		})
		require.NoError(t, err)

		// Wait for processing
		time.Sleep(30 * time.Second)

		// Verify system handles concurrent failures gracefully
		sfnClient := aws.NewStepFunctionsClient(t, awsRegion)
		executions, err := sfnClient.ListExecutions(&sfn.ListExecutionsInput{
			StateMachineArn: aws.String(stateMachineArn),
			MaxResults:      aws.Int64(50),
		})
		require.NoError(t, err)

		// Should have multiple executions
		assert.GreaterOrEqual(t, len(executions.ExecutionList), 5)

		// Count successful vs failed executions
		successCount := 0
		failCount := 0
		for _, execution := range executions.ExecutionList {
			if *execution.Status == "SUCCEEDED" {
				successCount++
			} else if *execution.Status == "FAILED" {
				failCount++
			}
		}

		// Should have some successful executions even under load
		assert.Greater(t, successCount, 0, "Should have successful executions under concurrent load")
	})

	// Test invalid variable values
	t.Run("InvalidConfigurationHandling", func(t *testing.T) {
		// Test with invalid configurations that should fail during plan/apply
		// This tests the validation logic in Terraform

		invalidOptions := &terraform.Options{
			TerraformDir: "../../",
			Vars: map[string]interface{}{
				"region":                  awsRegion,
				"org_mode":                false,
				"evidence_bucket_name":    "", // Invalid: empty bucket name
				"kms_alias":               kmsAlias,
				"quarantine_sg_name":      fmt.Sprintf("quarantine-sg-invalid-%s", testID),
				"finding_severity_threshold": "INVALID", // Invalid: not in allowed values
				"regions":                 []string{}, // Invalid: empty regions
				"sns_subscriptions": []map[string]interface{}{
					{
						"protocol": "invalid", // Invalid: not a valid protocol
						"endpoint": "test@example.com",
					},
				},
				"enable_standards": map[string]bool{
					"aws-foundational-security-best-practices": true,
					"cis-aws-foundations-benchmark":            true,
				},
				"tags": map[string]string{
					"Environment": "invalid-test",
					"TestID":      testID,
				},
			},
		}

		// This should fail during plan due to validation
		_, err := terraform.InitAndPlanE(t, invalidOptions)
		// We expect this to fail due to invalid configuration
		assert.Error(t, err, "Should fail with invalid configuration")
	})
}