package test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/eventbridge"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sfn"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/gruntwork-io/terratest/modules/aws"
	"github.com/gruntwork-io/terratest/modules/random"
	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGuardDutyFlowEndToEnd(t *testing.T) {
	t.Parallel()

	// Generate unique test ID
	testID := random.UniqueId()
	testName := fmt.Sprintf("threat-detection-ir-e2e-%s", testID)

	// Test configurations
	awsRegion := "us-east-1"
	evidenceBucketName := fmt.Sprintf("ir-evidence-e2e-%s", testID)
	kmsAlias := fmt.Sprintf("alias/ir-evidence-e2e-%s", testID)

	// Terraform options
	terraformOptions := &terraform.Options{
		TerraformDir: "../../",

		Vars: map[string]interface{}{
			"region":                  awsRegion,
			"org_mode":                false,
			"evidence_bucket_name":    evidenceBucketName,
			"kms_alias":               kmsAlias,
			"quarantine_sg_name":      fmt.Sprintf("quarantine-sg-e2e-%s", testID),
			"finding_severity_threshold": "HIGH",
			"regions":                 []string{awsRegion},
			"sns_subscriptions": []map[string]interface{}{
				{
					"protocol": "email",
					"endpoint": fmt.Sprintf("test-%s@example.com", testID),
				},
			},
			"enable_standards": map[string]bool{
				"aws-foundational-security-best-practices": true,
				"cis-aws-foundations-benchmark":            true,
				"nist-800-53-rev-5":                        false,
				"pci-dss":                                  false,
			},
			"tags": map[string]string{
				"Environment": "e2e-test",
				"TestID":      testID,
				"Project":     "threat-detection-ir",
			},
		},

		// Set the maximum number of retries for retryable errors
		MaxRetries:         3,
		TimeBetweenRetries: 5 * time.Second,

		// Set a reasonable timeout
		RetryableTerraformErrors: map[string]string{
			".*": "Retry on any error",
		},
	}

	// Clean up resources at the end of the test
	defer terraform.Destroy(t, terraformOptions)

	// Deploy the infrastructure
	terraform.InitAndApply(t, terraformOptions)

	// Get outputs
	lambdaFunctionName := terraform.Output(t, terraformOptions, "lambda_triage_function_name")
	stateMachineArn := terraform.Output(t, terraformOptions, "stepfn_ir_state_machine_arn")
	snsTopicArn := terraform.Output(t, terraformOptions, "sns_topic_arn")
	evidenceBucket := terraform.Output(t, terraformOptions, "s3_evidence_bucket_name")

	// Validate infrastructure deployment
	t.Run("InfrastructureValidation", func(t *testing.T) {
		// Verify Lambda function exists
		lambdaClient := aws.NewLambdaClient(t, awsRegion)
		function, err := lambdaClient.GetFunction(&lambda.GetFunctionInput{
			FunctionName: aws.String(lambdaFunctionName),
		})
		require.NoError(t, err)
		assert.Equal(t, lambdaFunctionName, *function.Configuration.FunctionName)
		assert.Equal(t, "python3.9", *function.Configuration.Runtime)

		// Verify Step Functions state machine exists
		sfnClient := aws.NewStepFunctionsClient(t, awsRegion)
		stateMachine, err := sfnClient.DescribeStateMachine(&sfn.DescribeStateMachineInput{
			StateMachineArn: aws.String(stateMachineArn),
		})
		require.NoError(t, err)
		assert.Contains(t, *stateMachine.Name, "guardduty-ir")

		// Verify S3 bucket exists and is encrypted
		s3Client := aws.NewS3Client(t, awsRegion)
		encryption, err := s3Client.GetBucketEncryption(&s3.GetBucketEncryptionInput{
			Bucket: aws.String(evidenceBucket),
		})
		require.NoError(t, err)
		assert.NotEmpty(t, encryption.ServerSideEncryptionConfiguration)

		// Verify SNS topic exists
		snsClient := aws.NewSnsClient(t, awsRegion)
		topicAttributes, err := snsClient.GetTopicAttributes(&sns.GetTopicAttributesInput{
			TopicArn: aws.String(snsTopicArn),
		})
		require.NoError(t, err)
		assert.NotEmpty(t, topicAttributes.Attributes)
	})

	// Test GuardDuty finding flow
	t.Run("GuardDutyFindingFlow", func(t *testing.T) {
		// Create sample GuardDuty finding events
		testFindings := []map[string]interface{}{
			{
				"id":        fmt.Sprintf("test-finding-high-%s", testID),
				"severity":  8.5,
				"type":      "UnauthorizedAccess:EC2/SSHBruteForce",
				"resource": map[string]interface{}{
					"resourceType": "Instance",
					"instanceDetails": map[string]interface{}{
						"instanceId": fmt.Sprintf("i-test%s", testID),
					},
				},
			},
			{
				"id":        fmt.Sprintf("test-finding-critical-%s", testID),
				"severity":  9.5,
				"type":      "Recon:EC2/Portscan",
				"resource": map[string]interface{}{
					"resourceType": "Instance",
					"instanceDetails": map[string]interface{}{
						"instanceId": fmt.Sprintf("i-test-critical-%s", testID),
					},
				},
			},
		}

		for _, finding := range testFindings {
			t.Run(fmt.Sprintf("Finding_%s", finding["id"].(string)), func(t *testing.T) {
				// Send test event to EventBridge
				eventbridgeClient := aws.NewEventBridgeClient(t, awsRegion)

				eventDetail := map[string]interface{}{
					"id":       finding["id"],
					"severity": finding["severity"],
					"type":     finding["type"],
					"resource": finding["resource"],
				}

				eventEntry := &eventbridge.PutEventsRequestEntry{
					Source:       aws.String("aws.guardduty"),
					DetailType:   aws.String("GuardDuty Finding"),
					Detail:       aws.String(fmt.Sprintf(`{"id":"%s","severity":%v,"type":"%s","resource":{"resourceType":"%s"}}`, finding["id"], finding["severity"], finding["type"], finding["resource"].(map[string]interface{})["resourceType"])),
					EventBusName: aws.String("default"),
				}

				_, err := eventbridgeClient.PutEvents(&eventbridge.PutEventsInput{
					Entries: []*eventbridge.PutEventsRequestEntry{eventEntry},
				})
				require.NoError(t, err)

				// Wait for processing
				time.Sleep(10 * time.Second)

				// Verify evidence stored in S3
				s3Client := aws.NewS3Client(t, awsRegion)
				objects, err := s3Client.ListObjectsV2(&s3.ListObjectsV2Input{
					Bucket: aws.String(evidenceBucket),
					Prefix: aws.String("findings/"),
				})
				require.NoError(t, err)

				// Should have at least one evidence object
				assert.NotEmpty(t, objects.Contents)

				// Verify Lambda was invoked (check CloudWatch logs)
				logsClient := aws.NewCloudWatchLogsClient(t, awsRegion)
				logGroupName := fmt.Sprintf("/aws/lambda/%s", lambdaFunctionName)

				// Get log streams
				logStreams, err := logsClient.DescribeLogStreams(&cloudwatchlogs.DescribeLogStreamsInput{
					LogGroupName:  aws.String(logGroupName),
					OrderBy:       aws.String("LastEventTime"),
					Descending:    aws.String("true"),
					MaxResults:    aws.Int64(1),
				})
				require.NoError(t, err)

				if len(logStreams.LogStreams) > 0 {
					// Get log events
					logEvents, err := logsClient.GetLogEvents(&cloudwatchlogs.GetLogEventsInput{
						LogGroupName:  aws.String(logGroupName),
						LogStreamName: logStreams.LogStreams[0].LogStreamName,
						StartFromHead: aws.Bool(false),
						Limit:         aws.Int64(100),
					})

					if err == nil && len(logEvents.Events) > 0 {
						// Check for processing logs
						foundProcessingLog := false
						for _, event := range logEvents.Events {
							if event.Message != nil && strings.Contains(*event.Message, "Processing finding") {
								foundProcessingLog = true
								break
							}
						}
						assert.True(t, foundProcessingLog, "Should find processing log for the finding")
					}
				}

				// Verify Step Functions execution was started
				sfnClient := aws.NewStepFunctionsClient(t, awsRegion)
				executions, err := sfnClient.ListExecutions(&sfn.ListExecutionsInput{
					StateMachineArn: aws.String(stateMachineArn),
					StatusFilter:    aws.String("SUCCEEDED"),
					MaxResults:      aws.Int64(10),
				})
				require.NoError(t, err)

				// Should have at least one successful execution
				assert.NotEmpty(t, executions.ExecutionList)

				// Verify execution details
				if len(executions.ExecutionList) > 0 {
					executionArn := executions.ExecutionList[0].ExecutionArn
					execution, err := sfnClient.DescribeExecution(&sfn.DescribeExecutionInput{
						ExecutionArn: executionArn,
					})
					require.NoError(t, err)

					// Execution should have completed successfully
					assert.Equal(t, "SUCCEEDED", *execution.Status)

					// Check execution output contains expected fields
					if execution.Output != nil {
						output := *execution.Output
						assert.Contains(t, output, "evidence")
						assert.Contains(t, output, "isolation")
						assert.Contains(t, output, "notification")
					}
				}
			})
		}
	})

	// Test low severity finding (should not trigger)
	t.Run("LowSeverityFindingIgnored", func(t *testing.T) {
		eventbridgeClient := aws.NewEventBridgeClient(t, awsRegion)

		eventEntry := &eventbridge.PutEventsRequestEntry{
			Source:       aws.String("aws.guardduty"),
			DetailType:   aws.String("GuardDuty Finding"),
			Detail:       aws.String(fmt.Sprintf(`{"id":"test-finding-low-%s","severity":3.0,"type":"Recon:EC2/PortProbeUnprotectedPort"}`, testID)),
			EventBusName: aws.String("default"),
		}

		_, err := eventbridgeClient.PutEvents(&eventbridge.PutEventsInput{
			Entries: []*eventbridge.PutEventsRequestEntry{eventEntry},
		})
		require.NoError(t, err)

		// Wait for processing
		time.Sleep(5 * time.Second)

		// Verify no new Step Functions executions (low severity should be ignored)
		sfnClient := aws.NewStepFunctionsClient(t, awsRegion)
		executions, err := sfnClient.ListExecutions(&sfn.ListExecutionsInput{
			StateMachineArn: aws.String(stateMachineArn),
			MaxResults:      aws.Int64(20),
		})
		require.NoError(t, err)

		// Count executions from this test (should be same as before)
		initialExecutionCount := len(executions.ExecutionList)

		// Wait a bit more and check again
		time.Sleep(5 * time.Second)
		executions, err = sfnClient.ListExecutions(&sfn.ListExecutionsInput{
			StateMachineArn: aws.String(stateMachineArn),
			MaxResults:      aws.Int64(20),
		})
		require.NoError(t, err)

		// Should not have new executions for low severity
		assert.Equal(t, initialExecutionCount, len(executions.ExecutionList))
	})

	// Test concurrent events
	t.Run("ConcurrentEvents", func(t *testing.T) {
		eventbridgeClient := aws.NewEventBridgeClient(t, awsRegion)

		// Send multiple events concurrently
		var entries []*eventbridge.PutEventsRequestEntry
		for i := 0; i < 5; i++ {
			entry := &eventbridge.PutEventsRequestEntry{
				Source:       aws.String("aws.guardduty"),
				DetailType:   aws.String("GuardDuty Finding"),
				Detail:       aws.String(fmt.Sprintf(`{"id":"test-concurrent-%s-%d","severity":8.0,"type":"UnauthorizedAccess:EC2/SSHBruteForce"}`, testID, i)),
				EventBusName: aws.String("default"),
			}
			entries = append(entries, entry)
		}

		_, err := eventbridgeClient.PutEvents(&eventbridge.PutEventsInput{
			Entries: entries,
		})
		require.NoError(t, err)

		// Wait for processing
		time.Sleep(15 * time.Second)

		// Verify all events were processed
		sfnClient := aws.NewStepFunctionsClient(t, awsRegion)
		executions, err := sfnClient.ListExecutions(&sfn.ListExecutionsInput{
			StateMachineArn: aws.String(stateMachineArn),
			StatusFilter:    aws.String("SUCCEEDED"),
			MaxResults:      aws.Int64(20),
		})
		require.NoError(t, err)

		// Should have at least 5 more successful executions
		assert.GreaterOrEqual(t, len(executions.ExecutionList), 5)
	})

	// Test evidence storage structure
	t.Run("EvidenceStorageStructure", func(t *testing.T) {
		s3Client := aws.NewS3Client(t, awsRegion)

		// List all evidence objects
		objects, err := s3Client.ListObjectsV2(&s3.ListObjectsV2Input{
			Bucket: aws.String(evidenceBucket),
			Prefix: aws.String("findings/"),
		})
		require.NoError(t, err)

		// Verify object naming convention
		for _, obj := range objects.Contents {
			assert.Contains(t, *obj.Key, "findings/")
			assert.Contains(t, *obj.Key, ".json")

			// Verify object is not empty
			assert.Greater(t, *obj.Size, int64(0))
		}

		// Verify encryption on objects
		if len(objects.Contents) > 0 {
			headObject, err := s3Client.HeadObject(&s3.HeadObjectInput{
				Bucket: aws.String(evidenceBucket),
				Key:    objects.Contents[0].Key,
			})
			require.NoError(t, err)

			// Should have server-side encryption
			assert.NotEmpty(t, headObject.ServerSideEncryption)
		}
	})
}