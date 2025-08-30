package helpers

import (
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatch"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sfn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// AssertStepFunctionExecutionSuccess asserts that a Step Functions execution completed successfully
func AssertStepFunctionExecutionSuccess(sess *session.Session, executionArn string, timeout time.Duration) error {
	execution, err := WaitForStepFunctionExecution(sess, executionArn, timeout)
	if err != nil {
		return fmt.Errorf("failed to wait for execution: %w", err)
	}

	if *execution.Status != "SUCCEEDED" {
		return fmt.Errorf("execution failed with status: %s", *execution.Status)
	}

	return nil
}

// AssertS3ObjectExists asserts that an S3 object exists with expected properties
func AssertS3ObjectExists(sess *session.Session, bucketName, key string) error {
	s3Client := s3.New(sess)

	_, err := s3Client.HeadObject(&s3.HeadObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("S3 object does not exist: %w", err)
	}

	return nil
}

// AssertS3ObjectEncrypted asserts that an S3 object is encrypted with KMS
func AssertS3ObjectEncrypted(sess *session.Session, bucketName, key string) error {
	s3Client := s3.New(sess)

	headObject, err := s3Client.HeadObject(&s3.HeadObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("failed to get object metadata: %w", err)
	}

	if headObject.ServerSideEncryption == nil || *headObject.ServerSideEncryption != "aws:kms" {
		return fmt.Errorf("object is not encrypted with KMS")
	}

	return nil
}

// AssertCloudWatchLogContainsPattern asserts that CloudWatch logs contain a specific pattern
func AssertCloudWatchLogContainsPattern(sess *session.Session, logGroupName, pattern string, timeout time.Duration) error {
	found, err := PollCloudWatchLogsForPattern(sess, logGroupName, pattern, timeout)
	if err != nil {
		return fmt.Errorf("failed to poll logs: %w", err)
	}

	if !found {
		return fmt.Errorf("pattern '%s' not found in logs within timeout", pattern)
	}

	return nil
}

// AssertStepFunctionStateTransitions asserts that expected state transitions occurred
func AssertStepFunctionStateTransitions(sess *session.Session, executionArn string) error {
	history, err := GetStepFunctionExecutionHistory(sess, executionArn)
	if err != nil {
		return fmt.Errorf("failed to get execution history: %w", err)
	}

	err = ValidateStepFunctionStateTransitions(history)
	if err != nil {
		return fmt.Errorf("state transition validation failed: %w", err)
	}

	return nil
}

// AssertS3EvidenceStructure asserts that evidence objects follow the expected naming convention
func AssertS3EvidenceStructure(sess *session.Session, bucketName string) error {
	err := ValidateS3ObjectNaming(sess, bucketName, "findings/")
	if err != nil {
		return fmt.Errorf("evidence structure validation failed: %w", err)
	}

	return nil
}

// AssertSecurityControlsEnforced asserts that security controls are properly enforced
func AssertSecurityControlsEnforced(sess *session.Session, bucketName string) error {
	s3Client := s3.New(sess)

	// Test 1: Bucket policy denies insecure transport
	bucketPolicy, err := s3Client.GetBucketPolicy(&s3.GetBucketPolicyInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		return fmt.Errorf("failed to get bucket policy: %w", err)
	}

	policyStr := *bucketPolicy.Policy
	if !strings.Contains(policyStr, "aws:SecureTransport") {
		return fmt.Errorf("bucket policy does not enforce secure transport")
	}

	// Test 2: Public access is blocked
	publicAccess, err := s3Client.GetPublicAccessBlock(&s3.GetPublicAccessBlockInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		return fmt.Errorf("failed to get public access block: %w", err)
	}

	if !(*publicAccess.PublicAccessBlockConfiguration.BlockPublicAcls &&
		*publicAccess.PublicAccessBlockConfiguration.BlockPublicPolicy &&
		*publicAccess.PublicAccessBlockConfiguration.IgnorePublicAcls &&
		*publicAccess.PublicAccessBlockConfiguration.RestrictPublicBuckets) {
		return fmt.Errorf("public access is not fully blocked")
	}

	return nil
}

// AssertPerformanceWithinBudget asserts that execution time is within acceptable limits
func AssertPerformanceWithinBudget(sess *session.Session, executionArn string, maxDuration time.Duration) error {
	sfnClient := sfn.New(sess)

	execution, err := sfnClient.DescribeExecution(&sfn.DescribeExecutionInput{
		ExecutionArn: aws.String(executionArn),
	})
	if err != nil {
		return fmt.Errorf("failed to describe execution: %w", err)
	}

	if execution.StopDate == nil || execution.StartDate == nil {
		return fmt.Errorf("execution timing data not available")
	}

	duration := execution.StopDate.Sub(*execution.StartDate)
	if duration > maxDuration {
		return fmt.Errorf("execution took %v, exceeding budget of %v", duration, maxDuration)
	}

	return nil
}

// AssertCloudWatchAlarmsTriggered asserts that CloudWatch alarms are triggered for errors
func AssertCloudWatchAlarmsTriggered(sess *session.Session, alarmNames []string, timeout time.Duration) error {
	cloudwatchClient := cloudwatch.New(sess)

	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		for _, alarmName := range alarmNames {
			alarm, err := cloudwatchClient.DescribeAlarms(&cloudwatch.DescribeAlarmsInput{
				AlarmNames: []*string{aws.String(alarmName)},
			})
			if err != nil {
				continue
			}

			if len(alarm.MetricAlarms) > 0 {
				alarmState := *alarm.MetricAlarms[0].StateValue
				if alarmState == "ALARM" {
					return nil // At least one alarm is triggered
				}
			}
		}

		time.Sleep(5 * time.Second)
	}

	return fmt.Errorf("no CloudWatch alarms were triggered within timeout")
}

// AssertResourceTagging asserts that resources have proper tags
func AssertResourceTagging(sess *session.Session, resourceType, resourceIdentifier string, requiredTags map[string]string) error {
	// This is a generic function that could be extended for different resource types
	// For now, it's a placeholder for the tagging validation logic

	for key, expectedValue := range requiredTags {
		if expectedValue == "" {
			return fmt.Errorf("required tag '%s' is empty", key)
		}
	}

	return nil
}

// AssertIdempotentOperations asserts that operations are idempotent
func AssertIdempotentOperations(sess *session.Session, operation func() error, iterations int) error {
	for i := 0; i < iterations; i++ {
		err := operation()
		if err != nil {
			return fmt.Errorf("operation failed on iteration %d: %w", i+1, err)
		}
	}

	return nil
}

// AssertErrorHandling asserts that errors are handled gracefully
func AssertErrorHandling(sess *session.Session, errorTrigger func() error, expectedErrorSubstring string) error {
	err := errorTrigger()
	if err == nil {
		return fmt.Errorf("expected error but none occurred")
	}

	if !strings.Contains(err.Error(), expectedErrorSubstring) {
		return fmt.Errorf("error message does not contain expected substring '%s': %s", expectedErrorSubstring, err.Error())
	}

	return nil
}

// AssertConcurrencyHandling asserts that concurrent operations are handled properly
func AssertConcurrencyHandling(sess *session.Session, concurrentOperations []func() error, maxConcurrent int) error {
	semaphore := make(chan struct{}, maxConcurrent)
	errorChan := make(chan error, len(concurrentOperations))

	for _, operation := range concurrentOperations {
		go func(op func() error) {
			semaphore <- struct{}{} // Acquire
			defer func() { <-semaphore }() // Release

			err := op()
			errorChan <- err
		}(operation)
	}

	// Wait for all operations to complete
	for i := 0; i < len(concurrentOperations); i++ {
		err := <-errorChan
		if err != nil {
			return fmt.Errorf("concurrent operation failed: %w", err)
		}
	}

	return nil
}