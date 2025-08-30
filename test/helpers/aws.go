package helpers

import (
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sfn"
)

// WaitForStepFunctionExecution waits for a Step Functions execution to complete
func WaitForStepFunctionExecution(sess *session.Session, executionArn string, timeout time.Duration) (*sfn.DescribeExecutionOutput, error) {
	sfnClient := sfn.New(sess)

	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		execution, err := sfnClient.DescribeExecution(&sfn.DescribeExecutionInput{
			ExecutionArn: aws.String(executionArn),
		})
		if err != nil {
			return nil, err
		}

		if *execution.Status == "SUCCEEDED" || *execution.Status == "FAILED" || *execution.Status == "TIMED_OUT" {
			return execution, nil
		}

		time.Sleep(2 * time.Second)
	}

	return nil, fmt.Errorf("timeout waiting for Step Functions execution to complete")
}

// PollCloudWatchLogsForPattern polls CloudWatch logs for a specific pattern
func PollCloudWatchLogsForPattern(sess *session.Session, logGroupName, pattern string, timeout time.Duration) (bool, error) {
	logsClient := cloudwatchlogs.New(sess)

	deadline := time.Now().Add(timeout)

	// Get log streams
	logStreams, err := logsClient.DescribeLogStreams(&cloudwatchlogs.DescribeLogStreamsInput{
		LogGroupName:  aws.String(logGroupName),
		OrderBy:       aws.String("LastEventTime"),
		Descending:    aws.String("true"),
		MaxResults:    aws.Int64(5),
	})
	if err != nil {
		return false, err
	}

	for time.Now().Before(deadline) {
		for _, logStream := range logStreams.LogStreams {
			// Get log events
			logEvents, err := logsClient.GetLogEvents(&cloudwatchlogs.GetLogEventsInput{
				LogGroupName:  aws.String(logGroupName),
				LogStreamName: logStream.LogStreamName,
				StartFromHead: aws.Bool(false),
				Limit:         aws.Int64(100),
			})
			if err != nil {
				continue
			}

			// Check for pattern in log events
			for _, event := range logEvents.Events {
				if event.Message != nil && strings.Contains(*event.Message, pattern) {
					return true, nil
				}
			}
		}

		time.Sleep(3 * time.Second)
	}

	return false, nil
}

// ValidateS3ObjectNaming validates S3 object naming convention
func ValidateS3ObjectNaming(sess *session.Session, bucketName, prefix string) error {
	s3Client := s3.New(sess)

	objects, err := s3Client.ListObjectsV2(&s3.ListObjectsV2Input{
		Bucket: aws.String(bucketName),
		Prefix: aws.String(prefix),
	})
	if err != nil {
		return err
	}

	expectedPattern := "findings/"
	for _, obj := range objects.Contents {
		if obj.Key != nil {
			if !strings.Contains(*obj.Key, expectedPattern) {
				return fmt.Errorf("object key %s does not match expected pattern %s", *obj.Key, expectedPattern)
			}
		}
	}

	return nil
}

// GetStepFunctionExecutionHistory gets the execution history for analysis
func GetStepFunctionExecutionHistory(sess *session.Session, executionArn string) (*sfn.GetExecutionHistoryOutput, error) {
	sfnClient := sfn.New(sess)

	history, err := sfnClient.GetExecutionHistory(&sfn.GetExecutionHistoryInput{
		ExecutionArn: aws.String(executionArn),
	})
	if err != nil {
		return nil, err
	}

	return history, nil
}

// ValidateStepFunctionStateTransitions validates state transitions in execution history
func ValidateStepFunctionStateTransitions(history *sfn.GetExecutionHistoryOutput) error {
	expectedStates := []string{"StoreEvidence", "IsolateResource", "Notify", "UpdateSecurityHub"}

	stateIndex := 0
	for _, event := range history.Events {
		if event.StateEnteredEventDetails != nil {
			stateName := *event.StateEnteredEventDetails.Name
			if stateIndex < len(expectedStates) && stateName == expectedStates[stateIndex] {
				stateIndex++
			}
		}
	}

	if stateIndex != len(expectedStates) {
		return fmt.Errorf("not all expected states were executed: got %d, expected %d", stateIndex, len(expectedStates))
	}

	return nil
}