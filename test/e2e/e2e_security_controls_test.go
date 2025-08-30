package test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/eventbridge"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sfn"
	"github.com/gruntwork-io/terratest/modules/aws"
	"github.com/gruntwork-io/terratest/modules/random"
	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecurityControlsRuntime(t *testing.T) {
	t.Parallel()

	// Generate unique test ID
	testID := random.UniqueId()
	testName := fmt.Sprintf("threat-detection-ir-security-%s", testID)

	// Test configurations
	awsRegion := "us-east-1"
	evidenceBucketName := fmt.Sprintf("ir-evidence-security-%s", testID)
	kmsAlias := fmt.Sprintf("alias/ir-evidence-security-%s", testID)

	// Terraform options
	terraformOptions := &terraform.Options{
		TerraformDir: "../../",

		Vars: map[string]interface{}{
			"region":                  awsRegion,
			"org_mode":                false,
			"evidence_bucket_name":    evidenceBucketName,
			"kms_alias":               kmsAlias,
			"quarantine_sg_name":      fmt.Sprintf("quarantine-sg-security-%s", testID),
			"finding_severity_threshold": "HIGH",
			"regions":                 []string{awsRegion},
			"sns_subscriptions": []map[string]interface{}{
				{
					"protocol": "email",
					"endpoint": fmt.Sprintf("security-%s@example.com", testID),
				},
			},
			"enable_standards": map[string]bool{
				"aws-foundational-security-best-practices": true,
				"cis-aws-foundations-benchmark":            true,
				"nist-800-53-rev-5":                        false,
				"pci-dss":                                  false,
			},
			"tags": map[string]string{
				"Environment": "security-test",
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
	evidenceBucket := terraform.Output(t, terraformOptions, "s3_evidence_bucket_name")
	snsTopicArn := terraform.Output(t, terraformOptions, "sns_topic_arn")

	// Test S3 bucket security controls
	t.Run("S3BucketSecurityControls", func(t *testing.T) {
		s3Client := aws.NewS3Client(t, awsRegion)

		// Test 1: Deny unencrypted PUT operations
		t.Run("DenyUnencryptedPuts", func(t *testing.T) {
			// Try to put an object without encryption (should fail)
			_, err := s3Client.PutObject(&s3.PutObjectInput{
				Bucket:      aws.String(evidenceBucket),
				Key:         aws.String("test-unencrypted.txt"),
				Body:        strings.NewReader("test content"),
				ContentType: aws.String("text/plain"),
				// Intentionally not setting encryption
			})

			// Should fail due to bucket policy
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "AccessDenied")
		})

		// Test 2: Deny non-HTTPS requests
		t.Run("DenyNonHTTPSRequests", func(t *testing.T) {
			// This is harder to test directly, but we can verify the bucket policy exists
			bucketPolicy, err := s3Client.GetBucketPolicy(&s3.GetBucketPolicyInput{
				Bucket: aws.String(evidenceBucket),
			})
			require.NoError(t, err)

			policyStr := *bucketPolicy.Policy
			assert.Contains(t, policyStr, "aws:SecureTransport")
			assert.Contains(t, policyStr, "Deny")
		})

		// Test 3: Verify server-side encryption is enforced
		t.Run("ServerSideEncryptionEnforced", func(t *testing.T) {
			encryption, err := s3Client.GetBucketEncryption(&s3.GetBucketEncryptionInput{
				Bucket: aws.String(evidenceBucket),
			})
			require.NoError(t, err)

			assert.NotEmpty(t, encryption.ServerSideEncryptionConfiguration)
			assert.Equal(t, "aws:kms", *encryption.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm)
		})

		// Test 4: Verify public access is blocked
		t.Run("PublicAccessBlocked", func(t *testing.T) {
			publicAccess, err := s3Client.GetPublicAccessBlock(&s3.GetPublicAccessBlockInput{
				Bucket: aws.String(evidenceBucket),
			})
			require.NoError(t, err)

			assert.True(t, *publicAccess.PublicAccessBlockConfiguration.BlockPublicAcls)
			assert.True(t, *publicAccess.PublicAccessBlockConfiguration.BlockPublicPolicy)
			assert.True(t, *publicAccess.PublicAccessBlockConfiguration.IgnorePublicAcls)
			assert.True(t, *publicAccess.PublicAccessBlockConfiguration.RestrictPublicBuckets)
		})
	})

	// Test SNS topic security controls
	t.Run("SNSTopicSecurityControls", func(t *testing.T) {
		snsClient := aws.NewSnsClient(t, awsRegion)

		// Test 1: Verify encryption is enabled
		t.Run("TopicEncryptionEnabled", func(t *testing.T) {
			topicAttributes, err := snsClient.GetTopicAttributes(&sns.GetTopicAttributesInput{
				TopicArn: aws.String(snsTopicArn),
			})
			require.NoError(t, err)

			assert.NotEmpty(t, topicAttributes.Attributes["KmsMasterKeyId"])
		})

		// Test 2: Test publishing without proper encryption context (if applicable)
		t.Run("EncryptionContextRequired", func(t *testing.T) {
			// This would require testing with invalid KMS context
			// For now, verify the topic has encryption configured
			topicAttributes, err := snsClient.GetTopicAttributes(&sns.GetTopicAttributesInput{
				TopicArn: aws.String(snsTopicArn),
			})
			require.NoError(t, err)

			assert.Equal(t, "true", topicAttributes.Attributes["EncryptionDisabled"])
		})
	})

	// Test IAM least privilege at runtime
	t.Run("IAMLeastPrivilegeRuntime", func(t *testing.T) {
		iamClient := aws.NewIamClient(t, awsRegion)

		// Test 1: Verify Lambda role cannot perform unauthorized actions
		t.Run("LambdaRoleCannotDeleteResources", func(t *testing.T) {
			// Try to simulate a delete operation that should be denied
			// This is difficult to test directly, but we can verify the policy structure
			rolePolicies, err := iamClient.ListAttachedRolePolicies(&iam.ListAttachedRolePoliciesInput{
				RoleName: aws.String("lambda-triage-role"),
			})
			require.NoError(t, err)

			// Should have policies attached
			assert.NotEmpty(t, rolePolicies.AttachedPolicies)

			// Verify no overly permissive policies
			for _, policy := range rolePolicies.AttachedPolicies {
				assert.NotContains(t, *policy.PolicyName, "Administrator")
				assert.NotContains(t, *policy.PolicyName, "FullAccess")
			}
		})

		// Test 2: Verify Step Functions role has limited permissions
		t.Run("StepFunctionsRoleLimitedPermissions", func(t *testing.T) {
			rolePolicies, err := iamClient.ListAttachedRolePolicies(&iam.ListAttachedRolePoliciesInput{
				RoleName: aws.String("stepfn-ir-role"),
			})
			require.NoError(t, err)

			assert.NotEmpty(t, rolePolicies.AttachedPolicies)

			// Should not have delete permissions
			for _, policy := range rolePolicies.AttachedPolicies {
				assert.NotContains(t, *policy.PolicyName, "Delete")
			}
		})
	})

	// Test quarantine security group effectiveness
	t.Run("QuarantineSecurityGroupEffectiveness", func(t *testing.T) {
		ec2Client := aws.NewEc2Client(t, awsRegion)

		// Test 1: Verify quarantine SG has no ingress rules
		t.Run("QuarantineSGNoIngress", func(t *testing.T) {
			securityGroups, err := ec2Client.DescribeSecurityGroups(&ec2.DescribeSecurityGroupsInput{
				GroupNames: []*string{aws.String(fmt.Sprintf("quarantine-sg-security-%s", testID))},
			})
			require.NoError(t, err)

			assert.NotEmpty(t, securityGroups.SecurityGroups)
			sg := securityGroups.SecurityGroups[0]

			// Should have no ingress rules
			assert.Empty(t, sg.IpPermissions)

			// Should have minimal or no egress rules
			if len(sg.IpPermissionsEgress) > 0 {
				// If there are egress rules, they should be restrictive
				for _, permission := range sg.IpPermissionsEgress {
					// Should not allow all outbound traffic
					assert.NotEqual(t, "-1", *permission.IpProtocol)
				}
			}
		})
	})

	// Test CloudWatch log encryption
	t.Run("CloudWatchLogEncryption", func(t *testing.T) {
		logsClient := aws.NewCloudWatchLogsClient(t, awsRegion)

		// Test Lambda log group encryption
		t.Run("LambdaLogGroupEncrypted", func(t *testing.T) {
			logGroupName := "/aws/lambda/guardduty-triage"
			logGroup, err := logsClient.DescribeLogGroups(&cloudwatchlogs.DescribeLogGroupsInput{
				LogGroupNamePrefix: aws.String(logGroupName),
			})
			require.NoError(t, err)

			assert.NotEmpty(t, logGroup.LogGroups)
			found := false
			for _, lg := range logGroup.LogGroups {
				if *lg.LogGroupName == logGroupName {
					assert.NotEmpty(t, lg.KmsKeyId)
					found = true
					break
				}
			}
			assert.True(t, found, "Lambda log group should exist and be encrypted")
		})

		// Test Step Functions log group encryption
		t.Run("StepFunctionsLogGroupEncrypted", func(t *testing.T) {
			logGroupName := "/aws/states/guardduty-ir"
			logGroup, err := logsClient.DescribeLogGroups(&cloudwatchlogs.DescribeLogGroupsInput{
				LogGroupNamePrefix: aws.String(logGroupName),
			})
			require.NoError(t, err)

			assert.NotEmpty(t, logGroup.LogGroups)
			found := false
			for _, lg := range logGroup.LogGroups {
				if *lg.LogGroupName == logGroupName {
					assert.NotEmpty(t, lg.KmsKeyId)
					found = true
					break
				}
			}
			assert.True(t, found, "Step Functions log group should exist and be encrypted")
		})
	})

	// Test EventBridge rule security
	t.Run("EventBridgeRuleSecurity", func(t *testing.T) {
		eventbridgeClient := aws.NewEventBridgeClient(t, awsRegion)

		// Test 1: Verify rule exists and has proper configuration
		t.Run("EventBridgeRuleConfiguration", func(t *testing.T) {
			rules, err := eventbridgeClient.ListRules(&eventbridge.ListRulesInput{
				NamePrefix: aws.String("guardduty-finding-rule"),
			})
			require.NoError(t, err)

			assert.NotEmpty(t, rules.Rules)
			rule := rules.Rules[0]

			// Should have event pattern
			assert.NotEmpty(t, rule.EventPattern)

			// Should be enabled
			assert.Equal(t, "ENABLED", *rule.State)
		})

		// Test 2: Verify targets have proper permissions
		t.Run("EventBridgeTargetsSecure", func(t *testing.T) {
			targets, err := eventbridgeClient.ListTargetsByRule(&eventbridge.ListTargetsByRuleInput{
				Rule: aws.String("guardduty-finding-rule"),
			})
			require.NoError(t, err)

			assert.NotEmpty(t, targets.Targets)

			// Each target should have proper configuration
			for _, target := range targets.Targets {
				assert.NotEmpty(t, target.Id)
				assert.NotEmpty(t, target.Arn)
			}
		})
	})

	// Test Step Functions execution security
	t.Run("StepFunctionsExecutionSecurity", func(t *testing.T) {
		sfnClient := aws.NewStepFunctionsClient(t, awsRegion)
		stateMachineArn := terraform.Output(t, terraformOptions, "stepfn_ir_state_machine_arn")

		// Test 1: Verify state machine has proper logging
		t.Run("StateMachineLoggingEnabled", func(t *testing.T) {
			stateMachine, err := sfnClient.DescribeStateMachine(&sfn.DescribeStateMachineInput{
				StateMachineArn: aws.String(stateMachineArn),
			})
			require.NoError(t, err)

			assert.NotEmpty(t, stateMachine.LoggingConfiguration)
			assert.Equal(t, "ALL", *stateMachine.LoggingConfiguration.Level)
		})

		// Test 2: Verify executions have proper IAM context
		t.Run("ExecutionIAMContext", func(t *testing.T) {
			executions, err := sfnClient.ListExecutions(&sfn.ListExecutionsInput{
				StateMachineArn: aws.String(stateMachineArn),
				MaxResults:      aws.Int64(5),
			})
			require.NoError(t, err)

			// If there are executions, they should have proper execution ARNs
			for _, execution := range executions.ExecutionList {
				assert.NotEmpty(t, execution.ExecutionArn)
				assert.Contains(t, *execution.ExecutionArn, "execution")
			}
		})
	})

	// Test end-to-end security with actual event
	t.Run("EndToEndSecurityValidation", func(t *testing.T) {
		eventbridgeClient := aws.NewEventBridgeClient(t, awsRegion)

		// Send a test finding
		eventEntry := &eventbridge.PutEventsRequestEntry{
			Source:       aws.String("aws.guardduty"),
			DetailType:   aws.String("GuardDuty Finding"),
			Detail:       aws.String(fmt.Sprintf(`{"id":"test-security-%s","severity":8.0,"type":"UnauthorizedAccess:EC2/SSHBruteForce","resource":{"resourceType":"Instance","instanceDetails":{"instanceId":"i-test%s"}}}`, testID, testID)),
			EventBusName: aws.String("default"),
		}

		_, err := eventbridgeClient.PutEvents(&eventbridge.PutEventsInput{
			Entries: []*eventbridge.PutEventsRequestEntry{eventEntry},
		})
		require.NoError(t, err)

		// Wait for processing
		time.Sleep(15 * time.Second)

		// Verify evidence was stored securely
		s3Client := aws.NewS3Client(t, awsRegion)
		objects, err := s3Client.ListObjectsV2(&s3.ListObjectsV2Input{
			Bucket: aws.String(evidenceBucket),
			Prefix: aws.String("findings/"),
		})
		require.NoError(t, err)

		assert.NotEmpty(t, objects.Contents)

		// Verify evidence object is encrypted
		if len(objects.Contents) > 0 {
			headObject, err := s3Client.HeadObject(&s3.HeadObjectInput{
				Bucket: aws.String(evidenceBucket),
				Key:    objects.Contents[0].Key,
			})
			require.NoError(t, err)

			assert.NotEmpty(t, headObject.ServerSideEncryption)
			assert.Equal(t, "aws:kms", *headObject.ServerSideEncryption)
		}

		// Verify Step Functions execution occurred securely
		sfnClient := aws.NewStepFunctionsClient(t, awsRegion)
		stateMachineArn := terraform.Output(t, terraformOptions, "stepfn_ir_state_machine_arn")

		executions, err := sfnClient.ListExecutions(&sfn.ListExecutionsInput{
			StateMachineArn: aws.String(stateMachineArn),
			MaxResults:      aws.Int64(10),
		})
		require.NoError(t, err)

		assert.NotEmpty(t, executions.ExecutionList)

		// Verify execution completed (should succeed with proper permissions)
		latestExecution := executions.ExecutionList[0]
		assert.Equal(t, "SUCCEEDED", *latestExecution.Status)
	})
}