package helpers

import (
	"encoding/json"
	"fmt"
)

// GuardDutyFinding represents a GuardDuty finding event
type GuardDutyFinding struct {
	ID       string                 `json:"id"`
	Severity float64                `json:"severity"`
	Type     string                 `json:"type"`
	Resource map[string]interface{} `json:"resource"`
	Details  map[string]interface{} `json:"details,omitempty"`
}

// SampleGuardDutyEvents provides realistic GuardDuty finding samples
var SampleGuardDutyEvents = map[string]GuardDutyFinding{
	"high-severity-ssh-brute-force": {
		ID:       "sample-finding-001",
		Severity: 8.5,
		Type:     "UnauthorizedAccess:EC2/SSHBruteForce",
		Resource: map[string]interface{}{
			"resourceType": "Instance",
			"instanceDetails": map[string]interface{}{
				"instanceId":    "i-1234567890abcdef0",
				"instanceType":  "t3.micro",
				"launchTime":    "2023-08-30T10:00:00Z",
				"platform":      "Linux/Unix",
				"networkInterfaces": []map[string]interface{}{
					{
						"networkInterfaceId": "eni-12345678",
						"privateIpAddress":   "10.0.1.100",
						"publicIp":           "203.0.113.1",
					},
				},
			},
		},
	},

	"critical-severity-port-scan": {
		ID:       "sample-finding-002",
		Severity: 9.5,
		Type:     "Recon:EC2/Portscan",
		Resource: map[string]interface{}{
			"resourceType": "Instance",
			"instanceDetails": map[string]interface{}{
				"instanceId":   "i-0987654321fedcba0",
				"instanceType": "t3.small",
				"launchTime":   "2023-08-30T11:00:00Z",
				"platform":     "Linux/Unix",
			},
		},
	},

	"medium-severity-suspicious-login": {
		ID:       "sample-finding-003",
		Severity: 6.0,
		Type:     "UnauthorizedAccess:EC2/MaliciousIPCaller",
		Resource: map[string]interface{}{
			"resourceType": "Instance",
			"instanceDetails": map[string]interface{}{
				"instanceId":   "i-abcdef1234567890",
				"instanceType": "t3.medium",
				"launchTime":   "2023-08-30T12:00:00Z",
				"platform":     "Linux/Unix",
			},
		},
	},

	"low-severity-info-finding": {
		ID:       "sample-finding-004",
		Severity: 2.0,
		Type:     "Recon:EC2/PortProbeUnprotectedPort",
		Resource: map[string]interface{}{
			"resourceType": "Instance",
			"instanceDetails": map[string]interface{}{
				"instanceId":   "i-fedcba0987654321",
				"instanceType": "t3.large",
				"launchTime":   "2023-08-30T13:00:00Z",
				"platform":     "Linux/Unix",
			},
		},
	},

	"s3-malware-finding": {
		ID:       "sample-finding-005",
		Severity: 8.0,
		Type:     "Trojan:EC2/BlackholeTraffic",
		Resource: map[string]interface{}{
			"resourceType": "Instance",
			"instanceDetails": map[string]interface{}{
				"instanceId":   "i-malwaresample123",
				"instanceType": "t3.micro",
				"launchTime":   "2023-08-30T14:00:00Z",
				"platform":     "Linux/Unix",
			},
		},
	},

	"rds-suspicious-activity": {
		ID:       "sample-finding-006",
		Severity: 7.5,
		Type:     "Discovery:S3/MaliciousIPCaller",
		Resource: map[string]interface{}{
			"resourceType": "S3Bucket",
			"s3BucketDetails": map[string]interface{}{
				"bucketName": "compromised-bucket",
				"ownerId":    "123456789012",
			},
		},
	},
}

// GetSampleEventBySeverity returns a sample event for the specified severity
func GetSampleEventBySeverity(severity string) (GuardDutyFinding, error) {
	switch severity {
	case "HIGH":
		return SampleGuardDutyEvents["high-severity-ssh-brute-force"], nil
	case "CRITICAL":
		return SampleGuardDutyEvents["critical-severity-port-scan"], nil
	case "MEDIUM":
		return SampleGuardDutyEvents["medium-severity-suspicious-login"], nil
	case "LOW":
		return SampleGuardDutyEvents["low-severity-info-finding"], nil
	default:
		return GuardDutyFinding{}, fmt.Errorf("unknown severity: %s", severity)
	}
}

// GenerateEventBridgeEvent creates a full EventBridge event from a GuardDuty finding
func GenerateEventBridgeEvent(finding GuardDutyFinding) (map[string]interface{}, error) {
	event := map[string]interface{}{
		"source":      "aws.guardduty",
		"detail-type": "GuardDuty Finding",
		"detail": map[string]interface{}{
			"id":       finding.ID,
			"severity": finding.Severity,
			"type":     finding.Type,
			"resource": finding.Resource,
		},
	}

	if finding.Details != nil {
		event["detail"].(map[string]interface{})["details"] = finding.Details
	}

	return event, nil
}

// GenerateEventBridgeEventJSON creates a JSON string for EventBridge
func GenerateEventBridgeEventJSON(finding GuardDutyFinding) (string, error) {
	event, err := GenerateEventBridgeEvent(finding)
	if err != nil {
		return "", err
	}

	jsonBytes, err := json.Marshal(event)
	if err != nil {
		return "", err
	}

	return string(jsonBytes), nil
}

// GetEventsBySeverityRange returns events within a severity range
func GetEventsBySeverityRange(minSeverity, maxSeverity float64) []GuardDutyFinding {
	var results []GuardDutyFinding

	for _, finding := range SampleGuardDutyEvents {
		if finding.Severity >= minSeverity && finding.Severity <= maxSeverity {
			results = append(results, finding)
		}
	}

	return results
}

// GetEventsByResourceType returns events for a specific resource type
func GetEventsByResourceType(resourceType string) []GuardDutyFinding {
	var results []GuardDutyFinding

	for _, finding := range SampleGuardDutyEvents {
		if resType, ok := finding.Resource["resourceType"].(string); ok && resType == resourceType {
			results = append(results, finding)
		}
	}

	return results
}

// GenerateBulkEvents creates multiple events for load testing
func GenerateBulkEvents(count int, severity string) ([]GuardDutyFinding, error) {
	baseFinding, err := GetSampleEventBySeverity(severity)
	if err != nil {
		return nil, err
	}

	var events []GuardDutyFinding
	for i := 0; i < count; i++ {
		finding := baseFinding
		finding.ID = fmt.Sprintf("%s-bulk-%d", baseFinding.ID, i)
		events = append(events, finding)
	}

	return events, nil
}

// MalformedEventSamples provides examples of malformed events for error testing
var MalformedEventSamples = map[string]string{
	"invalid-json": `{
		"source": "aws.guardduty",
		"detail-type": "GuardDuty Finding",
		"detail": {
			"id": "test-malformed",
			"severity": invalid-json
		}
	}`,

	"missing-required-fields": `{
		"source": "aws.guardduty",
		"detail-type": "GuardDuty Finding",
		"detail": {}
	}`,

	"wrong-source": `{
		"source": "aws.ec2",
		"detail-type": "GuardDuty Finding",
		"detail": {
			"id": "test-wrong-source",
			"severity": 8.0
		}
	}`,

	"empty-detail": `{
		"source": "aws.guardduty",
		"detail-type": "GuardDuty Finding",
		"detail": null
	}`,
}