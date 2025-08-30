# Architecture Diagrams: AWS Threat Detection & Incident Response Stack

**Version:** 1.0.0
**Last Updated:** 2025-08-30
**Diagram Tool:** Mermaid

## 📋 Table of Contents

1. [High-Level Architecture](#high-level-architecture)
2. [Data Flow Diagram](#data-flow-diagram)
3. [Service Interaction Flow](#service-interaction-flow)
4. [Module Dependency Graph](#module-dependency-graph)
5. [Event-Driven Processing Flow](#event-driven-processing-flow)
6. [Security Control Flow](#security-control-flow)
7. [Deployment Architecture](#deployment-architecture)
8. [Failure Recovery Flow](#failure-recovery-flow)

---

## 🏗️ High-Level Architecture

```mermaid
graph TB
    subgraph "AWS Security Services"
        GD[GuardDuty<br/>Threat Detection]
        SH[Security Hub<br/>Findings Aggregation]
        CW[CloudWatch<br/>Monitoring & Alarms]
    end

    subgraph "Event Processing"
        EB[EventBridge<br/>Event Router]
        Lambda[Lambda Triage<br/>Initial Analysis]
        SFN[Step Functions<br/>Incident Response]
    end

    subgraph "Storage & Communication"
        S3[S3 Evidence<br/>Data Storage]
        SNS[SNS Alerts<br/>Notifications]
    end

    subgraph "Infrastructure"
        VPC[VPC<br/>Network Isolation]
        IAM[IAM Roles<br/>Access Control]
        KMS[KMS<br/>Encryption Keys]
    end

    GD --> EB
    SH --> EB
    EB --> Lambda
    Lambda --> SFN
    Lambda --> S3
    Lambda --> SNS
    SFN --> S3
    SFN --> SNS
    SFN --> VPC

    Lambda -.-> CW
    SFN -.-> CW
    S3 -.-> KMS
    SNS -.-> KMS

    style GD fill:#e1f5fe
    style Lambda fill:#f3e5f5
    style SFN fill:#e8f5e8
    style S3 fill:#fff3e0
```

**Key Components:**
- **GuardDuty**: AWS threat detection service
- **Security Hub**: Centralized security findings
- **EventBridge**: Event routing and filtering
- **Lambda**: Serverless compute for triage
- **Step Functions**: Orchestrated incident response
- **S3**: Evidence storage with encryption
- **SNS**: Alert notifications
- **CloudWatch**: Monitoring and logging

---

## 🔄 Data Flow Diagram

```mermaid
flowchart TD
    A[GuardDuty Finding<br/>Generated] --> B{EventBridge<br/>Rule Filter}
    B --> C{Severity<br/>Threshold Check}

    C -->|HIGH/CRITICAL| D[Route to<br/>Lambda Triage]
    C -->|LOW/MEDIUM| E[Optional: Log Only]

    D --> F[Lambda Function<br/>Invoked]
    F --> G[Parse Event<br/>Extract Details]

    G --> H[Store Evidence<br/>in S3]
    G --> I[Tag Resources<br/>EC2 Instances]
    G --> J[Trigger Step<br/>Functions]

    J --> K[Step Functions<br/>State Machine]
    K --> L{Resource<br/>Type Check}

    L -->|EC2 Instance| M[Isolate Instance<br/>Security Group]
    L -->|Other Resources| N[Custom Remediation<br/>Logic]

    M --> O[Update Security<br/>Hub Finding]
    N --> O

    O --> P[Send SNS<br/>Notification]
    P --> Q[Log to<br/>CloudWatch]

    H --> R[Evidence Stored<br/>Encrypted]
    I --> S[Resources Tagged<br/>for Tracking]

    style A fill:#ffebee
    style F fill:#e8f5e8
    style K fill:#e3f2fd
    style P fill:#fff3e0
```

**Data Flow Explanation:**
1. **Threat Detection**: GuardDuty generates findings
2. **Event Filtering**: EventBridge filters by severity
3. **Initial Triage**: Lambda parses and enriches data
4. **Evidence Storage**: Raw events stored in encrypted S3
5. **Resource Tagging**: Affected resources tagged for tracking
6. **Incident Response**: Step Functions orchestrate remediation
7. **Status Updates**: Security Hub findings updated
8. **Notifications**: Stakeholders alerted via SNS
9. **Monitoring**: All activities logged to CloudWatch

---

## 🔗 Service Interaction Flow

```mermaid
sequenceDiagram
    participant GD as GuardDuty
    participant EB as EventBridge
    participant Lambda as Lambda Triage
    participant S3 as S3 Evidence
    participant SFN as Step Functions
    participant EC2 as EC2 API
    participant SH as Security Hub
    participant SNS as SNS
    participant CW as CloudWatch

    Note over GD,CW: Threat Detection & Response Flow

    GD->>EB: Security Finding Event
    EB->>Lambda: Filtered Event (High/Critical)

    Lambda->>S3: Store Raw Evidence
    S3-->>Lambda: Confirmation

    Lambda->>EC2: Tag Affected Instance
    EC2-->>Lambda: Tagging Confirmation

    Lambda->>SFN: Start Remediation Workflow
    SFN-->>Lambda: Execution Started

    SFN->>EC2: Apply Quarantine SG
    EC2-->>SFN: Isolation Complete

    SFN->>SH: Update Finding Status
    SH-->>SFN: Status Updated

    SFN->>SNS: Send Alert Notification
    SNS-->>SFN: Notification Sent

    Lambda->>CW: Log Triage Results
    SFN->>CW: Log Remediation Steps

    Note over Lambda,CW: Parallel Processing
```

**Interaction Details:**
- **Synchronous**: EventBridge → Lambda (immediate processing)
- **Asynchronous**: Lambda → Step Functions (workflow orchestration)
- **Parallel**: Multiple services can process simultaneously
- **Idempotent**: Operations designed to be safe for retries

---

## 📦 Module Dependency Graph

```mermaid
graph TD
    subgraph "Root Module"
        RM[main.tf<br/>Module Orchestrator]
    end

    subgraph "Core Modules"
        IAM[iam_roles<br/>Access Control]
        S3[s3_evidence<br/>Data Storage]
        SNS[sns_alerts<br/>Notifications]
        NET[network_quarantine<br/>Isolation]
    end

    subgraph "Processing Modules"
        EB[eventbridge<br/>Event Routing]
        LAMBDA[lambda_triage<br/>Initial Analysis]
        SFN[stepfn_ir<br/>Response Orchestration]
    end

    subgraph "Supporting Modules"
        CW[cloudwatch<br/>Monitoring]
        GD[guardduty<br/>Threat Detection]
        SH[securityhub<br/>Findings Management]
    end

    RM --> IAM
    RM --> S3
    RM --> SNS
    RM --> NET
    RM --> CW
    RM --> GD
    RM --> SH

    IAM --> LAMBDA
    IAM --> SFN
    S3 --> LAMBDA
    S3 --> SFN
    SNS --> LAMBDA
    SNS --> SFN
    NET --> LAMBDA
    NET --> SFN
    CW --> LAMBDA
    CW --> SFN

    EB --> LAMBDA
    EB --> SFN
    LAMBDA --> EB
    SFN --> EB

    style RM fill:#e3f2fd
    style IAM fill:#f3e5f5
    style EB fill:#e8f5e8
    style LAMBDA fill:#fff3e0
```

**Dependency Relationships:**
- **Hard Dependencies**: IAM roles required by compute resources
- **Soft Dependencies**: Services can operate independently
- **Circular Dependencies**: EventBridge ↔ Lambda/Step Functions (needs resolution)
- **Optional Dependencies**: CloudWatch monitoring can be disabled

---

## ⚡ Event-Driven Processing Flow

```mermaid
stateDiagram-v2
    [*] --> ThreatDetected
    ThreatDetected --> EventBridgeFilter: GuardDuty Finding

    state EventBridgeFilter as "EventBridge Rule"
        [*] --> SeverityCheck
        SeverityCheck --> HighSeverity: HIGH/CRITICAL
        SeverityCheck --> LogOnly: LOW/MEDIUM
        HighSeverity --> [*]
        LogOnly --> [*]
    end

    EventBridgeFilter --> LambdaTriage: High Severity Event

    state LambdaTriage as "Lambda Triage Function"
        [*] --> ParseEvent
        ParseEvent --> StoreEvidence: Extract Details
        StoreEvidence --> TagResources: Identify Assets
        TagResources --> TriggerWorkflow: Start Remediation
        TriggerWorkflow --> [*]
    end

    LambdaTriage --> StepFunctions: Remediation Request

    state StepFunctions as "Step Functions State Machine"
        [*] --> AssessImpact
        AssessImpact --> IsolateResource: EC2 Instance
        AssessImpact --> CustomAction: Other Resources
        IsolateResource --> UpdateFinding
        CustomAction --> UpdateFinding
        UpdateFinding --> SendNotification
        SendNotification --> [*]
    end

    StepFunctions --> SecurityHub: Status Update
    StepFunctions --> SNS: Alert Notification
    LambdaTriage --> CloudWatch: Processing Logs

    ThreatDetected --> CloudWatch: Raw Events
    StepFunctions --> CloudWatch: Remediation Logs

    style ThreatDetected fill:#ffebee
    style LambdaTriage fill:#e8f5e8
    style StepFunctions fill:#e3f2fd
```

**State Transitions:**
1. **Detection**: GuardDuty identifies threats
2. **Filtering**: EventBridge applies severity rules
3. **Triage**: Lambda performs initial analysis
4. **Response**: Step Functions orchestrates remediation
5. **Notification**: Stakeholders alerted of actions
6. **Logging**: All activities recorded for audit

---

## 🔒 Security Control Flow

```mermaid
flowchart TD
    A[Security Event<br/>Detected] --> B{Authentication<br/>Check}
    B -->|Valid| C{Authorization<br/>Check}
    B -->|Invalid| D[Access Denied<br/>Log Event]

    C -->|Authorized| E{Input<br/>Validation}
    C -->|Unauthorized| F[Access Denied<br/>Alert Security]

    E -->|Valid| G{Encryption<br/>Required}
    E -->|Invalid| H[Input Rejected<br/>Log & Alert]

    G -->|Yes| I[Encrypt Data<br/>KMS]
    G -->|No| J[Process Data<br/>Plaintext]

    I --> K{Data<br/>Classification}
    J --> K

    K -->|Sensitive| L[Store in Encrypted<br/>S3 Bucket]
    K -->|Public| M[Store with<br/>Access Controls]

    L --> N{Least Privilege<br/>Access}
    M --> N

    N -->|Granted| O[Allow Operation<br/>Audit Log]
    N -->|Denied| P[Access Denied<br/>Security Alert]

    O --> Q{Compliance<br/>Check}
    Q -->|Pass| R[Operation<br/>Successful]
    Q -->|Fail| S[Compliance Violation<br/>Block & Alert]

    style A fill:#ffebee
    style D fill:#ffcdd2
    style F fill:#ffcdd2
    style P fill:#ffcdd2
    style S fill:#ffcdd2
    style R fill:#e8f5e8
```

**Security Layers:**
1. **Authentication**: Verify request origin
2. **Authorization**: Check permissions
3. **Input Validation**: Sanitize data
4. **Encryption**: Protect data at rest/transit
5. **Access Control**: Least privilege enforcement
6. **Compliance**: Regulatory requirement validation
7. **Auditing**: All actions logged and monitored

---

## 🚀 Deployment Architecture

```mermaid
graph TB
    subgraph "Development"
        DEV[Developer<br/>Workstation]
        GIT[Git Repository<br/>Code Storage]
        TF_LOCAL[Terraform Local<br/>Validation]
    end

    subgraph "CI/CD Pipeline"
        GH[GitHub Actions<br/>Workflow]
        TF_CLOUD[Terraform Cloud<br/>State Management]
        CHECKOV[Checkov<br/>Security Scan]
        TFSEC[TFSec<br/>Policy Check]
    end

    subgraph "AWS Environments"
        STAGING[Staging Environment<br/>Pre-Production]
        PROD[Production Environment<br/>Live System]
    end

    subgraph "Staging Resources"
        STG_GD[GuardDuty<br/>Test Findings]
        STG_EB[EventBridge<br/>Test Rules]
        STG_LAMBDA[Lambda<br/>Test Functions]
        STG_S3[S3<br/>Test Buckets]
    end

    subgraph "Production Resources"
        PROD_GD[GuardDuty<br/>Live Monitoring]
        PROD_EB[EventBridge<br/>Production Rules]
        PROD_LAMBDA[Lambda<br/>Production Functions]
        PROD_S3[S3<br/>Production Buckets]
    end

    DEV --> GIT
    GIT --> GH
    GH --> CHECKOV
    GH --> TFSEC
    CHECKOV --> TF_CLOUD
    TFSEC --> TF_CLOUD
    TF_CLOUD --> STAGING
    TF_CLOUD --> PROD

    STAGING --> STG_GD
    STAGING --> STG_EB
    STAGING --> STG_LAMBDA
    STAGING --> STG_S3

    PROD --> PROD_GD
    PROD --> PROD_EB
    PROD --> PROD_LAMBDA
    PROD --> PROD_S3

    style DEV fill:#e3f2fd
    style GH fill:#e8f5e8
    style STAGING fill:#fff3e0
    style PROD fill:#e8f5e8
```

**Deployment Flow:**
1. **Development**: Local testing and validation
2. **CI/CD**: Automated security scanning and testing
3. **Staging**: Pre-production validation
4. **Production**: Live deployment with monitoring

---

## 🔄 Failure Recovery Flow

```mermaid
flowchart TD
    A[Service Failure<br/>Detected] --> B{Error Type<br/>Check}

    B -->|Lambda Timeout| C[Check CloudWatch<br/>Logs]
    B -->|Step Function Error| D[Check State Machine<br/>Execution]
    B -->|S3 Access Denied| E[Validate IAM<br/>Permissions]
    B -->|SNS Delivery Fail| F[Check Topic<br/>Policy]

    C --> G{Retry<br/>Possible}
    D --> G
    E --> G
    F --> G

    G -->|Yes| H[Automatic Retry<br/>with Backoff]
    G -->|No| I[Manual Intervention<br/>Required]

    H --> J{Retry<br/>Successful}
    J -->|Yes| K[Resume Normal<br/>Operation]
    J -->|No| I

    I --> L[Alert On-Call<br/>Engineer]
    L --> M[Diagnose Root<br/>Cause]
    M --> N{Resolution<br/>Path}

    N -->|Code Fix| O[Deploy Hotfix<br/>to Staging]
    N -->|Config Change| P[Update Terraform<br/>Variables]
    N -->|Service Issue| Q[Escalate to<br/>AWS Support]

    O --> R[Test Fix in<br/>Staging]
    P --> R
    Q --> S[AWS Resolution<br/>Timeline]

    R --> T{Fix<br/>Validated}
    T -->|Yes| U[Deploy to<br/>Production]
    T -->|No| V[Iterate Fix<br/>Process]

    U --> K
    S --> K

    style A fill:#ffebee
    style I fill:#ffcdd2
    style L fill:#ffcdd2
    style K fill:#e8f5e8
```

**Recovery Mechanisms:**
1. **Automatic Retries**: Exponential backoff for transient failures
2. **Circuit Breakers**: Prevent cascade failures
3. **Manual Intervention**: Complex issues require human analysis
4. **Rollback Procedures**: Quick reversion to stable state
5. **Monitoring Integration**: Proactive failure detection

---

## 📊 Metrics & Monitoring Dashboard

```mermaid
graph LR
    subgraph "Application Metrics"
        AM1[Event Processing<br/>Latency]
        AM2[Error Rate<br/>Percentage]
        AM3[Throughput<br/>Events/Minute]
        AM4[Success Rate<br/>Percentage]
    end

    subgraph "Infrastructure Metrics"
        IM1[Lambda Duration<br/>Milliseconds]
        IM2[Step Function<br/>Executions]
        IM3[S3 Storage<br/>Usage GB]
        IM4[SNS Messages<br/>Delivered]
    end

    subgraph "Security Metrics"
        SM1[IAM Policy<br/>Violations]
        SM2[Encryption<br/>Failures]
        SM3[Access Denied<br/>Events]
        SM4[Compliance<br/>Drift]
    end

    subgraph "Business Metrics"
        BM1[MTTR<br/>Minutes]
        BM2[MTTD<br/>Minutes]
        BM3[False Positive<br/>Rate]
        BM4[Incident<br/>Volume]
    end

    AM1 --> DASH[Monitoring<br/>Dashboard]
    AM2 --> DASH
    AM3 --> DASH
    AM4 --> DASH

    IM1 --> DASH
    IM2 --> DASH
    IM3 --> DASH
    IM4 --> DASH

    SM1 --> DASH
    SM2 --> DASH
    SM3 --> DASH
    SM4 --> DASH

    BM1 --> DASH
    BM2 --> DASH
    BM3 --> DASH
    BM4 --> DASH

    DASH --> ALERTS[Alerting<br/>System]
    ALERTS --> TEAMS[Response<br/>Teams]

    style DASH fill:#e3f2fd
    style ALERTS fill:#fff3e0
    style TEAMS fill:#e8f5e8
```

**Dashboard Components:**
- **Real-time Metrics**: Current system health
- **Historical Trends**: Performance over time
- **Alert Thresholds**: Automated notifications
- **Incident Correlation**: Related event analysis

---

## 🎯 Key Insights from Diagrams

### Architecture Strengths
1. **Event-Driven Design**: Loose coupling between services
2. **Serverless First**: Cost-effective and scalable
3. **Defense in Depth**: Multiple security layers
4. **Observability**: Comprehensive monitoring integration

### Potential Improvements
1. **Circuit Breakers**: Add between services for resilience
2. **Event Sourcing**: Store all events for audit trails
3. **Multi-Region**: Cross-region replication for DR
4. **Auto-Scaling**: Dynamic resource allocation

### Operational Considerations
1. **Cost Monitoring**: Serverless can scale unexpectedly
2. **Cold Starts**: Lambda initialization delays
3. **Event Ordering**: Ensure sequential processing when needed
4. **Rate Limiting**: Protect against event storms

---

## 📖 Usage Examples

### Normal Operation Flow
```
GuardDuty Finding → EventBridge → Lambda Triage → Step Functions → Resolution
```

### Error Recovery Flow
```
Service Failure → CloudWatch Alarm → SNS Alert → On-Call Response → Investigation → Fix → Deployment
```

### Security Incident Flow
```
Threat Detected → Automated Response → Manual Verification → Incident Closure → Post-Mortem
```

These diagrams provide a comprehensive view of the AWS threat detection and incident response stack, showing how each component interacts and contributes to the overall security posture.