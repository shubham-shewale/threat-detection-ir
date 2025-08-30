import json
import boto3
import os

def lambda_handler(event, context):
    """
    Lambda function to triage GuardDuty findings.
    - Parses the event
    - Tags implicated resources
    - Stores evidence in S3
    - Triggers Step Functions for remediation
    - Publishes notification to SNS
    """
    try:
        # Parse the GuardDuty finding event
        detail = event.get('detail', {})
        finding_id = detail.get('id', 'unknown')
        severity = detail.get('severity', 0)

        print(f"Processing finding: {finding_id} with severity: {severity}")

        # Store raw event in S3 evidence bucket
        s3_client = boto3.client('s3')
        evidence_bucket = os.environ['EVIDENCE_BUCKET']
        s3_key = f'findings/{finding_id}.json'

        s3_client.put_object(
            Bucket=evidence_bucket,
            Key=s3_key,
            Body=json.dumps(event),
            ContentType='application/json'
        )
        print(f"Stored evidence in s3://{evidence_bucket}/{s3_key}")

        # Tag implicated resource if it's an EC2 instance
        resource = detail.get('resource', {})
        if resource.get('resourceType') == 'Instance':
            instance_details = resource.get('instanceDetails', {})
            instance_id = instance_details.get('instanceId')
            if instance_id:
                ec2_client = boto3.client('ec2')
                ec2_client.create_tags(
                    Resources=[instance_id],
                    Tags=[
                        {'Key': 'GuardDutyFinding', 'Value': finding_id},
                        {'Key': 'Quarantined', 'Value': 'Pending'}
                    ]
                )
                print(f"Tagged instance {instance_id} with finding {finding_id}")

        # Trigger Step Functions state machine for remediation
        state_machine_arn = os.environ['STATE_MACHINE_ARN']
        sfn_client = boto3.client('stepfunctions')
        execution_name = f'IR-{finding_id.replace("/", "-")}'

        sfn_client.start_execution(
            stateMachineArn=state_machine_arn,
            name=execution_name,
            input=json.dumps(event)
        )
        print(f"Started Step Functions execution: {execution_name}")

        # Publish notification to SNS
        sns_topic_arn = os.environ['SNS_TOPIC_ARN']
        sns_client = boto3.client('sns')

        message = {
            'finding_id': finding_id,
            'severity': severity,
            'resource_type': resource.get('resourceType'),
            'action': 'Triage completed, remediation initiated'
        }

        sns_client.publish(
            TopicArn=sns_topic_arn,
            Message=json.dumps(message),
            Subject=f'GuardDuty Finding Triage: {finding_id}'
        )
        print(f"Published notification to SNS topic")

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Triage completed successfully',
                'finding_id': finding_id
            })
        }

    except Exception as e:
        print(f"Error in triage: {str(e)}")
        raise