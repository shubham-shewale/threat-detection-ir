output "topic_arn" {
  description = "ARN of the SNS topic for IR alerts"
  value       = aws_sns_topic.alerts.arn
}