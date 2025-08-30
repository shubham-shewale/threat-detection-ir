output "state_machine_arn" {
  description = "ARN of the Step Functions IR state machine"
  value       = aws_sfn_state_machine.ir.arn
}