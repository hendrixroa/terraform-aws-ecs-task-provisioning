// Cloudwatch event rule to detect state Provisioning for alerting stuff
resource "aws_cloudwatch_event_rule" "ecs_provisioning_rule" {
  name        = "ecs_provisioning_rule"
  description = "Event rule to capture ecs provisioning for alerting stuff"

  event_pattern = var.event_pattern
}

resource "aws_cloudwatch_event_target" "ecs_provisioning_target" {
  rule      = aws_cloudwatch_event_rule.ecs_provisioning_rule.name
  target_id = "ecs_provisioning_target"
  arn       = module.lambda_ecs_task_provisioning.lambda_arn
}

resource "aws_lambda_permission" "allow_invocation_provisioning" {
  statement_id  = "AllowExecutionEcsProvisioning"
  action        = "lambda:InvokeFunction"
  function_name = module.lambda_ecs_task_provisioning.lambda_arn
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.ecs_provisioning_rule.arn
}