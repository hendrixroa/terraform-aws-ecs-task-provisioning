// Cloudwatch event rule to detect state Provisioning for alerting stuff
resource "aws_cloudwatch_event_rule" "ecs_provisioning_rule" {
  name        = "ecs_provisioning_rule"
  description = "Event rule to capture ecs provisioning for alerting stuff"

  event_pattern = <<PATTERN
{
  "source": [
    "aws.ecs"
  ],
  "detail-type": [
    "ECS Task State Change"
  ],
  "detail": {
    "clusterArn": ${var.ecs_clusters_arn},
    "lastStatus": [
      "PROVISIONING"
    ]
  }
}
PATTERN

}

resource "aws_cloudwatch_event_target" "ecs_provisioning_target" {
  rule      = aws_cloudwatch_event_rule.ecs_provisioning_rule.name
  target_id = "ecs_provisioning_target"
  arn       = module.lambda_codedeploy_trigger.lambda_arn
}

resource "aws_lambda_permission" "allow_invocation_provisioning" {
  statement_id  = "AllowExecutionEcsProvisioning"
  action        = "lambda:InvokeFunction"
  function_name = module.lambda_codedeploy_trigger.lambda_arn
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.ecs_provisioning_rule.arn
}