// Codedeploy trigger
module "lambda_codedeploy_trigger" {
  source               = "hendrixroa/lambda/aws"
  enabled              = var.enabled
  code_location        = "${path.module}/${var.code_source}"
  filename             = "ecsTaskProvisioning.zip"
  lambda_iam_role      = aws_iam_role.lambda_elastic_queries_role.arn
  lambda_function_name = "EcsTaskProvisioning"
  lambda_runtime       = var.runtime
  timeout              = var.timeout
  memory               = var.memory
  layer_arn            = var.lambda_layer_arn

  subnets = var.subnets
  sg_ids  = [ var.security_group ]

  environment_variables = var.environment_variables
}