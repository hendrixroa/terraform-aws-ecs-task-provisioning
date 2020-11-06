variable "lambda_layer_arn" {
  description = "Lambda layer ARN"
}

variable "timeout" {
  default = 300
}

variable "memory" {
  default = 356
}

variable "subnets" {
  default = []
}

variable "security_group" {
  default = []
}

variable "environment_variables" {}

variable "runtime" {
  default = "nodejs10.x"
}

variable "ecs_clusters_arn" {
  default = []
}

variable "elasticsearch_arn" {}