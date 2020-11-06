// IAM Role for ecs task provision lambda
resource "aws_iam_role" "lambda_elastic_queries_role" {
  name = "lambda_elastic_queries_role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow"
    },
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "es.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

}

data "aws_iam_policy_document" "lambda_elastic_queries" {
  statement {
    sid    = ""
    effect = "Allow"

    actions = [
      "es:ESHttpGet",
      "es:ESHttpPut",
      "es:ESHttpPost",
    ]

    resources = [
      "${var.elasticsearch_arn}/*",
    ]
  }

  statement {
    sid    = ""
    effect = "Allow"

    actions = [
      "iam:PassRole",
    ]

    resources = [aws_iam_role.lambda_elastic_queries_role.arn]
  }

  statement {
    effect = "Allow"

    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    resources = [
      "arn:aws:logs:*:*:*",
    ]
  }

  statement {
    effect = "Allow"

    actions = [
      "iam:ListAccountAliases",
    ]

    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "lambda_elastic_queries_policy" {
  name   = "lambda_elastic_queries_policy"
  role   = aws_iam_role.lambda_elastic_queries_role.id
  policy = data.aws_iam_policy_document.lambda_elastic_queries.json
}
