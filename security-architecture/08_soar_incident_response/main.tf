# ==============================================================================
# Layer: SOAR Incident Response & Slack ChatOps
# 構成: AWS WAF 遮断イベント / CloudWatch Alarm -> SNS -> Lambda -> Slack Block Kit
# ==============================================================================

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# ------------------------------------------------------------------------------
# 1. インシデント通知用 SNS トピック
# ------------------------------------------------------------------------------
resource "aws_sns_topic" "security_incidents" {
  name              = "security-incident-alerts"
  kms_master_key_id = var.kms_key_arn

  tags = {
    Environment = "production"
    Tier        = "Security-SOAR"
  }
}

# ------------------------------------------------------------------------------
# 2. CloudWatch Alarm: WAF によるブロック数が急増した場合のアラート
# ------------------------------------------------------------------------------
resource "aws_cloudwatch_metric_alarm" "waf_block_alarm" {
  alarm_name          = "waf-high-blocked-requests"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "BlockedRequests"
  namespace           = "AWS/WAFV2"
  period              = 60
  statistic           = "Sum"
  threshold           = 20
  alarm_description   = "Trigger SOAR alert when WAF blocks > 20 requests in 1 minute"

  dimensions = {
    WebACL = var.waf_web_acl_name
    Region = "us-east-1"
    Rule   = "ALL"
  }

  alarm_actions = [aws_sns_topic.security_incidents.arn]
}

# ------------------------------------------------------------------------------
# 3. AWS Lambda: Slack インシデント通知ディスパッチャー
# ------------------------------------------------------------------------------
resource "aws_iam_role" "soar_lambda_role" {
  name = "waf-soar-slack-dispatcher-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_policy" "soar_lambda_policy" {
  name        = "waf-soar-slack-dispatcher-policy"
  description = "Allows SOAR Lambda to write CloudWatch logs and read secrets"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = "arn:aws:secretsmanager:*:*:secret:security/slack-webhook-*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "soar_lambda_attach" {
  role       = aws_iam_role.soar_lambda_role.name
  policy_arn = aws_iam_policy.soar_lambda_policy.arn
}

resource "aws_lambda_function" "soar_notifier" {
  function_name = "waf-soar-slack-notifier"
  role          = aws_iam_role.soar_lambda_role.arn
  handler       = "bootstrap"
  runtime       = "provided.al2023"
  architectures = ["arm64"]
  timeout       = 10
  memory_size   = 128

  # ダミーコード (CI/CD で Go バイナリをパッケージングしてデプロイ)
  filename         = "${path.module}/dummy_payload.zip"
  source_code_hash = filebase64sha256("${path.module}/dummy_payload.zip")

  environment {
    variables = {
      SLACK_WEBHOOK_URL = var.slack_webhook_url
      ENVIRONMENT       = "production"
    }
  }

  tags = {
    Environment = "production"
    Tier        = "Security-SOAR"
  }
}

# ------------------------------------------------------------------------------
# 4. SNS から Lambda へのサブスクリプション & 権限付与
# ------------------------------------------------------------------------------
resource "aws_sns_topic_subscription" "lambda_sub" {
  topic_arn = aws_sns_topic.security_incidents.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.soar_notifier.arn
}

resource "aws_lambda_permission" "allow_sns" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.soar_notifier.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.security_incidents.arn
}

# ------------------------------------------------------------------------------
# 変数定義
# ------------------------------------------------------------------------------
variable "kms_key_arn" {
  type    = string
  default = "arn:aws:kms:ap-northeast-1:123456789012:key/example-kms-key-id"
}

variable "waf_web_acl_name" {
  type    = string
  default = "edge-waf-acl"
}

variable "slack_webhook_url" {
  type      = string
  sensitive = true
  default   = "https://hooks.slack.com/services/REPLACE_WITH_YOUR_SLACK_WEBHOOK"
}
