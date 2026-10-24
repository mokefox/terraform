# ==============================================================================
# Layer 3/4 (Network Audit & Host Identity Hardening):
# 現場の必須要件: IMDSv2強制 (SSRF対策), VPC Flow Logs (監査), Pod Identity (最小IAM)
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. IMDSv2 (Instance Metadata Service v2) 強制設定 (Launch Template)
#    コンテナ侵害時にホストのEC2メタデータ/IAMロールが盗まれる (SSRF) のを防御
# ------------------------------------------------------------------------------
resource "aws_launch_template" "hardened_node_template" {
  name_prefix   = "eks-hardened-node-"
  image_id      = "ami-0123456789abcdef0"
  instance_type = "m6i.large"

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 を必須化 (IMDSv1の平文GETを拒否)
    http_put_response_hop_limit = 1          # Hop Limit を 1 に制限 (コンテナからのIMDSアクセス遮断)
    instance_metadata_tags      = "disabled"
  }

  monitoring {
    enabled = true
  }

  network_interfaces {
    associate_public_ip_address = false
    security_groups             = [aws_security_group.app_container_sg.id]
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      SecurityStandard = "CIS-AWS-Benchmark-v1.4"
    }
  }
}

# ------------------------------------------------------------------------------
# 2. VPC Flow Logs (全ネットワークトラフィック監査・拒否パケット分析)
# ------------------------------------------------------------------------------
resource "aws_flow_log" "vpc_traffic_log" {
  iam_role_arn    = aws_iam_role.flow_log_role.arn
  log_destination = aws_cloudwatch_log_group.vpc_flow_logs.arn
  traffic_type    = "ALL" # REJECT および ACCEPT の全記録
  vpc_id          = var.vpc_id
}

resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  name              = "/aws/vpc/flow-logs-hardened"
  retention_in_days = 90
  kms_key_id        = var.kms_key_arn # 暗号化
}

resource "aws_iam_role" "flow_log_role" {
  name = "flow-log-delivery-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "flow_log_policy" {
  name = "flow-log-delivery-policy"
  role = aws_iam_role.flow_log_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

# ------------------------------------------------------------------------------
# 3. EKS Pod Identity / IRSA (IAM Roles for Service Accounts)
#    Pod 単位での最小権限付与 (ノード全体の権限肥大化を完全防止)
# ------------------------------------------------------------------------------
resource "aws_iam_role" "app_pod_role" {
  name = "secure-app-pod-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/oidc.eks.ap-northeast-1.amazonaws.com/id/EXAMPLE"
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "oidc.eks.ap-northeast-1.amazonaws.com/id/EXAMPLE:sub" = "system:serviceaccount:production:secure-app-sa"
          }
        }
      }
    ]
  })
}

# Pod が必要とする最小のアクセス権限のみを付与 (例: S3バケット1つのみ)
resource "aws_iam_policy" "app_minimal_policy" {
  name        = "app-minimal-least-privilege-policy"
  description = "Strict least-privilege IAM policy for Go backend pod"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = "arn:aws:secretsmanager:ap-northeast-1:*:secret:app/production/*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "app_pod_attach" {
  role       = aws_iam_role.app_pod_role.name
  policy_arn = aws_iam_policy.app_minimal_policy.arn
}

data "aws_caller_identity" "current" {}

variable "kms_key_arn" {
  type    = string
  default = "arn:aws:kms:ap-northeast-1:123456789012:key/example-kms-key-id"
}

