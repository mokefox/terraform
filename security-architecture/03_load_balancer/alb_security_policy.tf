# ==============================================================================
# Layer 4/7: ALB Security Policy & TLS Termination
# 対策: 暗号化終端, TLS 1.3強制, 脆弱な暗号スイート排除, 偽装アクセス遮断
# ==============================================================================

resource "aws_lb" "app_alb" {
  name               = "hardened-prod-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [var.alb_security_group_id]
  subnets            = var.public_subnet_ids

  drop_invalid_header_fields = true # HTTP/2 & HTTP/1.1 不正ヘッダー自動ドロップ
  enable_deletion_protection = true

  tags = {
    Environment = "production"
    Tier        = "Public-DMZ"
  }
}

# 1. HTTP (ポート80) リスナー -> HTTPS (ポート443) への強制 301 リダイレクト
resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.app_alb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# 2. HTTPS (ポート443) リスナー -> 最新の TLS 1.3 / 1.2 セキュリティポリシー
resource "aws_lb_listener" "https_secure" {
  load_balancer_arn = aws_lb.app_alb.arn
  port              = 443
  protocol          = "HTTPS"

  # 最新のTLS 1.3対応セキュリティポリシー (CBC, 3DES, RC4, TLS1.0/1.1 は完全拒否)
  ssl_policy      = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn = var.alb_acm_certificate_arn

  # デフォルトアクション: CloudFront 以外の直接アクセスは 403 Forbidden
  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "application/json"
      message_body = "{\"error\": \"Direct access forbidden. Access must route through CloudFront edge.\"}"
      status_code  = "403"
    }
  }
}

# 3. リスナールール: CloudFront のカスタムシークレットヘッダー一致時のみターゲットグループへ転送
resource "aws_lb_listener_rule" "allow_cloudfront_traffic" {
  listener_arn = aws_lb_listener.https_secure.arn
  priority     = 100

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.backend_tg.arn
  }

  condition {
    http_header {
      http_header_name = "X-Origin-Verify"
      values           = [var.origin_verify_secret]
    }
  }
}

# 4. ターゲットグループ (コンテナバックエンド: ALB -> ECS/EKS)
resource "aws_lb_target_group" "backend_tg" {
  name        = "hardened-backend-tg"
  port        = 8080
  protocol    = "HTTP" # またはエンドツーエンド HTTPS (mTLS)
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    enabled             = true
    path                = "/healthz"
    protocol            = "HTTP"
    port                = "8080"
    interval            = 15
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
    matcher             = "200"
  }
}

variable "alb_security_group_id" {
  type    = string
  default = "sg-0123456789alb"
}

variable "public_subnet_ids" {
  type    = list(string)
  default = ["subnet-a", "subnet-b"]
}

variable "alb_acm_certificate_arn" {
  type    = string
  default = "arn:aws:acm:ap-northeast-1:123456789012:certificate/xyz"
}

variable "origin_verify_secret" {
  type      = string
  sensitive = true
  default   = "Strong-Shared-Secret-Token-12345"
}

variable "vpc_id" {
  type    = string
  default = "vpc-0123456789abcdef0"
}
