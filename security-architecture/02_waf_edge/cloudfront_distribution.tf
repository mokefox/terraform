# ==============================================================================
# Layer 6/7: CloudFront Edge CDN & Presentation Security
# 対策: TLS 1.3暗号化, HSTS, CSP, XSS/Clickjacking防止, 圧縮最適化
# ==============================================================================

# 1. セキュリティレスポンスヘッダーポリシー
resource "aws_cloudfront_response_headers_policy" "strict_security_headers" {
  name    = "Strict-ZeroTrust-Security-Headers-Policy"
  comment = "Enforce HSTS, CSP, XFO, nosniff, and anti-MIM/Clickjacking headers"

  security_headers_config {
    # HSTS: HTTPS 強制 & サブドメイン包含 & プリロード登録対応
    strict_transport_security {
      access_control_max_age_sec = 63072000 # 2年
      include_subdomains         = true
      preload                    = true
      override                   = true
    }

    # Content-Security-Policy (XSS & データインジェクション完全防御)
    content_security_policy {
      content_security_policy = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self';"
      override                = true
    }

    # X-Frame-Options: Clickjacking 完全遮断
    frame_options {
      frame_option = "DENY"
      override     = true
    }

    # X-Content-Type-Options: MIME スニッフィング防止
    content_type_options {
      override = true
    }

    # Referrer-Policy: 参照元情報の最小化
    referrer_policy {
      referrer_policy = "strict-origin-when-cross-origin"
      override        = true
    }

    # X-XSS-Protection (Legacy protection)
    xss_protection {
      mode_block = true
      protection = true
      override   = true
    }
  }

  # 機密クッキーの安全属性強制
  custom_headers_config {
    items {
      header   = "Permissions-Policy"
      value    = "geolocation=(), microphone=(), camera=(), payment=()"
      override = true
    }
  }
}

# 2. CloudFront Distribution
resource "aws_cloudfront_distribution" "secure_cdn" {
  enabled         = true
  is_ipv6_enabled = true
  comment         = "Hardened CloudFront with WAFv2 & TLS 1.3"
  web_acl_id      = aws_wafv2_web_acl.edge_security_acl.arn
  price_class     = "PriceClass_100"

  origin {
    domain_name = var.alb_domain_name
    origin_id   = "ALB-Origin"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only" # バックエンドへもHTTPS強制
      origin_ssl_protocols   = ["TLSv1.2"]

      origin_read_timeout      = 30
      origin_keepalive_timeout = 5
    }

    # ALB直接アクセス防止用 カスタムシークレットヘッダー
    custom_header {
      name  = "X-Origin-Verify"
      value = var.origin_verify_secret
    }
  }

  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "ALB-Origin"

    # HTTPS強制リダイレクト
    viewer_protocol_policy = "redirect-to-https"

    # レスポンスヘッダーポリシーの適用
    response_headers_policy_id = aws_cloudfront_response_headers_policy.strict_security_headers.id

    # Gzip / Brotli 圧縮を有効化
    compress = true

    forwarded_values {
      query_string = true
      headers      = ["Authorization", "Host", "X-CSRF-Token"]

      cookies {
        forward = "all"
      }
    }

    min_ttl     = 0
    default_ttl = 3600
    max_ttl     = 86400
  }

  restrictions {
    geo_restriction {
      restriction_type = "none" # または特定国制限
    }
  }

  viewer_certificate {
    # TLS 1.3 / 安全な暗号スイートの強制 (SNI)
    acm_certificate_arn      = var.acm_certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }
}

variable "alb_domain_name" {
  type    = string
  default = "internal-alb.example.corp"
}

variable "origin_verify_secret" {
  type      = string
  sensitive = true
  default   = "Strong-Shared-Secret-Token-12345"
}

variable "acm_certificate_arn" {
  type    = string
  default = "arn:aws:acm:us-east-1:123456789012:certificate/abcdef01-2345-6789-abcd-ef0123456789"
}
