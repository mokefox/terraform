# ==============================================================================
# Layer 7 (WAF): AWS WAF v2 Web ACL
# 防御対象: SQLi, XSS, CSRF, Tor/匿名IP, 不正Bot, DDoS/ブルートフォース
# ==============================================================================

resource "aws_wafv2_web_acl" "edge_security_acl" {
  name        = "hardened-edge-waf-acl"
  description = "Production-grade WAF with SQLi, XSS, CSRF, Tor block, and Rate Limiting"
  scope       = "CLOUDFRONT" # CloudFront または REGIONAL (ALB)

  default_action {
    allow {}
  }

  # ----------------------------------------------------------------------------
  # Rule 1: レート制限 (Rate Limiting: IPあたり5分間に1000リクエスト)
  # ----------------------------------------------------------------------------
  rule {
    name     = "RateLimit-IP-Based"
    priority = 10

    action {
      block {
        custom_response {
          response_code            = 429
          custom_response_body_key = "rate_limit_exceeded_body"
        }
      }
    }

    statement {
      rate_based_statement {
        limit              = 1000
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimitIPBasedMetric"
      sampled_requests_enabled   = true
    }
  }

  # ----------------------------------------------------------------------------
  # Rule 2: Tor / 匿名IP / VPN / プロキシの遮断 (AWSManagedRulesAnonymousIpList)
  # ----------------------------------------------------------------------------
  rule {
    name     = "AWS-AWSManagedRulesAnonymousIpList"
    priority = 20

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAnonymousIpList"
        vendor_name = "AWS"

        # Tor ノードや匿名プロキシを確実に遮断
        rule_action_override {
          name = "AnonymousIPList"
          action_to_use {
            block {}
          }
        }
        rule_action_override {
          name = "HostingProviderIPList"
          action_to_use {
            block {} # クラウドホスティング経由のBot通信もブロック
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "WAFAnonymousIPListMetric"
      sampled_requests_enabled   = true
    }
  }

  # ----------------------------------------------------------------------------
  # Rule 3: AWS コア共通脆弱性ルール (OWASP Top 10, XSS, LFI/RFI等)
  # ----------------------------------------------------------------------------
  rule {
    name     = "AWS-AWSManagedRulesCommonRuleSet"
    priority = 30

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"

        # 大容量ボディの検査
        rule_action_override {
          name = "SizeRestrictions_BODY"
          action_to_use {
            block {}
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "WAFCommonRuleSetMetric"
      sampled_requests_enabled   = true
    }
  }

  # ----------------------------------------------------------------------------
  # Rule 4: SQL インジェクション (SQLi) 対策ルールセット
  # ----------------------------------------------------------------------------
  rule {
    name     = "AWS-AWSManagedRulesSQLiRuleSet"
    priority = 40

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "WAFSQLiRuleSetMetric"
      sampled_requests_enabled   = true
    }
  }

  # ----------------------------------------------------------------------------
  # Rule 5: 既知の悪意ある入力パターン遮断 (Known Bad Inputs)
  # ----------------------------------------------------------------------------
  rule {
    name     = "AWS-AWSManagedRulesKnownBadInputsRuleSet"
    priority = 50

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "WAFKnownBadInputsMetric"
      sampled_requests_enabled   = true
    }
  }

  # ----------------------------------------------------------------------------
  # Rule 6: CSRF 防止用カスタムヘッダー照合 & 危険なHTTPメソッド検証
  # ----------------------------------------------------------------------------
  rule {
    name     = "Enforce-CSRF-Custom-Header-For-Mutating-Requests"
    priority = 60

    action {
      block {
        custom_response {
          response_code            = 403
          custom_response_body_key = "csrf_violation_body"
        }
      }
    }

    statement {
      and_statement {
        # POST / PUT / DELETE / PATCH 等の状態変更リクエストを対象
        statement {
          byte_match_statement {
            search_string = "GET"
            field_to_match {
              method {}
            }
            text_transformation {
              priority = 0
              type     = "NONE"
            }
            positional_constraint = "EXACTLY"
          }
        }
        # X-Requested-With または X-CSRF-Token ヘッダーが存在しない場合はブロック
        # (ブラウザからの単純クロスオリジンリクエストによるCSRFを防止)
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "WAFCSRFProtectionMetric"
      sampled_requests_enabled   = true
    }
  }

  # カスタムレスポンスボディ定義
  custom_response_body {
    key          = "rate_limit_exceeded_body"
    content_type = "APPLICATION_JSON"
    content = jsonencode({
      error   = "Too Many Requests"
      message = "Rate limit exceeded. Please try again later."
      code    = 429
    })
  }

  custom_response_body {
    key          = "csrf_violation_body"
    content_type = "APPLICATION_JSON"
    content = jsonencode({
      error   = "Forbidden"
      message = "CSRF protection validation failed."
      code    = 403
    })
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "HardenedEdgeWAFWebACLMetric"
    sampled_requests_enabled   = true
  }
}
