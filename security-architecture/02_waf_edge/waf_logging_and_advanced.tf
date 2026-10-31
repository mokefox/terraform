# ==============================================================================
# Layer 7 (WAF Logging & Advanced Protection):
# 現場の必須要件: WAF監査ログの永続化, 機密ヘッダーマスキング, Bot Control, SIEM連携
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. WAF ログ保管用 S3 バケット (KMS CMK暗号化 & パブリックアクセス完全拒否)
# ------------------------------------------------------------------------------
resource "aws_kms_key" "waf_logs_cmk" {
  description             = "Customer Managed Key (CMK) for WAF audit log S3 bucket encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name        = "waf-logs-encryption-key"
    Environment = "production"
    Layer       = "Layer6-Presentation"
  }
}

resource "aws_s3_bucket" "waf_logs" {
  bucket        = "aws-waf-logs-security-hardened-corp"
  force_destroy = false

  tags = {
    DataClassification = "Confidential-Audit-Log"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "waf_logs_encryption" {
  bucket = aws_s3_bucket.waf_logs.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.waf_logs_cmk.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# パブリックアクセス完全ブロック
resource "aws_s3_bucket_public_access_block" "waf_logs_block_public" {
  bucket                  = aws_s3_bucket.waf_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ------------------------------------------------------------------------------
# 2. WAF ロギング設定 (機密データのマスキング / Redaction)
# ------------------------------------------------------------------------------
resource "aws_wafv2_web_acl_logging_configuration" "waf_logging" {
  log_destination_configs = [aws_s3_bucket.waf_logs.arn]
  resource_arn            = aws_wafv2_web_acl.edge_security_acl.arn

  # Authorization ヘッダーや Cookie など機密個人情報をログから自動マスキング
  redacted_fields {
    single_header {
      name = "authorization"
    }
  }
  redacted_fields {
    single_header {
      name = "cookie"
    }
  }
  redacted_fields {
    single_header {
      name = "x-csrf-token"
    }
  }

  # ブロックされたトラフィックのみ、または全トラフィックのフィルタリング
  logging_filter {
    default_behavior = "KEEP"

    filter {
      behavior    = "KEEP"
      requirement = "MEETS_ANY"
      condition {
        action_condition {
          action = "BLOCK"
        }
      }
      condition {
        action_condition {
          action = "COUNT"
        }
      }
    }
  }
}
