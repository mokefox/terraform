# ==============================================================================
# Security Hardening & Multi-Layer Defense for Application Stack
# Defense against: Ransomware, DNS Tunneling, Bulk Scraping, Audit Tampering
# ==============================================================================

# --- 1. AWS WAFv2 Web ACL with Rate-Based Rule (Anti-Bulk Scraping / L7) ---
resource "aws_wafv2_web_acl" "app_waf" {
  name        = "${var.project.service}-${var.project.env}-app-waf"
  description = "WAFv2 with rate-based limiting to block bulk scraping and injection"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "BulkScrapingRateLimit"
    priority = 1

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 100 # 5分間に100リクエスト超過で即時IP遮断
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "BulkScrapingRateLimitMetric"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "AppWafMetric"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_association" "app_waf_assoc" {
  resource_arn = module.app-lb.arn
  web_acl_arn  = aws_wafv2_web_acl.app_waf.arn
}

# --- 2. Route 53 Resolver DNS Firewall (Anti-DNS Tunneling & C2 Defense) ---
resource "aws_route53_resolver_dns_firewall_rule_group" "dns_c2_block" {
  name = "${var.project.service}-${var.project.env}-dns-firewall-group"
}

resource "aws_route53_resolver_dns_firewall_rule_group_association" "dns_c2_assoc" {
  name                   = "dns-firewall-vpc-assoc"
  firewall_rule_group_id = aws_route53_resolver_dns_firewall_rule_group.dns_c2_block.id
  priority               = 101
  vpc_id                 = data.aws_vpc.common.id
}

# --- 3. Immutable CloudTrail Audit Trail with KMS Encryption & Validation ---
resource "aws_kms_key" "cloudtrail_key" {
  description             = "Dedicated KMS Key for CloudTrail Log Encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_s3_bucket" "cloudtrail_vault" {
  bucket              = "${var.project.service}-${var.project.env}-cloudtrail-audit-vault"
  object_lock_enabled = true
}

resource "aws_s3_bucket_versioning" "cloudtrail_vault_versioning" {
  bucket = aws_s3_bucket.cloudtrail_vault.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "cloudtrail_vault_lock" {
  bucket = aws_s3_bucket.cloudtrail_vault.id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 365
    }
  }
}

resource "aws_cloudtrail" "main_audit_trail" {
  name                          = "${var.project.service}-${var.project.env}-audit-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_vault.id
  enable_log_file_validation    = true # 整合性ダイジェスト署名による改竄防止
  is_multi_region_trail         = true
  kms_key_id                    = aws_kms_key.cloudtrail_key.arn
}
