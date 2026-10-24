# ==============================================================================
# Layer 7 (DNS): Route 53 DNSSEC & Resolver Security (Terraform)
# 防御対象: DNSキャッシュポイズニング, DNSスプーフィング, 改竄攻撃
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

# 1. 権威DNSゾーンの作成
resource "aws_route53_zone" "primary" {
  name = "example.internal.security.corp"

  tags = {
    Environment = "production"
    Security    = "hardened"
  }
}

# 2. DNSSEC 署名用 AWS KMS カスタマー管理キー (ECC_NIST_P256)
resource "aws_kms_key" "dnssec_key" {
  customer_master_key_spec = "ECC_NIST_P256"
  key_usage                = "SIGN_VERIFY"
  description              = "KMS Key for Route 53 DNSSEC Key Signing Key (KSK)"
  deletion_window_in_days  = 7

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow Route 53 DNSSEC Service to Sign"
        Effect = "Allow"
        Principal = {
          Service = "dnssec-route53.amazonaws.com"
        }
        Action = [
          "kms:DescribeKey",
          "kms:GetPublicKey",
          "kms:Sign"
        ]
        Resource = "*"
      },
      {
        Sid    = "Allow Route 53 DNSSEC to create Grant"
        Effect = "Allow"
        Principal = {
          Service = "dnssec-route53.amazonaws.com"
        }
        Action   = "kms:CreateGrant"
        Resource = "*"
        Condition = {
          Bool = {
            "kms:GrantIsForAWSResource" = "true"
          }
        }
      }
    ]
  })
}

data "aws_caller_identity" "current" {}

# 3. Route 53 Key-Signing Key (KSK) の登録
resource "aws_route53_key_signing_key" "dnssec_ksk" {
  hosted_zone_id             = aws_route53_zone.primary.id
  key_management_service_arn = aws_kms_key.dnssec_key.arn
  name                       = "dnssec-ksk-example"
  status                     = "ACTIVE"
}

# 4. ホストゾーンの DNSSEC 署名の有効化（RRSIG/DNSKEYレコードの自動生成・提供）
resource "aws_route53_hosted_zone_dnssec" "dnssec_enable" {
  depends_on     = [aws_route53_key_signing_key.dnssec_ksk]
  hosted_zone_id = aws_route53_key_signing_key.dnssec_ksk.hosted_zone_id
}

# 5. Route 53 Resolver (VPC内部クライアント用 DNSSEC 検証の強制)
resource "aws_route53_resolver_config" "dnssec_validation" {
  resource_id              = var.vpc_id
  autodefined_reverse_flag = "ENABLE"
}

# DNSSEC 検証を有効にする Resolver DNSSEC Config
resource "aws_route53_resolver_dnssec_config" "vpc_dnssec" {
  resource_id = var.vpc_id
}

variable "vpc_id" {
  type        = string
  description = "Target VPC ID for DNSSEC validation"
  default     = "vpc-0123456789abcdef0"
}

output "ds_record" {
  description = "Parent Registrar (TLD) に登録するための DS レコード情報"
  value = {
    delegation_signer_number = aws_route53_key_signing_key.dnssec_ksk.dnskey_record
    ds_record                = aws_route53_key_signing_key.dnssec_ksk.ds_record
    public_key               = aws_route53_key_signing_key.dnssec_ksk.public_key
  }
}
