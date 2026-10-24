# ==============================================================================
# Layer 7 (DNS Additional): CAA Record & Route 53 DNS Firewall
# 現場の必須要件: 不正CAによる証明書偽造防止 & マルウェアC2へのDNS名前解決遮断
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. CAA (Certification Authority Authorization) レコード
#    許可されたCA (例: Amazon Trust Services, Let's Encrypt) 以外の証明書発行を拒否
# ------------------------------------------------------------------------------
resource "aws_route53_record" "caa" {
  zone_id = aws_route53_zone.primary.zone_id
  name    = "example.internal.security.corp"
  type    = "CAA"
  ttl     = 300

  records = [
    "0 issue \"amazon.com\"",                        # 単一ドメイン証明書の発行を Amazon Trust Services に限定
    "0 issuewild \";\"",                             # ワイルドカード証明書の発行を完全禁止 (安全のため)
    "0 iodef \"mailto:security-alert@example.corp\"" # 違反した発行試行があった場合の通知先
  ]
}

# ------------------------------------------------------------------------------
# 2. Route 53 Resolver DNS Firewall (VPC アウトバウンドDNS保護)
#    コンテナが侵害された際、C2サーバや不正ドメインへの名前解決を即座にブロック
# ------------------------------------------------------------------------------
resource "aws_route53_resolver_firewall_rule_group" "vpc_dns_firewall" {
  name = "hardened-vpc-dns-firewall"
  tags = {
    Environment = "production"
  }
}

# 悪意ある C2 / ボットネット通信を遮断するドメインリスト
resource "aws_route53_resolver_firewall_domain_list" "malware_domain_list" {
  name    = "blocked-malware-c2-domains"
  domains = ["malicious-c2.evil.com.", "botnet-command.xyz."]
  tags = {
    Environment = "production"
  }
}

# ドメインリストに基づくブロックルール
resource "aws_route53_resolver_firewall_rule" "block_malware_domains" {
  name                    = "BlockMalwareDomains"
  action                  = "BLOCK"
  block_response          = "NODATA"
  firewall_rule_group_id  = aws_route53_resolver_firewall_rule_group.vpc_dns_firewall.id
  firewall_domain_list_id = aws_route53_resolver_firewall_domain_list.malware_domain_list.id
  priority                = 100
}

# VPC への DNS Firewall ルールグループの関連付け
resource "aws_route53_resolver_firewall_rule_group_association" "vpc_association" {
  name                   = "dns-firewall-vpc-assoc"
  firewall_rule_group_id = aws_route53_resolver_firewall_rule_group.vpc_dns_firewall.id
  priority               = 101
  vpc_id                 = var.vpc_id
  mutation_protection    = "ENABLED"
}
