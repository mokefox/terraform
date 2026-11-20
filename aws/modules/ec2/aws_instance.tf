resource "aws_instance" "app" {
  count         = var.num
  ami           = var.ami
  instance_type = var.instance_type
  subnet_id     = length(var.subnet_id) > 0 ? element(var.subnet_id, count.index) : null

  # 1. ネットワーク露出の制限
  associate_public_ip_address = false

  # 2. ストレージの暗号化 (Ransomware & Data protection)
  root_block_device {
    encrypted = true
  }

  ebs_block_device {
    encrypted   = true # 明示的にtrueを強制
    device_name = var.device_name
  }

  # 3. IMDS v2 の必須化 & ホップ数制限 (Credential protection & Anti-SSRF Bypass)
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2強制 (トークン必須)
    http_put_response_hop_limit = 1          # 多段プロキシやコンテナ経由のトークン不正取得を遮断
  }

  vpc_security_group_ids = var.security_group_ids

  tags = {
    Name         = "${format("web%02d", count.index + 1)}"
    BackupPolicy = "high-resilience"
    Project      = "terraform-1" # 必須タグの追加
    Environment  = "staging"     # 必須タグの追加
  }
}

# aws_eip.app is removed as we access via ALB only
