# ==============================================================================
# Layer 3/4: Security Groups (AWS 多層防御 & 横展開防止)
# 対策: 最小ポート原則, ティア間セグメンテーション, ラテラルムーブメント遮断
# NOTE: 相互参照による循環依存 (Cycle) を防ぐため、ルールは aws_security_group_rule で定義
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. セキュリティグループ本体定義
# ------------------------------------------------------------------------------
resource "aws_security_group" "alb_sg" {
  name        = "hardened-alb-sg"
  description = "ALB Ingress from CDN / Internet, Egress to App tier only"
  vpc_id      = var.vpc_id

  tags = {
    Name = "alb-security-group"
    Tier = "DMZ"
  }
}

resource "aws_security_group" "app_container_sg" {
  name        = "hardened-app-container-sg"
  description = "App Containers: strictly accepts traffic from ALB SG only"
  vpc_id      = var.vpc_id

  tags = {
    Name = "app-container-sg"
    Tier = "App"
  }
}

resource "aws_security_group" "db_sg" {
  name        = "hardened-database-sg"
  description = "Database: accepts connections strictly from App Containers"
  vpc_id      = var.vpc_id

  tags = {
    Name = "database-sg"
    Tier = "Database"
  }
}

# ------------------------------------------------------------------------------
# 2. ALB SG ルール
# ------------------------------------------------------------------------------
resource "aws_security_group_rule" "alb_ingress_https" {
  type              = "ingress"
  description       = "Allow HTTPS from CloudFront / Clients"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.alb_sg.id
}

resource "aws_security_group_rule" "alb_ingress_http" {
  type              = "ingress"
  description       = "Allow HTTP for redirect to HTTPS"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.alb_sg.id
}

resource "aws_security_group_rule" "alb_egress_to_app" {
  type                     = "egress"
  description              = "Allow traffic only to App Container Tier"
  from_port                = 8080
  to_port                  = 8080
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.app_container_sg.id
  security_group_id        = aws_security_group.alb_sg.id
}

# ------------------------------------------------------------------------------
# 3. App Container SG ルール
# ------------------------------------------------------------------------------
resource "aws_security_group_rule" "app_ingress_from_alb" {
  type                     = "ingress"
  description              = "Allow Ingress from ALB SG strictly"
  from_port                = 8080
  to_port                  = 8080
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.alb_sg.id
  security_group_id        = aws_security_group.app_container_sg.id
}

resource "aws_security_group_rule" "app_egress_to_db" {
  type                     = "egress"
  description              = "Allow Egress only to Database Tier"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.db_sg.id
  security_group_id        = aws_security_group.app_container_sg.id
}

resource "aws_security_group_rule" "app_egress_to_vpc_endpoints" {
  type              = "egress"
  description       = "Allow Egress to VPC Endpoints (PrivateLink)"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  prefix_list_ids   = [var.vpc_endpoints_prefix_list_id]
  security_group_id = aws_security_group.app_container_sg.id
}

# ------------------------------------------------------------------------------
# 4. Database SG ルール (外部へのEgressは完全遮断)
# ------------------------------------------------------------------------------
resource "aws_security_group_rule" "db_ingress_from_app" {
  type                     = "ingress"
  description              = "Allow PostgreSQL access strictly from App SG"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.app_container_sg.id
  security_group_id        = aws_security_group.db_sg.id
}

# ------------------------------------------------------------------------------
# 変数定義
# ------------------------------------------------------------------------------
variable "vpc_id" {
  type    = string
  default = "vpc-0123456789abcdef0"
}

variable "vpc_endpoints_prefix_list_id" {
  type    = string
  default = "pl-12345678"
}
