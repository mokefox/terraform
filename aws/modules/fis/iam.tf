data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

locals {
  region     = data.aws_region.current.region
  account_id = data.aws_caller_identity.current.account_id
}

resource "aws_iam_role" "fis" {
  name = format("%s%sFISRole", title(var.project), title(var.environment))
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "fis.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

data "aws_iam_policy_document" "fis_ecs" {
  statement {
    sid       = "FISECSActions"
    actions   = ["ecs:ListTasks", "ecs:DescribeTasks", "ecs:StopTask"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "fis_ec2" {
  statement {
    sid       = "FISEC2Actions"
    actions   = ["ec2:RebootInstances", "ec2:StopInstances", "ec2:StartInstances"]
    resources = ["arn:aws:ec2:*:*:instance/*"]
  }
}

data "aws_iam_policy_document" "fis_rds" {
  statement {
    sid       = "FISRDSActions"
    actions   = ["rds:FailoverDBCluster", "rds:RebootDBInstance"]
    resources = ["arn:aws:rds:*:*:cluster:*", "arn:aws:rds:*:*:db:*"]
  }
}

data "aws_iam_policy_document" "fis_ssm" {
  statement {
    sid       = "FISSSMActions"
    actions   = ["ssm:SendCommand", "ssm:GetCommandInvocation"]
    resources = ["arn:aws:ssm:*:*:document/*", "arn:aws:ec2:*:*:instance/*"]
  }
}

data "aws_iam_policy_document" "fis_network" {
  statement {
    sid       = "FISNetworkActions"
    actions   = ["network-firewall:DescribeFirewall", "ec2:DescribeSubnets", "ec2:CreateNetworkInterfacePermission"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "fis_control_plane" {
  statement {
    sid       = "FISControlPlaneActions"
    actions   = ["fis:InjectApiError", "iam:GetRole", "iam:ListRoles"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "fis_ebs" {
  statement {
    sid       = "FISEBSActions"
    actions   = ["ec2:PauseVolumeIO", "ec2:ResumeVolumeIO"]
    resources = ["arn:aws:ec2:*:*:volume/*"]
  }
}

data "aws_iam_policy_document" "fis_combined" {
  source_policy_documents = [
    data.aws_iam_policy_document.fis_ecs.json,
    data.aws_iam_policy_document.fis_ec2.json,
    data.aws_iam_policy_document.fis_rds.json,
    data.aws_iam_policy_document.fis_ssm.json,
    data.aws_iam_policy_document.fis_network.json,
    data.aws_iam_policy_document.fis_control_plane.json,
    data.aws_iam_policy_document.fis_ebs.json
  ]
}

resource "aws_iam_policy" "fis" {
  name   = format("%s%sFISPolicy", title(var.project), title(var.environment))
  policy = data.aws_iam_policy_document.fis_combined.json
}

resource "aws_iam_role_policy_attachment" "fis" {
  role       = aws_iam_role.fis.name
  policy_arn = aws_iam_policy.fis.arn
}
