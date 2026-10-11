resource "aws_ecs_cluster" "this" {
  name = "ministack-fis-cluster"
}

resource "random_pet" "suffix" {
  length = 2
}

resource "aws_ecs_service" "this" {
  name            = "ministack-fis-service-${random_pet.suffix.id}"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.app.arn
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.subnet_ids
    assign_public_ip = true
    security_groups  = [aws_security_group.sg.id]
  }

  desired_count = 1
}

resource "aws_ecs_task_definition" "app" {
  family                   = var.task_family
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "256"
  memory                   = "512"

  container_definitions = jsonencode([
    {
      name      = "demo"
      image     = "public.ecr.aws/nginx/nginx:latest"
      essential = true
      portMappings = [{
        containerPort = 80
        hostPort      = 80
        protocol      = "tcp"
      }]
    }
  ])

  # Fault injection 用に有効化 (Ministack がサポート)
  enable_fault_injection = true
}

resource "aws_security_group" "sg" {
  name        = "ministack-fis-sg"
  description = "Security group for FIS task"
  vpc_id      = var.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "sg_ingress_http" {
  security_group_id = aws_security_group.sg.id
  description       = "Allow inbound HTTP for FIS demo container"
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_egress_rule" "sg_egress_https" {
  security_group_id = aws_security_group.sg.id
  description       = "Allow outbound HTTPS for image pulling and AWS APIs"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  # コンテナイメージ取得およびAWSサービス連携のためHTTPS外向き通信を許可
  # trivy:ignore:AWS-0104
  cidr_ipv4 = "0.0.0.0/0"
}



# ---- FIS Experiment Templates ----
resource "aws_fis_experiment_template" "task_stop" {
  count       = var.enable_fis ? 1 : 0
  description = "Stop ECS task"
  role_arn    = aws_iam_role.fis.arn

  action {
    name      = "stop-ecs-tasks"
    action_id = "aws:ecs:stop-task"
    target {
      key   = "Tasks"
      value = "ecs-tasks-target"
    }
  }

  target {
    name           = "ecs-tasks-target"
    resource_type  = "aws:ecs:task"
    selection_mode = "COUNT(1)"
    parameters = {
      cluster = aws_ecs_cluster.this.name
      service = aws_ecs_service.this.name
    }
  }

  stop_condition {
    source = "aws:cloudwatch:alarm"
    value  = "arn:aws:cloudwatch:::alarm:dummy"
  }
}

resource "aws_fis_experiment_template" "network_latency" {
  count       = var.enable_fis ? 1 : 0
  description = "Inject network latency via SSM"
  role_arn    = aws_iam_role.fis.arn

  action {
    name      = "inject-latency"
    action_id = "aws:ssm:send-command"
    parameter {
      key   = "documentArn"
      value = "arn:aws:ssm:*:*:document/AWSFIS-Run-Network-Latency"
    }
    parameter {
      key   = "documentParameters"
      value = jsonencode({ duration = "PT30S", latency = 200 })
    }
    target {
      key   = "Instances"
      value = "network-target"
    }
  }

  target {
    name           = "network-target"
    resource_type  = "aws:ec2:instance"
    selection_mode = "ALL"
    resource_arns  = []
  }

  stop_condition {
    source = "aws:cloudwatch:alarm"
    value  = "arn:aws:cloudwatch:::alarm:dummy"
  }
}

resource "aws_fis_experiment_template" "network_blackhole" {
  count       = var.enable_fis ? 1 : 0
  description = "Inject network blackhole via SSM"
  role_arn    = aws_iam_role.fis.arn

  action {
    name      = "inject-blackhole"
    action_id = "aws:ssm:send-command"
    parameter {
      key   = "documentArn"
      value = "arn:aws:ssm:*:*:document/AWSFIS-Run-Network-Blackhole"
    }
    parameter {
      key   = "documentParameters"
      value = jsonencode({ duration = "PT30S" })
    }
    target {
      key   = "Instances"
      value = "network-target"
    }
  }

  target {
    name           = "network-target"
    resource_type  = "aws:ec2:instance"
    selection_mode = "ALL"
    resource_arns  = []
  }

  stop_condition {
    source = "aws:cloudwatch:alarm"
    value  = "arn:aws:cloudwatch:::alarm:dummy"
  }
}
