resource "aws_ecs_task_definition" "app" {
  family                   = "ministack-demo"
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

  # Enable fault injection for FIS
  enable_fault_injection = true
}
