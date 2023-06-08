terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "~> 5.1.0"
    }
  }
}

provider "aws" {
  region = "eu-central-1"
}

locals {
  keycloak_image = "quay.io/keycloak/keycloak"
  keycloak_version = "latest"
}

resource "aws_vpc" "vpc" {
  cidr_block = "10.0.0.0/16"

  enable_dns_hostnames = true
  enable_dns_support = true

  tags = {
    Name = "keycloak_vpc"
  }
}

resource "aws_subnet" "primary" {
  vpc_id     = aws_vpc.vpc.id
  cidr_block = "10.0.3.0/24"
  availability_zone = "eu-central-1a"

  tags = {
    Name = "keycloak_subnet"
  }
}

resource "aws_subnet" "secondary" {
  vpc_id     = aws_vpc.vpc.id
  cidr_block = "10.0.4.0/24"
  availability_zone = "eu-central-1b"

  tags = {
    Name = "keycloak_subnet"
  }
}

resource "aws_security_group" "rds_sg" {
  name        = "rds_sg"
  description = "Allow incoming traffic to RDS"
  vpc_id      = aws_vpc.vpc.id
}

resource "aws_security_group_rule" "rds_sg_rule" {
  security_group_id = aws_security_group.rds_sg.id

  type        = "ingress"
  from_port   = 5432
  to_port     = 5432
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_db_subnet_group" "db_subnet_group" {
  name       = "keycloak_db_subnet_group"
  subnet_ids = [aws_subnet.primary.id, aws_subnet.secondary.id]
}

resource "aws_db_instance" "keycloak_rds" {
  identifier           = "keycloak-rds"
  engine               = "postgres"
  engine_version       = "15.3"
  instance_class       = "db.t3.small"
  allocated_storage    = 20
  username             = "keycloak"
  password             = "hj645ei56wiee5478i5wi6zu3iz"
  db_subnet_group_name = aws_db_subnet_group.db_subnet_group.name
  vpc_security_group_ids = [aws_security_group.rds_sg.id]
  skip_final_snapshot = true
  publicly_accessible = true
}

resource "aws_security_group" "ecs_sg" {
  name        = "ecs_sg"
  description = "Allow incoming traffic to Keycloak container"
  vpc_id      = aws_vpc.vpc.id
}

resource "aws_security_group_rule" "ecs_sg_ingress_rule" {
  security_group_id = aws_security_group.ecs_sg.id

  type        = "ingress"
  from_port   = 8080
  to_port     = 8080
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_security_group_rule" "ecs_rds_rule" {
  security_group_id = aws_security_group.ecs_sg.id

  type        = "egress"
  from_port   = 5432
  to_port     = 5432
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_security_group_rule" "ecs_sg_egress_rule" {
  security_group_id = aws_security_group.ecs_sg.id

  type        = "egress"
  from_port   = 443
  to_port     = 443
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_internet_gateway" "internet_gateway" {
  vpc_id = aws_vpc.vpc.id

  tags = {
    Name = "keycloak_internet_gateway"
  }
}

resource "aws_route_table" "route_table" {
  vpc_id = aws_vpc.vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.internet_gateway.id
  }

  tags = {
    Name = "keycloak_route_table"
  }
}

resource "aws_route_table_association" "primary_route_table_association" {
  subnet_id      = aws_subnet.primary.id
  route_table_id = aws_route_table.route_table.id
}

resource "aws_route_table_association" "secondary_route_table_association" {
  subnet_id      = aws_subnet.secondary.id
  route_table_id = aws_route_table.route_table.id
}

resource "aws_ecs_cluster" "keycloak_cluster" {
  name = "keycloak-cluster"
}

resource "aws_ecs_task_definition" "keycloak_task" {
  family                   = "keycloak-task"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "1024"
  memory                   = "2048"
  execution_role_arn       = aws_iam_role.ecs_execution_role.arn
  task_role_arn = aws_iam_role.ecs_execution_role.arn

  container_definitions = jsonencode([
    {
      name  = "keycloak"
      image = "${local.keycloak_image}:${local.keycloak_version}"

      entrypoint: ["/opt/keycloak/bin/kc.sh", "start-dev"]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-region"        = "eu-central-1" # Replace with your region
          "awslogs-group"         = aws_cloudwatch_log_group.keycloak_log_group.name
          "awslogs-stream-prefix" = "keycloak"
        }
      }

      environment = [
        {name: "KEYCLOAK_ADMIN", value: "admin"},
        {name: "KEYCLOAK_ADMIN_PASSWORD", value: "6345zuw4w5uu46u"},
        {name: "KC_HTTP_ENABLED", value: "true"},
        {name: "KC_HOSTNAME_STRICT_HTTPS", value: "false"},
        {name: "KC_PROXY", value: "edge"},
        {name: "KC_PROXY_ADDRESS_FORWARDING", value: "true"},
        {name  = "DB_VENDOR", value = "postgres" },
        {name  = "DB_URL", value = "jdbc:postgresql://${aws_db_instance.keycloak_rds.endpoint}"},
        {name  = "DB_PORT", value = "5432"},
        {name  = "DB_DATABASE", value = "keycloak"},
        {name  = "DB_USER", value = "keycloak"},
        {name  = "DB_PASSWORD", value = "hj645ei56wiee5478i5wi6zu3iz" }
      ]

      portMappings = [
        {
          containerPort = 8080
          hostPort      = 8080
          protocol      = "tcp"
        }
      ]
    }
  ])
}

resource "aws_iam_role" "ecs_execution_role" {
  name = "ecs_execution_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_policy" "ecs_execution_policy" {
  name = "ecs_execution_policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
      {
        "Effect": "Allow",
        "Action": [
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:*"
        ],
        "Resource": "*"
      }
    ]
  })
}

resource "aws_cloudwatch_log_resource_policy" "keycloak_log_policy" {
  policy_name = "keycloak-log-policy"
  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "logs:PutLogEvents",
          "logs:PutLogEventsBatch",
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:*"
        ]
        Effect   = "Allow"
        Resource = "*"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_execution_policy_attachment" {
  policy_arn = aws_iam_policy.ecs_execution_policy.arn
  role       = aws_iam_role.ecs_execution_role.name
}

resource "aws_cloudwatch_log_group" "keycloak_log_group" {
  name = "/aws/ecs/keycloak"
}

resource "aws_ecs_service" "keycloak_service" {
  name            = "keycloak-service"
  cluster         = aws_ecs_cluster.keycloak_cluster.id
  task_definition = aws_ecs_task_definition.keycloak_task.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = [aws_subnet.primary.id, aws_subnet.secondary.id]
    security_groups  = [aws_security_group.ecs_sg.id]
    assign_public_ip = true
  }
}

