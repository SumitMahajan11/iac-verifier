locals {
  app_name  = "analytics"
  full_name = "${local.app_name}-${var.environment}"
}

data "aws_vpc" "selected" {
  id = var.vpc_id
}

resource "aws_security_group" "db_sg" {
  name        = "${local.full_name}-sg"
  description = "Database SG for ${local.full_name}"
  vpc_id      = var.vpc_id
}

resource "aws_security_group_rule" "db_ingress" {
  type              = "ingress"
  from_port         = var.db_port
  to_port           = var.db_port
  protocol          = "tcp"
  cidr_blocks       = [data.aws_vpc.selected.cidr_block]
  security_group_id = aws_security_group.db_sg.id
}

resource "aws_db_instance" "db" {
  identifier        = local.full_name
  allocated_storage = 20
  engine            = "postgres"
  engine_version    = "15.3"
  instance_class    = "db.t3.micro"
}
