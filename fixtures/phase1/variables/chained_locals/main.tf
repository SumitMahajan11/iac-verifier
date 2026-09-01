locals {
  env    = var.environment
  prefix = "${local.env}-app"
  cidr   = var.cidr
}

resource "aws_security_group" "app_sg" {
  name        = "${local.prefix}-sg"
  description = "App SG in ${local.env}"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [local.cidr]
  }
}
