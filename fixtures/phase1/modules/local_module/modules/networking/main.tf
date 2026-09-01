resource "aws_security_group" "web_sg" {
  name        = "web-sg"
  description = "Security group for web"
}

resource "aws_security_group_rule" "web_ingress" {
  type              = "ingress"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = [var.vpc_cidr]
  security_group_id = aws_security_group.web_sg.id
}
