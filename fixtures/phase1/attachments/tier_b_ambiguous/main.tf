resource "aws_security_group" "sg1" {
  name = "shared-web-sg"
}

resource "aws_security_group" "sg2" {
  name = "shared-web-sg"
}

resource "aws_security_group_rule" "ambiguous_rule" {
  type              = "ingress"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = "shared-web-sg"
}
