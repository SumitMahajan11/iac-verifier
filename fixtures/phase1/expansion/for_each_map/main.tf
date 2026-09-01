resource "aws_security_group" "web_sg" {
  name = "web-sg"
}

resource "aws_security_group_rule" "ingress_rules" {
  for_each = {
    "http"  = 80
    "https" = 443
    "ssh"   = 22
  }

  type              = "ingress"
  from_port         = each.value
  to_port           = each.value
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.web_sg.id
  description       = "Allow ${each.key}"
}
