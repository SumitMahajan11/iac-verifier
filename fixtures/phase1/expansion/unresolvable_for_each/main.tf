data "aws_vpc" "selected" {
  id = "vpc-123456"
}

resource "aws_security_group_rule" "data_rule" {
  for_each = data.aws_vpc.selected.cidr_blocks

  type        = "ingress"
  from_port   = 80
  to_port     = 80
  protocol    = "tcp"
  cidr_blocks = [each.value]
  description = "Rule for ${each.key}"
}
