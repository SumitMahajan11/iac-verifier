data "aws_vpc" "selected" {
  id = "vpc-123456"
}

resource "aws_security_group" "data_sg" {
  name        = "data-sg"
  vpc_id      = data.aws_vpc.selected.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.selected.cidr_block]
  }
}
