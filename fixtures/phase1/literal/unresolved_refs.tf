resource "aws_security_group" "unresolved_sg" {
  name        = "unresolved-sg"
  vpc_id      = var.vpc_id
  description = "SG with ${var.env} environment reference"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }
}
