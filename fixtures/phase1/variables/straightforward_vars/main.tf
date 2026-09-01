resource "aws_security_group" "web_sg" {
  name        = "web-sg"
  vpc_id      = var.vpc_id
  description = "Security group for web"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }
}
