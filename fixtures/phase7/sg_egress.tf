resource "aws_security_group" "unsafe_egress" {
  name        = "unsafe-egress"
  description = "Unsafe egress on all ports"

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "safe_egress" {
  name        = "safe-egress"
  description = "Safe egress"

  egress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
