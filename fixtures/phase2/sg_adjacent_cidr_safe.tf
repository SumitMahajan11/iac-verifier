resource "aws_security_group" "adjacent_safe" {
  name        = "adjacent-safe-sg"
  description = "Security group using private CIDR adjacent to public boundary (10.255.255.0/24 vs 11.0.0.0/24)"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.255.255.0/24"]
  }
}
