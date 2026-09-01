resource "aws_security_group" "restricted_ssh" {
  name        = "restricted-ssh-sg"
  description = "Security group restricting SSH to internal VPC"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}
