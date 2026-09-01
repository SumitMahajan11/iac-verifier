resource "aws_security_group" "open_ssh" {
  name        = "open-ssh-sg"
  description = "Security group exposing SSH to the world"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
