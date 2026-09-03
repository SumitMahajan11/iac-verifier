# Regression Fixture: Multi-resource and Non-contiguous Rule Deletion
# Tests that diff generation only targets specified resource and deletes exact statement indices [0, 2] while preserving index 1 and other resources.

resource "aws_security_group" "sg_safe" {
  name        = "sg-safe"
  description = "Safe security group in the same file"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

resource "aws_security_group" "sg_target" {
  name        = "sg-target"
  description = "Target security group with non-contiguous open SSH rules"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
