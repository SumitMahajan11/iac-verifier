resource "aws_security_group" "svc_sg" {
  name        = "${var.service_name}-sg"
  description = "SG for ${var.service_name}"
}

resource "aws_instance" "server" {
  count         = 2
  ami           = "ami-0abcdef1234567890"
  instance_type = var.instance_type

  tags = {
    Name = "${var.service_name}-node-${count.index}"
  }
}
