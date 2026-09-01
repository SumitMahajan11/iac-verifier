resource "aws_instance" "server" {
  count         = var.instance_count
  ami           = "ami-87654321"
  instance_type = "t3.small"
  tags = {
    Name = "server-${count.index}"
  }
}
