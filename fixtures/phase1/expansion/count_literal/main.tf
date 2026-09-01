resource "aws_instance" "web" {
  count         = 2
  ami           = "ami-12345678"
  instance_type = "t3.micro"
  tags = {
    Name = "web-server-${count.index}"
  }
}
