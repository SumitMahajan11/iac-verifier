variable "root_cidr" {
  type    = string
  default = "10.0.0.0/16"
}

module "networking" {
  source   = "./modules/networking"
  vpc_cidr = var.root_cidr
}

resource "aws_instance" "app" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
}
