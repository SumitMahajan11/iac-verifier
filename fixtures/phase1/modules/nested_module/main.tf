resource "aws_instance" "root_app" {
  ami           = "ami-99999999"
  instance_type = "t3.nano"
}

module "parent_mod" {
  source = "./modules/parent_mod"
}
