resource "aws_security_group" "parent_sg" {
  name = "parent-sg"
}

module "child_mod" {
  source = "./modules/child_mod"
}
