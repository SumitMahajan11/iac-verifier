variable "environment" {
  type    = string
  default = "dev"
}

variable "vpc_id" {
  type = string
}

variable "db_port" {
  type    = number
  default = 5432
}
