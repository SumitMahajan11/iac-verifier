variable "services" {
  type = map(string)
  default = {
    "frontend" = "t3.micro"
    "backend"  = "t3.small"
  }
}
