module "app_service" {
  for_each = var.services

  source        = "./modules/app_service"
  service_name  = each.key
  instance_type = each.value
}
