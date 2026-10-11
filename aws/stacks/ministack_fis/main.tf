module "fis" {
  source = "../../modules/fis"

  region     = var.region
  project    = var.project
  ec2_config = var.ec2_config
  lb_config  = var.lb_config

  environment = var.environment
  cluster_arn = ""

  vpc_id     = var.vpc_id
  subnet_ids = var.subnet_ids

  enable_fis = var.enable_fis
  fis        = var.fis
}
