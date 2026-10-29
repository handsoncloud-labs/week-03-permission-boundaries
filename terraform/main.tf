data "aws_caller_identity" "current" {}

locals {
  account_id   = data.aws_caller_identity.current.account_id
  trusted      = coalesce(var.trusted_principal_arn, data.aws_caller_identity.current.arn)
  app_role_arn = "arn:aws:iam::${local.account_id}:role/${var.name_prefix}-app-*"
  boundary_arn = "arn:aws:iam::${local.account_id}:policy/${var.name_prefix}-boundary"
}
