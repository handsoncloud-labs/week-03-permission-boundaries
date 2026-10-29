output "delegate_role_arn" {
  value = aws_iam_role.delegate.arn
}

output "delegate_role_name" {
  value = aws_iam_role.delegate.name
}

output "boundary_arn" {
  value = aws_iam_policy.boundary.arn
}

output "team_bucket" {
  value = aws_s3_bucket.team.bucket
}

output "other_bucket" {
  value = aws_s3_bucket.other.bucket
}

output "app_role_prefix" {
  description = "Delegated roles must be named <prefix>*."
  value       = "${var.name_prefix}-app-"
}
