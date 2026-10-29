# Two empty buckets. The boundary lets delegated roles touch "team" and nothing else,
# so "other" is how the video shows the cap holding.
resource "aws_s3_bucket" "team" {
  bucket        = "${var.name_prefix}-${local.account_id}-team"
  force_destroy = true # lab only
}

resource "aws_s3_bucket" "other" {
  bucket        = "${var.name_prefix}-${local.account_id}-other"
  force_destroy = true # lab only
}
