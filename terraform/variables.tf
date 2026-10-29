variable "aws_region" {
  description = "Region for the buckets. IAM itself is global."
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Prefix for every named resource. Delegated roles must start with <prefix>-app-."
  type        = string
  default     = "hoc-pb"
}

variable "trusted_principal_arn" {
  description = "Who may assume the delegate role (the person playing the platform engineer). Null means whoever runs terraform."
  type        = string
  default     = null
}
