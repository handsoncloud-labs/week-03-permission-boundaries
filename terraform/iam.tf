# ---- the boundary: the most any delegated role can ever do -------------------
# A permissions boundary never grants anything. A role's effective permissions are
# the overlap of its own policies and this one, so attaching AdministratorAccess
# to a bounded role still stops at the edge of this document.
data "aws_iam_policy_document" "boundary" {
  statement {
    sid       = "ListTeamBucket"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.team.arn]
  }

  statement {
    sid       = "ReadWriteTeamObjects"
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["${aws_s3_bucket.team.arn}/*"]
  }
}

resource "aws_iam_policy" "boundary" {
  name   = "${var.name_prefix}-boundary"
  policy = data.aws_iam_policy_document.boundary.json
}

# ---- the delegate: may create roles, but only bounded ones ------------------
data "aws_iam_policy_document" "delegate_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = [local.trusted]
    }
  }
}

resource "aws_iam_role" "delegate" {
  name                 = "${var.name_prefix}-delegate"
  assume_role_policy   = data.aws_iam_policy_document.delegate_trust.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "delegate" {
  # Create roles, and attach policies to them, ONLY when the role carries our boundary.
  statement {
    sid = "CreateAndShapeBoundedRoles"
    actions = [
      "iam:CreateRole",
      "iam:AttachRolePolicy",
      "iam:PutRolePolicy",
    ]
    resources = [local.app_role_arn]

    condition {
      test     = "StringEquals"
      variable = "iam:PermissionsBoundary"
      values   = [aws_iam_policy.boundary.arn]
    }
  }

  # Tagging is evaluated without the boundary key, so it cannot carry the condition.
  statement {
    sid       = "TagAppRoles"
    actions   = ["iam:TagRole"]
    resources = [local.app_role_arn]
  }

  # Looking at and cleaning up the roles it made.
  statement {
    sid = "ManageAppRoles"
    actions = [
      "iam:GetRole",
      "iam:ListAttachedRolePolicies",
      "iam:ListRolePolicies",
      "iam:DetachRolePolicy",
      "iam:DeleteRolePolicy",
      "iam:DeleteRole",
    ]
    resources = [local.app_role_arn]
  }

  statement {
    sid       = "UseAppRoles"
    actions   = ["sts:AssumeRole"]
    resources = [local.app_role_arn]
  }

  # Belt and braces: an explicit Deny beats any Allow, so the boundary can be neither
  # removed nor edited from here, even if a broader policy is attached later.
  statement {
    sid       = "NoTouchingTheBoundary"
    effect    = "Deny"
    actions   = ["iam:DeleteRolePermissionsBoundary", "iam:PutRolePermissionsBoundary"]
    resources = [local.app_role_arn]
  }

  statement {
    sid    = "NoEditingTheBoundaryPolicy"
    effect = "Deny"
    actions = [
      "iam:CreatePolicyVersion",
      "iam:DeletePolicy",
      "iam:DeletePolicyVersion",
      "iam:SetDefaultPolicyVersion",
    ]
    resources = [aws_iam_policy.boundary.arn]
  }
}

resource "aws_iam_role_policy" "delegate" {
  name   = "create-bounded-roles"
  role   = aws_iam_role.delegate.id
  policy = data.aws_iam_policy_document.delegate.json
}
