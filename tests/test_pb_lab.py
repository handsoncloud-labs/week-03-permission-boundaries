import pytest
from botocore.exceptions import ClientError

import pb

BOUNDARY = "arn:aws:iam::123456789012:policy/hoc-pb-boundary"


def err(code):
    return ClientError({"Error": {"Code": code, "Message": "nope"}}, "Op")


def delegate(cond_arn=BOUNDARY, actions=("iam:CreateRole", "iam:AttachRolePolicy", "iam:PutRolePolicy")):
    return {"Statement": [{"Effect": "Allow", "Action": list(actions), "Resource": "arn:aws:iam::1:role/hoc-pb-app-*",
                           "Condition": {"StringEquals": {"iam:PermissionsBoundary": cond_arn}}}]}


def test_is_denied_only_for_authorization_errors():
    assert pb.is_denied(err("AccessDenied"))
    assert pb.is_denied(err("UnauthorizedOperation"))
    assert not pb.is_denied(err("NoSuchEntity"))
    assert not pb.is_denied(err("Throttling"))
    assert not pb.is_denied(ValueError("x"))


def test_analyze_boundary_lists_allows_and_ignores_denies():
    p = {"Statement": [
        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": "arn:aws:s3:::b/*"},
        {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "arn:aws:s3:::b"},
        {"Effect": "Deny", "Action": "*", "Resource": "*"},
    ]}
    b = pb.analyze_boundary(p)
    assert b["actions"] == ["s3:GetObject", "s3:ListBucket", "s3:PutObject"]
    assert b["wildcard"] is False


@pytest.mark.parametrize("action,resource", [("*", "arn:x"), ("s3:*", "arn:x"), ("s3:GetObject", "*")])
def test_analyze_boundary_flags_wildcards(action, resource):
    p = {"Statement": [{"Effect": "Allow", "Action": action, "Resource": resource}]}
    assert pb.analyze_boundary(p)["wildcard"] is True


def test_requires_boundary_passes_when_all_role_actions_are_conditioned():
    assert pb.requires_boundary(delegate(), BOUNDARY)


def test_requires_boundary_fails_on_wrong_arn_or_missing_actions():
    assert not pb.requires_boundary(delegate(cond_arn="arn:aws:iam::1:policy/other"), BOUNDARY)
    assert not pb.requires_boundary(delegate(actions=("iam:CreateRole",)), BOUNDARY)


def test_requires_boundary_fails_when_an_unconditioned_allow_exists():
    p = delegate()
    p["Statement"].append({"Effect": "Allow", "Action": "iam:AttachRolePolicy", "Resource": "*"})
    assert not pb.requires_boundary(p, BOUNDARY)


def test_summarize_checks_counts_outcomes():
    s = pb.summarize_checks([{"name": "a", "outcome": "allowed"}, {"name": "b", "outcome": "denied"},
                             {"name": "c", "outcome": "denied"}])
    assert (s["allowed"], s["denied"], s["total"], s["denied_names"]) == (1, 2, 3, ["b", "c"])


def test_redact_hides_account_ids_only():
    assert pb.redact("arn:aws:iam::123456789012:role/x 20") == "arn:aws:iam::************:role/x 20"


def test_error_line_hides_account_and_caller_prefix():
    e = ClientError({"Error": {"Code": "AccessDenied", "Message":
                     "User: arn:aws:sts::123456789012:assumed-role/hoc-pb-delegate/s is not authorized to perform: iam:CreateRole"}}, "CreateRole")
    line = pb.error_line(e)
    assert "123456789012" not in line and line.startswith("AccessDenied: is not authorized")


def test_trust_for_names_only_the_delegate():
    import json
    t = json.loads(pb.trust_for("arn:aws:iam::1:role/hoc-pb-delegate"))
    assert t["Statement"][0]["Principal"] == {"AWS": "arn:aws:iam::1:role/hoc-pb-delegate"}
