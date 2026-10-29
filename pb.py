#!/usr/bin/env python3
"""Client for the IAM permission boundaries lab.

  python pb.py guardrail      # show the boundary and what the delegate role is allowed to do
  python pb.py create-naked   # delegate tries to create a role WITHOUT the boundary: refused
  python pb.py create         # delegate creates a role WITH the boundary, then attaches AdministratorAccess
  python pb.py test           # use that role: team bucket works, everything else is refused
  python pb.py escape         # delegate tries to remove the boundary or edit it: refused
  python pb.py cleanup        # delete the demo role

Needs AWS credentials for the user the delegate role trusts (terraform's caller).
Set HOC_FACTS to also write what happened into the episode's facts.json.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
TF_DIR = HERE / "terraform"
DEMO_SUFFIX = "demo"
ADMIN_POLICY = "arn:aws:iam::aws:policy/AdministratorAccess"
WIDTH = max(40, min(76, shutil.get_terminal_size((80, 24)).columns - 1))

GREEN, RED, CYAN, DIM, BOLD, RESET = (
    ("\033[32m", "\033[31m", "\033[36m", "\033[2m", "\033[1m", "\033[0m")
    if sys.stdout.isatty() or os.environ.get("FORCE_COLOR")
    else ("",) * 6
)

DENY_CODES = {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
              "UnauthorizedAccess", "Client.UnauthorizedOperation"}


def fail(msg: str) -> "None":
    print(f"{RED}{msg}{RESET}", file=sys.stderr)
    raise SystemExit(1)


def redact(text: str) -> str:
    """Hide 12-digit AWS account IDs before anything is shown on camera."""
    return re.sub(r"(?<!\d)\d{12}(?!\d)", "************", text)


def record(namespace: str, data: dict) -> None:
    """If HOC_FACTS is set, merge real run output into that JSON file."""
    path = os.environ.get("HOC_FACTS")
    if not path:
        return
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    facts = json.loads(p.read_text()) if p.exists() else {}
    facts[namespace] = data
    p.write_text(json.dumps(facts, indent=2) + "\n")


# ---------------------------------------------------------------- analysis

def _as_list(v) -> list:
    return v if isinstance(v, list) else [v]


def is_denied(err) -> bool:
    """True when a boto ClientError is an authorization refusal (not a typo or throttle)."""
    code = getattr(err, "response", {}).get("Error", {}).get("Code", "")
    return code in DENY_CODES


def analyze_boundary(policy: dict) -> dict:
    """What a boundary document caps a role to: the actions and resources it allows.

    `wildcard` is True when any Allow uses Action "*" / "service:*" or Resource "*":
    a boundary that wide caps nothing.
    """
    actions: list[str] = []
    resources: list[str] = []
    for s in _as_list(policy["Statement"]):
        if s.get("Effect") != "Allow":
            continue
        actions += _as_list(s.get("Action", []))
        resources += _as_list(s.get("Resource", []))
    wildcard = any(a == "*" or a.endswith(":*") for a in actions) or "*" in resources
    return {"actions": sorted(set(actions)), "resources": sorted(set(resources)), "wildcard": wildcard}


def requires_boundary(policy: dict, boundary_arn: str) -> bool:
    """True if every Allow that creates or shapes roles is conditional on the boundary ARN."""
    must = {"iam:CreateRole", "iam:AttachRolePolicy", "iam:PutRolePolicy"}
    seen: set[str] = set()
    for s in _as_list(policy["Statement"]):
        if s.get("Effect") != "Allow":
            continue
        acts = set(_as_list(s.get("Action", [])))
        if not acts & must:
            continue
        cond = s.get("Condition", {}).get("StringEquals", {})
        if boundary_arn not in _as_list(cond.get("iam:PermissionsBoundary", [])):
            return False
        seen |= acts & must
    return seen == must


def summarize_checks(results: list[dict]) -> dict:
    """Counts for the narration: how many calls the bounded admin role could and could not make."""
    allowed = [r for r in results if r["outcome"] == "allowed"]
    denied = [r for r in results if r["outcome"] == "denied"]
    return {"allowed": len(allowed), "denied": len(denied), "total": len(results),
            "denied_names": [r["name"] for r in denied]}


# ---------------------------------------------------------------- aws

def tf_outputs() -> dict:
    out = subprocess.run(["terraform", f"-chdir={TF_DIR}", "output", "-json"], capture_output=True, text=True)
    raw = json.loads(out.stdout or "{}")
    if out.returncode != 0 or not raw:
        fail("No Terraform outputs. Run `make EP=week-03-permission-boundaries lab-up` first.")
    return {k: v["value"] for k, v in raw.items()}


def assume(session, role_arn: str, name: str, retries: int = 12):
    """Return a boto3 Session using temporary credentials for role_arn. New IAM changes take a few seconds."""
    import boto3
    from botocore.exceptions import ClientError

    sts = session.client("sts")
    for attempt in range(retries):
        try:
            c = sts.assume_role(RoleArn=role_arn, RoleSessionName=name, DurationSeconds=900)["Credentials"]
            return boto3.Session(aws_access_key_id=c["AccessKeyId"], aws_secret_access_key=c["SecretAccessKey"],
                                 aws_session_token=c["SessionToken"], region_name=session.region_name or "us-east-1")
        except ClientError as e:
            if not is_denied(e) or attempt == retries - 1:
                raise
            time.sleep(3)
    raise AssertionError("unreachable")


def delegate_session(out: dict):
    import boto3

    return assume(boto3.Session(), out["delegate_role_arn"], "pb-delegate")


def demo_role_name(out: dict) -> str:
    return f"{out['app_role_prefix']}{DEMO_SUFFIX}"


def trust_for(delegate_arn: str) -> str:
    """The new role may be assumed only by the delegate that created it."""
    return json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": delegate_arn}, "Action": "sts:AssumeRole"}]})


def error_line(err) -> str:
    e = err.response["Error"]
    msg = re.sub(r"^User: \S+ ", "", e.get("Message", ""))
    msg = re.sub(r" Go to https://\S+ for complete details.*$", "", msg)
    msg = redact(re.sub(r"arn:aws:(sts|iam)::\d+:", r"arn:aws:\1::", msg))
    return f"{e['Code']}: {msg}"


# ---------------------------------------------------------------- commands

def cmd_guardrail(_args) -> int:
    import boto3

    out = tf_outputs()
    iam = boto3.client("iam")
    arn = out["boundary_arn"]
    version = iam.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]
    boundary = iam.get_policy_version(PolicyArn=arn, VersionId=version)["PolicyVersion"]["Document"]
    delegate = iam.get_role_policy(RoleName=out["delegate_role_name"], PolicyName="create-bounded-roles")["PolicyDocument"]

    b = analyze_boundary(boundary)
    print(f"{BOLD}boundary{RESET}  {redact(arn.split('/')[-1])}  {DIM}(the ceiling){RESET}")
    for a in b["actions"]:
        print(f"  {GREEN}allow{RESET} {a}")
    for r in b["resources"]:
        print(f"       {DIM}{redact(r)}{RESET}")
    ok = requires_boundary(delegate, arn)
    print(f"\n{BOLD}delegate{RESET}  {out['delegate_role_name']}")
    print(f"  {CYAN}iam:CreateRole, AttachRolePolicy, PutRolePolicy{RESET}")
    print(f"  only if {CYAN}iam:PermissionsBoundary{RESET} == the boundary above")
    if b["wildcard"] or not ok:
        print(f"{RED}✗ guardrail is too loose{RESET}")
        return 1
    print(f"{GREEN}✓ boundary is narrow, and creating roles requires it{RESET}")
    record("guardrail", {"boundary_actions": len(b["actions"]), "wildcard": b["wildcard"],
                         "requires_boundary": ok})
    return 0


def cmd_create_naked(_args) -> int:
    from botocore.exceptions import ClientError

    out = tf_outputs()
    sess = delegate_session(out)
    name = demo_role_name(out)
    print(f"{BOLD}▶ iam:CreateRole {name}{RESET}  {DIM}(no boundary){RESET}")
    try:
        sess.client("iam").create_role(RoleName=name, AssumeRolePolicyDocument=trust_for(out["delegate_role_arn"]))
    except ClientError as e:
        if not is_denied(e):
            raise
        print(f"  {RED}✗ {error_line(e)}{RESET}")
        record("naked", {"outcome": "denied", "code": e.response["Error"]["Code"]})
        return 0
    sess.client("iam").delete_role(RoleName=name)
    fail("Expected CreateRole without a boundary to be refused. Facts not recorded.")


def cmd_create(_args) -> int:
    from botocore.exceptions import ClientError

    out = tf_outputs()
    sess = delegate_session(out)
    iam = sess.client("iam")
    name = demo_role_name(out)
    print(f"{BOLD}▶ iam:CreateRole {name}{RESET}  {DIM}--permissions-boundary {out['boundary_arn'].split('/')[-1]}{RESET}")
    try:
        iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust_for(out["delegate_role_arn"]),
                        PermissionsBoundary=out["boundary_arn"],
                        Tags=[{"Key": "Project", "Value": "handsoncloud"}, {"Key": "Lab", "Value": "week-03-permission-boundaries"}])
    except ClientError as e:
        if e.response["Error"]["Code"] != "EntityAlreadyExists":
            raise
        print(f"  {DIM}role already exists{RESET}")
    print(f"  {GREEN}✓{RESET} created")
    iam.attach_role_policy(RoleName=name, PolicyArn=ADMIN_POLICY)
    print(f"{BOLD}▶ iam:AttachRolePolicy{RESET}  {CYAN}AdministratorAccess{RESET}")
    print(f"  {GREEN}✓{RESET} attached: this role now has full admin ... on paper")
    record("create", {"role_name": name, "attached": "AdministratorAccess"})
    return 0


CHECKS = [
    ("s3:ListBucket   team bucket", "team", lambda s, o: s.client("s3").list_objects_v2(Bucket=o["team_bucket"], MaxKeys=1)),
    ("s3:PutObject    team bucket", "team", lambda s, o: s.client("s3").put_object(Bucket=o["team_bucket"], Key="hello.txt", Body=b"hi")),
    ("s3:GetObject    team bucket", "team", lambda s, o: s.client("s3").get_object(Bucket=o["team_bucket"], Key="hello.txt")["Body"].read()),
    ("s3:ListBucket   other bucket", "other", lambda s, o: s.client("s3").list_objects_v2(Bucket=o["other_bucket"], MaxKeys=1)),
    ("iam:ListUsers", "iam", lambda s, o: s.client("iam").list_users(MaxItems=1)),
    ("iam:CreateUser", "iam", lambda s, o: s.client("iam").create_user(UserName="hoc-pb-intruder")),
    ("ec2:DescribeRegions", "ec2", lambda s, o: s.client("ec2", region_name=o.get("region", "us-east-1")).describe_regions()),
]


def run_check(sess, out: dict, fn, patient: bool) -> str:
    """Return 'allowed' or 'denied'. `patient` waits for new IAM permissions to propagate."""
    from botocore.exceptions import ClientError

    for _ in range(14 if patient else 1):
        try:
            fn(sess, out)
            return "allowed"
        except ClientError as e:
            if not is_denied(e):
                raise
            if not patient:
                return "denied"
            time.sleep(3)
    return "denied"


def cmd_test(_args) -> int:
    out = tf_outputs()
    delegate = delegate_session(out)
    role_arn = f"arn:aws:iam::{delegate.client('sts').get_caller_identity()['Account']}:role/{demo_role_name(out)}"
    app = assume(delegate, role_arn, "pb-app")
    print(f"{BOLD}▶ as {demo_role_name(out)}{RESET}  {DIM}(AdministratorAccess + boundary){RESET}")

    results = []
    for label, area, fn in CHECKS:
        outcome = run_check(app, out, fn, patient=(area == "team" and not results))
        results.append({"name": label, "outcome": outcome})
        mark = f"{GREEN}✓ allowed" if outcome == "allowed" else f"{RED}✗ denied "
        print(f"  {mark}{RESET}  {label}")

    s = summarize_checks(results)
    print(f"{BOLD}{s['allowed']} allowed, {s['denied']} denied{RESET} {DIM}of {s['total']} calls{RESET}")
    expected_allowed = {r["name"] for r in results if "team bucket" in r["name"]}
    got_allowed = {r["name"] for r in results if r["outcome"] == "allowed"}
    if got_allowed != expected_allowed:
        fail("Boundary did not behave as designed. Facts not recorded.")
    record("test", {"allowed": s["allowed"], "denied": s["denied"], "total": s["total"],
                    "admin_denied": any("iam:CreateUser" in n for n in s["denied_names"])})
    return 0


def cmd_escape(_args) -> int:
    from botocore.exceptions import ClientError

    out = tf_outputs()
    sess = delegate_session(out)
    iam = sess.client("iam")
    name = demo_role_name(out)
    attempts = [
        ("iam:DeleteRolePermissionsBoundary", lambda: iam.delete_role_permissions_boundary(RoleName=name)),
        ("iam:CreatePolicyVersion  (edit the boundary)", lambda: iam.create_policy_version(
            PolicyArn=out["boundary_arn"], SetAsDefault=True,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
                {"Effect": "Allow", "Action": "*", "Resource": "*"}]}))),
    ]
    refused = 0
    for label, fn in attempts:
        print(f"{BOLD}▶ {label}{RESET}")
        try:
            fn()
        except ClientError as e:
            if not is_denied(e):
                raise
            refused += 1
            print(f"  {RED}✗ {error_line(e)}{RESET}")
        else:
            fail(f"{label} was allowed: the boundary can be escaped!")
    record("escape", {"attempts": len(attempts), "refused": refused})
    return 0


def cmd_cleanup(_args) -> int:
    from botocore.exceptions import ClientError

    out = tf_outputs()
    iam = delegate_session(out).client("iam")
    name = demo_role_name(out)
    try:
        for p in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]:
            iam.detach_role_policy(RoleName=name, PolicyArn=p["PolicyArn"])
        for p in iam.list_role_policies(RoleName=name)["PolicyNames"]:
            iam.delete_role_policy(RoleName=name, PolicyName=p)
        iam.delete_role(RoleName=name)
        print(f"{GREEN}✓{RESET} deleted role {name}")
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise
        print(f"{DIM}nothing to delete{RESET}")
    return 0


def main(argv: list[str] | None = None) -> int:
    from botocore.exceptions import ClientError

    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn in (("guardrail", cmd_guardrail), ("create-naked", cmd_create_naked), ("create", cmd_create),
                     ("test", cmd_test), ("escape", cmd_escape), ("cleanup", cmd_cleanup)):
        sub.add_parser(name).set_defaults(fn=fn)
    args = ap.parse_args(argv)
    try:
        return args.fn(args)
    except ClientError as e:
        fail(error_line(e))


if __name__ == "__main__":
    sys.exit(main())
