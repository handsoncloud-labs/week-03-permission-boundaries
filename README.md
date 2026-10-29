# IAM permission boundaries: let people create roles without letting them escalate

A "delegate" role may create IAM roles, but **only roles that carry a permissions boundary**. Even if someone attaches `AdministratorAccess` to a bounded role, it can still only touch one S3 bucket.

```
user ──assume──▶ hoc-pb-delegate ──CreateRole (only with boundary)──▶ hoc-pb-app-demo
                                                                        │ AdministratorAccess ∩ boundary
                                                                        ▼
                                                        team bucket: yes · everything else: no
```

- `terraform/`: boundary policy, delegate role + policy, two empty buckets (`team`, `other`)
- `pb.py`: the client used in the video (`guardrail`, `create-naked`, `create`, `test`, `escape`, `cleanup`)

## The two ideas

1. **A boundary is a ceiling, not a grant.** Effective permissions = the role's own policies **∩** the boundary.
2. **The delegate can only create roles that wear the boundary**, enforced by a condition on `iam:PermissionsBoundary`, plus explicit Denies so the boundary can't be removed or edited.

```hcl
condition { test = "StringEquals"  variable = "iam:PermissionsBoundary"  values = [aws_iam_policy.boundary.arn] }
```

## Run it

Requires Terraform ≥ 1.9, Python 3.11+, boto3, and AWS credentials that can create IAM roles, IAM policies and S3 buckets.

```bash
terraform -chdir=terraform init && terraform -chdir=terraform apply

python pb.py guardrail      # the ceiling, and the rule on the delegate
python pb.py create-naked   # CreateRole without the boundary: AccessDenied
python pb.py create         # with the boundary: allowed; attach AdministratorAccess
python pb.py test           # 3 calls allowed (team bucket), 4 refused (other bucket, IAM, EC2)
python pb.py escape         # remove the boundary / edit it: AccessDenied

python pb.py cleanup && terraform -chdir=terraform destroy
```

Roles can take a few seconds to take effect; the client retries while IAM catches up.

## Cost

IAM is free. Two empty S3 buckets cost nothing measurable. Destroy afterwards anyway.

## Not covered

Boundaries don't limit what a role can *do to itself* through other paths (for example a delegate that is also allowed `iam:CreatePolicy` could write a new, broader boundary and use that). Pair boundaries with an SCP or a tight `iam:PolicyARN` condition in real accounts.
