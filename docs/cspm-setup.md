# AWS CSPM Setup

How to configure AWS Cloud Security Posture Management in Complyt.

## What It Checks

Complyt runs 25 read-only checks against your AWS account:

**S3** (5 checks): Public access blocks, encryption, versioning, access logging, account-level public access block.

**IAM** (6 checks): Root MFA, user MFA, access key rotation (90 days), unused credentials, overly permissive policies (Action:* Resource:*), password policy strength.

**CloudTrail** (3 checks): Trail existence, active logging, log file validation.

**EC2/VPC** (5 checks): Unrestricted SSH (port 22), unrestricted RDP (port 3389), default security group rules, EBS volume encryption, IMDSv2 enforcement.

**RDS** (3 checks): Storage encryption, public accessibility, automated backups.

**KMS** (2 checks): Customer-managed key rotation, keys pending deletion.

**CloudWatch Logs** (1 check): Log group retention policy.

See [Scanner Reference](scanner-reference.md) for the complete check ID list.

## Required IAM Policy

Create an IAM user or role with this minimal read-only policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetEncryptionConfiguration",
        "s3:GetBucketVersioning",
        "s3:GetBucketLogging",
        "s3control:GetPublicAccessBlock",
        "iam:GetAccountSummary",
        "iam:ListUsers",
        "iam:ListMFADevices",
        "iam:ListAccessKeys",
        "iam:ListPolicies",
        "iam:GetPolicyVersion",
        "iam:GetAccountPasswordPolicy",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVolumes",
        "ec2:DescribeInstances",
        "rds:DescribeDBInstances",
        "sts:GetCallerIdentity",
        "kms:ListKeys",
        "kms:DescribeKey",
        "kms:GetKeyRotationStatus",
        "logs:DescribeLogGroups"
      ],
      "Resource": "*"
    }
  ]
}
```

This policy grants **read-only** access. Complyt never creates, modifies, or deletes any AWS resources.

## Step-by-Step Configuration

1. **Create an IAM user** in the AWS Console with the policy above. Generate an access key pair.

2. **Open Complyt** and go to **Settings**.

3. **Scroll to Cloud Security** (or Security Testing section).

4. **Enter your credentials**:
   - AWS Access Key ID
   - AWS Secret Access Key
   - AWS Region (e.g., `us-east-1`)

5. **Click Test & Save**. Complyt will call `sts:GetCallerIdentity` to verify the credentials work.

6. **Run an evidence pack**. The CSPM check will now run as part of the pipeline and produce `cspm-aws.json`.

## Security

- Credentials are encrypted with **AES-256-GCM** before storage.
- The encryption key is derived from your machine's hostname and OS username using `scrypt`. It never leaves your machine.
- Credentials are stored in the local SQLite database — never transmitted to any external service.
- All AWS API calls are **read-only**. Complyt uses only `Describe*`, `Get*`, and `List*` operations.
- To remove credentials, delete them from the Settings page or delete the SQLite database.

## Troubleshooting

### "insufficient_permissions" errors

Some checks will report `error: insufficient_permissions` if your IAM policy doesn't include the required actions. Add the missing actions to your policy or accept partial results.

### Region-specific resources

IAM checks always run against `us-east-1` (IAM is a global service). All other checks run against the region you configured. Resources in other regions are not scanned.

### Credential test fails

Verify the access key is active in the AWS Console. Check that the IAM user has `sts:GetCallerIdentity` permission (included in the policy above).
