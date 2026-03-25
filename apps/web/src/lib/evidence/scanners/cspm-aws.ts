import {
  S3Client,
  ListBucketsCommand,
  GetPublicAccessBlockCommand,
  GetBucketEncryptionCommand,
  GetBucketVersioningCommand,
  GetBucketLoggingCommand,
} from "@aws-sdk/client-s3";
import {
  S3ControlClient,
  GetPublicAccessBlockCommand as GetAccountPublicAccessBlockCommand,
} from "@aws-sdk/client-s3-control";
import {
  IAMClient,
  GetAccountSummaryCommand,
  ListUsersCommand,
  ListMFADevicesCommand,
  ListAccessKeysCommand,
  ListPoliciesCommand,
  GetPolicyVersionCommand,
  GetAccountPasswordPolicyCommand,
} from "@aws-sdk/client-iam";
import {
  CloudTrailClient,
  DescribeTrailsCommand,
  GetTrailStatusCommand,
} from "@aws-sdk/client-cloudtrail";
import {
  EC2Client,
  DescribeSecurityGroupsCommand,
  DescribeVolumesCommand,
  DescribeInstancesCommand,
} from "@aws-sdk/client-ec2";
import {
  RDSClient,
  DescribeDBInstancesCommand,
} from "@aws-sdk/client-rds";
import {
  STSClient,
  GetCallerIdentityCommand,
} from "@aws-sdk/client-sts";
import {
  KMSClient,
  ListKeysCommand,
  GetKeyRotationStatusCommand,
  DescribeKeyCommand,
} from "@aws-sdk/client-kms";
import {
  CloudWatchLogsClient,
  DescribeLogGroupsCommand,
} from "@aws-sdk/client-cloudwatch-logs";

interface CspmCheckResult {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low";
  status: "pass" | "fail" | "error";
  error?: string;
  resources: Array<{ arn?: string; id?: string; detail: string }>;
}

interface CspmScanResult {
  scan_timestamp: string;
  scanner: string;
  provider: string;
  account_id: string;
  region: string;
  checks: CspmCheckResult[];
  summary: {
    total_checks: number;
    passed: number;
    failed: number;
    errors: number;
    by_severity: Record<string, number>;
  };
}

const CHECK_TIMEOUT_MS = 15_000;

type CheckFn = () => Promise<CspmCheckResult>;

function makeAbortSignal(): AbortSignal {
  return AbortSignal.timeout(CHECK_TIMEOUT_MS);
}

function isAccessDenied(err: unknown): boolean {
  if (err instanceof Error) {
    const name = (err as { name?: string }).name ?? "";
    const code = (err as { Code?: string }).Code ?? "";
    return (
      name === "AccessDeniedException" ||
      name === "AccessDenied" ||
      code === "AccessDenied" ||
      code === "AccessDeniedException" ||
      name === "UnauthorizedAccess" ||
      name.includes("AccessDenied")
    );
  }
  return false;
}

function accessDeniedResult(
  id: string,
  title: string,
  severity: CspmCheckResult["severity"],
): CspmCheckResult {
  return {
    id,
    title,
    severity,
    status: "error",
    error: "insufficient_permissions",
    resources: [],
  };
}

function errorResult(
  id: string,
  title: string,
  severity: CspmCheckResult["severity"],
  err: unknown,
): CspmCheckResult {
  if (isAccessDenied(err)) return accessDeniedResult(id, title, severity);
  return {
    id,
    title,
    severity,
    status: "error",
    error: err instanceof Error ? err.message : String(err),
    resources: [],
  };
}

// ---------------------------------------------------------------------------
// S3 Checks
// ---------------------------------------------------------------------------

function checkS3PublicAccessBlock(s3: S3Client): CheckFn {
  const id = "S3-01";
  const title = "S3 buckets should block public access";
  const severity = "critical" as const;

  return async () => {
    try {
      const { Buckets = [] } = await s3.send(
        new ListBucketsCommand({}),
        { abortSignal: makeAbortSignal() },
      );
      const resources: CspmCheckResult["resources"] = [];
      let allPass = true;

      for (const bucket of Buckets) {
        try {
          const resp = await s3.send(
            new GetPublicAccessBlockCommand({ Bucket: bucket.Name }),
            { abortSignal: makeAbortSignal() },
          );
          const cfg = resp.PublicAccessBlockConfiguration;
          if (
            !cfg?.BlockPublicAcls ||
            !cfg?.BlockPublicPolicy ||
            !cfg?.IgnorePublicAcls ||
            !cfg?.RestrictPublicBuckets
          ) {
            allPass = false;
            resources.push({
              arn: `arn:aws:s3:::${bucket.Name}`,
              detail: "Public access block is not fully enabled",
            });
          }
        } catch {
          allPass = false;
          resources.push({
            arn: `arn:aws:s3:::${bucket.Name}`,
            detail: "Public access block configuration not found",
          });
        }
      }

      return { id, title, severity, status: allPass ? "pass" : "fail", resources };
    } catch (err) {
      return errorResult(id, title, severity, err);
    }
  };
}

function checkS3Encryption(s3: S3Client): CheckFn {
  const id = "S3-02";
  const title = "S3 buckets should have server-side encryption enabled";
  const severity = "high" as const;

  return async () => {
    try {
      const { Buckets = [] } = await s3.send(
        new ListBucketsCommand({}),
        { abortSignal: makeAbortSignal() },
      );
      const resources: CspmCheckResult["resources"] = [];
      let allPass = true;

      for (const bucket of Buckets) {
        try {
          const resp = await s3.send(
            new GetBucketEncryptionCommand({ Bucket: bucket.Name }),
            { abortSignal: makeAbortSignal() },
          );
          const rules =
            resp.ServerSideEncryptionConfiguration?.Rules ?? [];
          if (rules.length === 0) {
            allPass = false;
            resources.push({
              arn: `arn:aws:s3:::${bucket.Name}`,
              detail: "No encryption rules configured",
            });
          }
        } catch {
          allPass = false;
          resources.push({
            arn: `arn:aws:s3:::${bucket.Name}`,
            detail: "Server-side encryption configuration not found",
          });
        }
      }

      return { id, title, severity, status: allPass ? "pass" : "fail", resources };
    } catch (err) {
      return errorResult(id, title, severity, err);
    }
  };
}

function checkS3Versioning(s3: S3Client): CheckFn {
  const id = "S3-03";
  const title = "S3 buckets should have versioning enabled";
  const severity = "medium" as const;

  return async () => {
    try {
      const { Buckets = [] } = await s3.send(
        new ListBucketsCommand({}),
        { abortSignal: makeAbortSignal() },
      );
      const resources: CspmCheckResult["resources"] = [];
      let allPass = true;

      for (const bucket of Buckets) {
        const resp = await s3.send(
          new GetBucketVersioningCommand({ Bucket: bucket.Name }),
          { abortSignal: makeAbortSignal() },
        );
        if (resp.Status !== "Enabled") {
          allPass = false;
          resources.push({
            arn: `arn:aws:s3:::${bucket.Name}`,
            detail: `Versioning status: ${resp.Status ?? "Disabled"}`,
          });
        }
      }

      return { id, title, severity, status: allPass ? "pass" : "fail", resources };
    } catch (err) {
      return errorResult(id, title, severity, err);
    }
  };
}

function checkS3Logging(s3: S3Client): CheckFn {
  const id = "S3-04";
  const title = "S3 buckets should have access logging enabled";
  const severity = "medium" as const;

  return async () => {
    try {
      const { Buckets = [] } = await s3.send(
        new ListBucketsCommand({}),
        { abortSignal: makeAbortSignal() },
      );
      const resources: CspmCheckResult["resources"] = [];
      let allPass = true;

      for (const bucket of Buckets) {
        const resp = await s3.send(
          new GetBucketLoggingCommand({ Bucket: bucket.Name }),
          { abortSignal: makeAbortSignal() },
        );
        if (!resp.LoggingEnabled) {
          allPass = false;
          resources.push({
            arn: `arn:aws:s3:::${bucket.Name}`,
            detail: "Access logging is not enabled",
          });
        }
      }

      return { id, title, severity, status: allPass ? "pass" : "fail", resources };
    } catch (err) {
      return errorResult(id, title, severity, err);
    }
  };
}

function checkS3AccountPublicAccessBlock(
  s3c: S3ControlClient,
  accountId: string,
): CheckFn {
  const id = "S3-05";
  const title = "S3 account-level public access block should be enabled";
  const severity = "critical" as const;

  return async () => {
    try {
      const resp = await s3c.send(
        new GetAccountPublicAccessBlockCommand({ AccountId: accountId }),
        { abortSignal: makeAbortSignal() },
      );
      const cfg = resp.PublicAccessBlockConfiguration;
      const resources: CspmCheckResult["resources"] = [];

      if (
        !cfg?.BlockPublicAcls ||
        !cfg?.BlockPublicPolicy ||
        !cfg?.IgnorePublicAcls ||
        !cfg?.RestrictPublicBuckets
      ) {
        resources.push({
          detail: "Account-level public access block is not fully enabled",
        });
        return { id, title, severity, status: "fail", resources };
      }

      return { id, title, severity, status: "pass", resources };
    } catch (err) {
      return errorResult(id, title, severity, err);
    }
  };
}

// ---------------------------------------------------------------------------
// IAM Checks
// ---------------------------------------------------------------------------

function checkIamRootMfa(iam: IAMClient): CheckFn {
  const id = "IAM-01";
  const title = "Root account should have MFA enabled";
  const severity = "critical" as const;

  return async () => {
    try {
      const resp = await iam.send(
        new GetAccountSummaryCommand({}),
        { abortSignal: makeAbortSignal() },
      );
      const mfaEnabled = resp.SummaryMap?.AccountMFAEnabled ?? 0;
      const resources: CspmCheckResult["resources"] = [];

      if (mfaEnabled === 0) {
        resources.push({ detail: "Root account MFA is not enabled" });
        return { id, title, severity, status: "fail", resources };
      }

      return { id, title, severity, status: "pass", resources };
    } catch (err) {
      return errorResult(id, title, severity, err);
    }
  };
}

function checkIamUserMfa(iam: IAMClient): CheckFn {
  const id = "IAM-02";
  const title = "All IAM users should have MFA enabled";
  const severity = "high" as const;

  return async () => {
    try {
      const { Users = [] } = await iam.send(
        new ListUsersCommand({}),
        { abortSignal: makeAbortSignal() },
      );
      const resources: CspmCheckResult["resources"] = [];
      let allPass = true;

      for (const user of Users) {
        const mfa = await iam.send(
          new ListMFADevicesCommand({ UserName: user.UserName }),
          { abortSignal: makeAbortSignal() },
        );
        if ((mfa.MFADevices ?? []).length === 0) {
          allPass = false;
          resources.push({
            arn: user.Arn,
            id: user.UserName,
            detail: "No MFA devices configured",
          });
        }
      }

      return { id, title, severity, status: allPass ? "pass" : "fail", resources };
    } catch (err) {
      return errorResult(id, title, severity, err);
    }
  };
}

function checkIamAccessKeyAge(iam: IAMClient): CheckFn {
  const id = "IAM-03";
  const title = "IAM access keys should be rotated within 90 days";
  const severity = "high" as const;

  return async () => {
    try {
      const { Users = [] } = await iam.send(
        new ListUsersCommand({}),
        { abortSignal: makeAbortSignal() },
      );
      const resources: CspmCheckResult["resources"] = [];
      let allPass = true;
      const ninetyDaysAgo = Date.now() - 90 * 24 * 60 * 60 * 1000;

      for (const user of Users) {
        const keys = await iam.send(
          new ListAccessKeysCommand({ UserName: user.UserName }),
          { abortSignal: makeAbortSignal() },
        );
        for (const key of keys.AccessKeyMetadata ?? []) {
          if (key.CreateDate && key.CreateDate.getTime() < ninetyDaysAgo) {
            allPass = false;
            resources.push({
              arn: user.Arn,
              id: key.AccessKeyId,
              detail: `Access key created ${key.CreateDate.toISOString()}, older than 90 days`,
            });
          }
        }
      }

      return { id, title, severity, status: allPass ? "pass" : "fail", resources };
    } catch (err) {
      return errorResult(id, title, severity, err);
    }
  };
}

function checkIamUnusedCredentials(iam: IAMClient): CheckFn {
  const id = "IAM-04";
  const title = "IAM user credentials should be used within 90 days";
  const severity = "medium" as const;

  return async () => {
    try {
      const { Users = [] } = await iam.send(
        new ListUsersCommand({}),
        { abortSignal: makeAbortSignal() },
      );
      const resources: CspmCheckResult["resources"] = [];
      let allPass = true;
      const ninetyDaysAgo = Date.now() - 90 * 24 * 60 * 60 * 1000;

      for (const user of Users) {
        const lastUsed = user.PasswordLastUsed;
        if (!lastUsed || lastUsed.getTime() < ninetyDaysAgo) {
          allPass = false;
          resources.push({
            arn: user.Arn,
            id: user.UserName,
            detail: lastUsed
              ? `Password last used ${lastUsed.toISOString()}, over 90 days ago`
              : "Password never used",
          });
        }
      }

      return { id, title, severity, status: allPass ? "pass" : "fail", resources };
    } catch (err) {
      return errorResult(id, title, severity, err);
    }
  };
}

function checkIamOverlyPermissivePolicies(iam: IAMClient): CheckFn {
  const id = "IAM-05";
  const title = "IAM policies should not allow full wildcard access";
  const severity = "critical" as const;

  return async () => {
    try {
      const { Policies = [] } = await iam.send(
        new ListPoliciesCommand({ Scope: "Local" }),
        { abortSignal: makeAbortSignal() },
      );
      const resources: CspmCheckResult["resources"] = [];
      let allPass = true;

      for (const policy of Policies) {
        if (!policy.DefaultVersionId || !policy.Arn) continue;

        const version = await iam.send(
          new GetPolicyVersionCommand({
            PolicyArn: policy.Arn,
            VersionId: policy.DefaultVersionId,
          }),
          { abortSignal: makeAbortSignal() },
        );

        const doc = version.PolicyVersion?.Document;
        if (!doc) continue;

        const parsed = JSON.parse(decodeURIComponent(doc));
        const statements = Array.isArray(parsed.Statement)
          ? parsed.Statement
          : [parsed.Statement];

        for (const stmt of statements) {
          if (stmt.Effect !== "Allow") continue;
          const actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
          const resourceList = Array.isArray(stmt.Resource)
            ? stmt.Resource
            : [stmt.Resource];
          if (actions.includes("*") && resourceList.includes("*")) {
            allPass = false;
            resources.push({
              arn: policy.Arn,
              id: policy.PolicyName,
              detail: "Policy allows Action:* on Resource:*",
            });
            break;
          }
        }
      }

      return { id, title, severity, status: allPass ? "pass" : "fail", resources };
    } catch (err) {
      return errorResult(id, title, severity, err);
    }
  };
}

function checkIamPasswordPolicy(iam: IAMClient): CheckFn {
  const id = "IAM-06";
  const title = "IAM password policy should enforce strong requirements";
  const severity = "high" as const;

  return async () => {
    try {
      const resp = await iam.send(
        new GetAccountPasswordPolicyCommand({}),
        { abortSignal: makeAbortSignal() },
      );
      const pp = resp.PasswordPolicy;
      const resources: CspmCheckResult["resources"] = [];
      const failures: string[] = [];

      if (!pp) {
        resources.push({ detail: "No password policy configured" });
        return { id, title, severity, status: "fail", resources };
      }

      if ((pp.MinimumPasswordLength ?? 0) < 14) {
        failures.push(`MinimumPasswordLength=${pp.MinimumPasswordLength ?? 0} (expected >=14)`);
      }
      if (!pp.RequireSymbols) failures.push("RequireSymbols is false");
      if (!pp.RequireNumbers) failures.push("RequireNumbers is false");
      if (!pp.RequireUppercaseCharacters) failures.push("RequireUppercaseCharacters is false");
      if (!pp.RequireLowercaseCharacters) failures.push("RequireLowercaseCharacters is false");

      if (failures.length > 0) {
        resources.push({ detail: failures.join("; ") });
        return { id, title, severity, status: "fail", resources };
      }

      return { id, title, severity, status: "pass", resources };
    } catch (err) {
      return errorResult(id, title, severity, err);
    }
  };
}

// ---------------------------------------------------------------------------
// CloudTrail Checks
// ---------------------------------------------------------------------------

function checkCloudTrailEnabled(ct: CloudTrailClient): CheckFn {
  const id = "CT-01";
  const title = "CloudTrail should be enabled";
  const severity = "critical" as const;

  return async () => {
    try {
      const { trailList = [] } = await ct.send(
        new DescribeTrailsCommand({}),
        { abortSignal: makeAbortSignal() },
      );

      if (trailList.length === 0) {
        return {
          id,
          title,
          severity,
          status: "fail",
          resources: [{ detail: "No CloudTrail trails configured" }],
        };
      }

      return { id, title, severity, status: "pass", resources: [] };
    } catch (err) {
      return errorResult(id, title, severity, err);
    }
  };
}

function checkCloudTrailLogging(ct: CloudTrailClient): CheckFn {
  const id = "CT-02";
  const title = "All CloudTrail trails should be actively logging";
  const severity = "critical" as const;

  return async () => {
    try {
      const { trailList = [] } = await ct.send(
        new DescribeTrailsCommand({}),
        { abortSignal: makeAbortSignal() },
      );
      const resources: CspmCheckResult["resources"] = [];
      let allPass = true;

      for (const trail of trailList) {
        const status = await ct.send(
          new GetTrailStatusCommand({ Name: trail.TrailARN }),
          { abortSignal: makeAbortSignal() },
        );
        if (!status.IsLogging) {
          allPass = false;
          resources.push({
            arn: trail.TrailARN,
            id: trail.Name,
            detail: "Trail is not actively logging",
          });
        }
      }

      return { id, title, severity, status: allPass ? "pass" : "fail", resources };
    } catch (err) {
      return errorResult(id, title, severity, err);
    }
  };
}

function checkCloudTrailLogValidation(ct: CloudTrailClient): CheckFn {
  const id = "CT-03";
  const title = "CloudTrail log file validation should be enabled";
  const severity = "high" as const;

  return async () => {
    try {
      const { trailList = [] } = await ct.send(
        new DescribeTrailsCommand({}),
        { abortSignal: makeAbortSignal() },
      );
      const resources: CspmCheckResult["resources"] = [];
      let allPass = true;

      for (const trail of trailList) {
        if (!trail.LogFileValidationEnabled) {
          allPass = false;
          resources.push({
            arn: trail.TrailARN,
            id: trail.Name,
            detail: "Log file validation is not enabled",
          });
        }
      }

      return { id, title, severity, status: allPass ? "pass" : "fail", resources };
    } catch (err) {
      return errorResult(id, title, severity, err);
    }
  };
}

// ---------------------------------------------------------------------------
// EC2/VPC Checks
// ---------------------------------------------------------------------------

function checkEc2SshOpen(ec2: EC2Client): CheckFn {
  const id = "EC2-01";
  const title = "Security groups should not allow unrestricted SSH access";
  const severity = "critical" as const;

  return async () => {
    try {
      const { SecurityGroups = [] } = await ec2.send(
        new DescribeSecurityGroupsCommand({}),
        { abortSignal: makeAbortSignal() },
      );
      const resources: CspmCheckResult["resources"] = [];
      let allPass = true;

      for (const sg of SecurityGroups) {
        for (const rule of sg.IpPermissions ?? []) {
          const from = rule.FromPort ?? 0;
          const to = rule.ToPort ?? 65535;
          if (from <= 22 && to >= 22) {
            const openCidrs = (rule.IpRanges ?? []).filter(
              (r) => r.CidrIp === "0.0.0.0/0",
            );
            const openIpv6 = (rule.Ipv6Ranges ?? []).filter(
              (r) => r.CidrIpv6 === "::/0",
            );
            if (openCidrs.length > 0 || openIpv6.length > 0) {
              allPass = false;
              resources.push({
                id: sg.GroupId,
                detail: `Security group ${sg.GroupName} allows SSH (port 22) from 0.0.0.0/0`,
              });
              break;
            }
          }
        }
      }

      return { id, title, severity, status: allPass ? "pass" : "fail", resources };
    } catch (err) {
      return errorResult(id, title, severity, err);
    }
  };
}

function checkEc2RdpOpen(ec2: EC2Client): CheckFn {
  const id = "EC2-02";
  const title = "Security groups should not allow unrestricted RDP access";
  const severity = "critical" as const;

  return async () => {
    try {
      const { SecurityGroups = [] } = await ec2.send(
        new DescribeSecurityGroupsCommand({}),
        { abortSignal: makeAbortSignal() },
      );
      const resources: CspmCheckResult["resources"] = [];
      let allPass = true;

      for (const sg of SecurityGroups) {
        for (const rule of sg.IpPermissions ?? []) {
          const from = rule.FromPort ?? 0;
          const to = rule.ToPort ?? 65535;
          if (from <= 3389 && to >= 3389) {
            const openCidrs = (rule.IpRanges ?? []).filter(
              (r) => r.CidrIp === "0.0.0.0/0",
            );
            const openIpv6 = (rule.Ipv6Ranges ?? []).filter(
              (r) => r.CidrIpv6 === "::/0",
            );
            if (openCidrs.length > 0 || openIpv6.length > 0) {
              allPass = false;
              resources.push({
                id: sg.GroupId,
                detail: `Security group ${sg.GroupName} allows RDP (port 3389) from 0.0.0.0/0`,
              });
              break;
            }
          }
        }
      }

      return { id, title, severity, status: allPass ? "pass" : "fail", resources };
    } catch (err) {
      return errorResult(id, title, severity, err);
    }
  };
}

function checkEc2DefaultSg(ec2: EC2Client): CheckFn {
  const id = "EC2-03";
  const title = "Default security groups should restrict all inbound traffic";
  const severity = "high" as const;

  return async () => {
    try {
      const { SecurityGroups = [] } = await ec2.send(
        new DescribeSecurityGroupsCommand({
          Filters: [{ Name: "group-name", Values: ["default"] }],
        }),
        { abortSignal: makeAbortSignal() },
      );
      const resources: CspmCheckResult["resources"] = [];
      let allPass = true;

      for (const sg of SecurityGroups) {
        if ((sg.IpPermissions ?? []).length > 0) {
          allPass = false;
          resources.push({
            id: sg.GroupId,
            detail: `Default security group in VPC ${sg.VpcId} has ${sg.IpPermissions!.length} inbound rule(s)`,
          });
        }
      }

      return { id, title, severity, status: allPass ? "pass" : "fail", resources };
    } catch (err) {
      return errorResult(id, title, severity, err);
    }
  };
}

function checkEc2EbsEncryption(ec2: EC2Client): CheckFn {
  const id = "EC2-04";
  const title = "EBS volumes should be encrypted";
  const severity = "high" as const;

  return async () => {
    try {
      const { Volumes = [] } = await ec2.send(
        new DescribeVolumesCommand({}),
        { abortSignal: makeAbortSignal() },
      );
      const resources: CspmCheckResult["resources"] = [];
      let allPass = true;

      for (const vol of Volumes) {
        if (!vol.Encrypted) {
          allPass = false;
          resources.push({
            id: vol.VolumeId,
            detail: `EBS volume ${vol.VolumeId} is not encrypted`,
          });
        }
      }

      return { id, title, severity, status: allPass ? "pass" : "fail", resources };
    } catch (err) {
      return errorResult(id, title, severity, err);
    }
  };
}

function checkEc2ImdsV2(ec2: EC2Client): CheckFn {
  const id = "EC2-05";
  const title = "EC2 instances should require IMDSv2";
  const severity = "high" as const;

  return async () => {
    try {
      const { Reservations = [] } = await ec2.send(
        new DescribeInstancesCommand({}),
        { abortSignal: makeAbortSignal() },
      );
      const resources: CspmCheckResult["resources"] = [];
      let allPass = true;

      for (const res of Reservations) {
        for (const inst of res.Instances ?? []) {
          if (inst.MetadataOptions?.HttpTokens !== "required") {
            allPass = false;
            resources.push({
              id: inst.InstanceId,
              detail: `Instance ${inst.InstanceId} does not require IMDSv2 (HttpTokens=${inst.MetadataOptions?.HttpTokens ?? "unknown"})`,
            });
          }
        }
      }

      return { id, title, severity, status: allPass ? "pass" : "fail", resources };
    } catch (err) {
      return errorResult(id, title, severity, err);
    }
  };
}

// ---------------------------------------------------------------------------
// RDS Checks
// ---------------------------------------------------------------------------

function checkRdsEncryption(rds: RDSClient): CheckFn {
  const id = "RDS-01";
  const title = "RDS instances should have storage encryption enabled";
  const severity = "high" as const;

  return async () => {
    try {
      const { DBInstances = [] } = await rds.send(
        new DescribeDBInstancesCommand({}),
        { abortSignal: makeAbortSignal() },
      );
      const resources: CspmCheckResult["resources"] = [];
      let allPass = true;

      for (const db of DBInstances) {
        if (!db.StorageEncrypted) {
          allPass = false;
          resources.push({
            arn: db.DBInstanceArn,
            id: db.DBInstanceIdentifier,
            detail: "Storage encryption is not enabled",
          });
        }
      }

      return { id, title, severity, status: allPass ? "pass" : "fail", resources };
    } catch (err) {
      return errorResult(id, title, severity, err);
    }
  };
}

function checkRdsPublicAccess(rds: RDSClient): CheckFn {
  const id = "RDS-02";
  const title = "RDS instances should not be publicly accessible";
  const severity = "critical" as const;

  return async () => {
    try {
      const { DBInstances = [] } = await rds.send(
        new DescribeDBInstancesCommand({}),
        { abortSignal: makeAbortSignal() },
      );
      const resources: CspmCheckResult["resources"] = [];
      let allPass = true;

      for (const db of DBInstances) {
        if (db.PubliclyAccessible) {
          allPass = false;
          resources.push({
            arn: db.DBInstanceArn,
            id: db.DBInstanceIdentifier,
            detail: "Instance is publicly accessible",
          });
        }
      }

      return { id, title, severity, status: allPass ? "pass" : "fail", resources };
    } catch (err) {
      return errorResult(id, title, severity, err);
    }
  };
}

function checkRdsBackup(rds: RDSClient): CheckFn {
  const id = "RDS-03";
  const title = "RDS instances should have automated backups enabled";
  const severity = "high" as const;

  return async () => {
    try {
      const { DBInstances = [] } = await rds.send(
        new DescribeDBInstancesCommand({}),
        { abortSignal: makeAbortSignal() },
      );
      const resources: CspmCheckResult["resources"] = [];
      let allPass = true;

      for (const db of DBInstances) {
        if ((db.BackupRetentionPeriod ?? 0) === 0) {
          allPass = false;
          resources.push({
            arn: db.DBInstanceArn,
            id: db.DBInstanceIdentifier,
            detail: "Backup retention period is 0 (backups disabled)",
          });
        }
      }

      return { id, title, severity, status: allPass ? "pass" : "fail", resources };
    } catch (err) {
      return errorResult(id, title, severity, err);
    }
  };
}

// ---------------------------------------------------------------------------
// KMS Checks
// ---------------------------------------------------------------------------

function checkKmsKeyRotation(kms: KMSClient): CheckFn {
  const id = "KMS-01";
  const title = "KMS customer-managed keys should have rotation enabled";
  const severity = "medium" as const;

  return async () => {
    try {
      const { Keys = [] } = await kms.send(
        new ListKeysCommand({}),
        { abortSignal: makeAbortSignal() },
      );
      const resources: CspmCheckResult["resources"] = [];
      let allPass = true;

      for (const key of Keys) {
        if (!key.KeyId) continue;

        const desc = await kms.send(
          new DescribeKeyCommand({ KeyId: key.KeyId }),
          { abortSignal: makeAbortSignal() },
        );

        if (desc.KeyMetadata?.KeyManager !== "CUSTOMER") continue;
        if (desc.KeyMetadata?.KeyState !== "Enabled") continue;

        const rotation = await kms.send(
          new GetKeyRotationStatusCommand({ KeyId: key.KeyId }),
          { abortSignal: makeAbortSignal() },
        );

        if (!rotation.KeyRotationEnabled) {
          allPass = false;
          resources.push({
            arn: desc.KeyMetadata?.Arn,
            id: key.KeyId,
            detail: "Key rotation is not enabled",
          });
        }
      }

      return { id, title, severity, status: allPass ? "pass" : "fail", resources };
    } catch (err) {
      return errorResult(id, title, severity, err);
    }
  };
}

function checkKmsPendingDeletion(kms: KMSClient): CheckFn {
  const id = "KMS-02";
  const title = "KMS keys should not be scheduled for deletion";
  const severity = "high" as const;

  return async () => {
    try {
      const { Keys = [] } = await kms.send(
        new ListKeysCommand({}),
        { abortSignal: makeAbortSignal() },
      );
      const resources: CspmCheckResult["resources"] = [];
      let allPass = true;

      for (const key of Keys) {
        if (!key.KeyId) continue;

        const desc = await kms.send(
          new DescribeKeyCommand({ KeyId: key.KeyId }),
          { abortSignal: makeAbortSignal() },
        );

        if (desc.KeyMetadata?.KeyState === "PendingDeletion") {
          allPass = false;
          resources.push({
            arn: desc.KeyMetadata?.Arn,
            id: key.KeyId,
            detail: `Key is pending deletion (scheduled: ${desc.KeyMetadata?.DeletionDate?.toISOString() ?? "unknown"})`,
          });
        }
      }

      return { id, title, severity, status: allPass ? "pass" : "fail", resources };
    } catch (err) {
      return errorResult(id, title, severity, err);
    }
  };
}

// ---------------------------------------------------------------------------
// CloudWatch Logs Check
// ---------------------------------------------------------------------------

function checkLogRetention(cwl: CloudWatchLogsClient): CheckFn {
  const id = "LOG-01";
  const title = "CloudWatch log groups should have a retention policy";
  const severity = "medium" as const;

  return async () => {
    try {
      const { logGroups = [] } = await cwl.send(
        new DescribeLogGroupsCommand({}),
        { abortSignal: makeAbortSignal() },
      );
      const resources: CspmCheckResult["resources"] = [];
      let allPass = true;

      for (const lg of logGroups) {
        if (lg.retentionInDays === undefined) {
          allPass = false;
          resources.push({
            arn: lg.arn,
            id: lg.logGroupName,
            detail: "No retention policy set (logs retained indefinitely)",
          });
        }
      }

      return { id, title, severity, status: allPass ? "pass" : "fail", resources };
    } catch (err) {
      return errorResult(id, title, severity, err);
    }
  };
}

// ---------------------------------------------------------------------------
// Concurrency-limited runner
// ---------------------------------------------------------------------------

async function runWithConcurrency(
  checks: CheckFn[],
  limit: number,
): Promise<CspmCheckResult[]> {
  const results: CspmCheckResult[] = [];
  let idx = 0;

  async function next(): Promise<void> {
    while (idx < checks.length) {
      const current = idx++;
      results[current] = await checks[current]();
    }
  }

  const workers = Array.from({ length: Math.min(limit, checks.length) }, () =>
    next(),
  );
  await Promise.allSettled(workers);
  return results;
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

export async function runCspmAwsScan(credentials: {
  accessKeyId: string;
  secretAccessKey: string;
  region: string;
}): Promise<CspmScanResult> {
  const clientConfig = {
    region: credentials.region,
    credentials: {
      accessKeyId: credentials.accessKeyId,
      secretAccessKey: credentials.secretAccessKey,
    },
  };

  const sts = new STSClient(clientConfig);

  let accountId: string;
  try {
    const identity = await sts.send(
      new GetCallerIdentityCommand({}),
      { abortSignal: makeAbortSignal() },
    );
    accountId = identity.Account ?? "unknown";
  } catch {
    return {
      scan_timestamp: new Date().toISOString(),
      scanner: "cspm-aws",
      provider: "aws",
      account_id: "unknown",
      region: credentials.region,
      checks: [],
      summary: {
        total_checks: 0,
        passed: 0,
        failed: 0,
        errors: 1,
        by_severity: {},
      },
    };
  }

  const s3 = new S3Client(clientConfig);
  const s3c = new S3ControlClient(clientConfig);
  const iam = new IAMClient({ ...clientConfig, region: "us-east-1" });
  const ct = new CloudTrailClient(clientConfig);
  const ec2 = new EC2Client(clientConfig);
  const rds = new RDSClient(clientConfig);
  const kms = new KMSClient(clientConfig);
  const cwl = new CloudWatchLogsClient(clientConfig);

  const allChecks: CheckFn[] = [
    checkS3PublicAccessBlock(s3),
    checkS3Encryption(s3),
    checkS3Versioning(s3),
    checkS3Logging(s3),
    checkS3AccountPublicAccessBlock(s3c, accountId),
    checkIamRootMfa(iam),
    checkIamUserMfa(iam),
    checkIamAccessKeyAge(iam),
    checkIamUnusedCredentials(iam),
    checkIamOverlyPermissivePolicies(iam),
    checkIamPasswordPolicy(iam),
    checkCloudTrailEnabled(ct),
    checkCloudTrailLogging(ct),
    checkCloudTrailLogValidation(ct),
    checkEc2SshOpen(ec2),
    checkEc2RdpOpen(ec2),
    checkEc2DefaultSg(ec2),
    checkEc2EbsEncryption(ec2),
    checkEc2ImdsV2(ec2),
    checkRdsEncryption(rds),
    checkRdsPublicAccess(rds),
    checkRdsBackup(rds),
    checkKmsKeyRotation(kms),
    checkKmsPendingDeletion(kms),
    checkLogRetention(cwl),
  ];

  const checks = await runWithConcurrency(allChecks, 5);

  const passed = checks.filter((c) => c.status === "pass").length;
  const failed = checks.filter((c) => c.status === "fail").length;
  const errors = checks.filter((c) => c.status === "error").length;

  const bySeverity: Record<string, number> = {};
  for (const c of checks) {
    if (c.status === "fail") {
      bySeverity[c.severity] = (bySeverity[c.severity] ?? 0) + 1;
    }
  }

  return {
    scan_timestamp: new Date().toISOString(),
    scanner: "cspm-aws",
    provider: "aws",
    account_id: accountId,
    region: credentials.region,
    checks,
    summary: {
      total_checks: checks.length,
      passed,
      failed,
      errors,
      by_severity: bySeverity,
    },
  };
}
