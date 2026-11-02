"""
CloudSentinel - Rules (بتحلل خصائص حقيقية، مش أعلام جاهزة)

كل قاعدة بتاخد Resource موحّد وبترجع Outcome فيه status:
  PASS            الأدلة المتاحة تؤكد إن الفحص عدّى
  FAIL            الأدلة المتاحة تؤكد وجود مخالفة
  UNKNOWN         مفيش معلومات كافية للحكم (قيمة ديناميكية أو ناقصة)
  NOT_APPLICABLE  القاعدة مش بتنطبق على المورد ده
"""

from .model import (
    DYNAMIC,
    FAIL,
    MISSING,
    NOT_APPLICABLE,
    PASS,
    UNKNOWN,
    Outcome,
    Resource,
    Rule,
    and3,
    clean,
    or3,
)
from .parser import WORLD_CIDRS

SENSITIVE_PORTS = {
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "SQL Server",
    1521: "Oracle",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
}


# =================================================================== S3

def s3_public_acl(r: Resource) -> Outcome:
    acl = r.data["acl"]
    if acl is DYNAMIC:
        return Outcome(UNKNOWN, "AccessControl is a dynamic value (Ref/Fn::*) and cannot be evaluated.")
    if acl in ("PublicRead", "PublicReadWrite"):
        severity = "CRITICAL" if acl == "PublicReadWrite" else None
        return Outcome(
            FAIL,
            f"The bucket uses the public canned ACL '{acl}'.",
            {"AccessControl": acl},
            severity,
        )
    return Outcome(PASS, "No public canned ACL is set. Bucket policies and account-level settings are not evaluated.")


def s3_block_public_access(r: Resource) -> Outcome:
    block = r.data["block"]
    if block is MISSING:
        return Outcome(
            FAIL,
            "PublicAccessBlockConfiguration is not set on the bucket.",
            {"PublicAccessBlockConfiguration": "not set"},
        )
    if block is DYNAMIC:
        return Outcome(UNKNOWN, "PublicAccessBlockConfiguration is a dynamic value and cannot be evaluated.")
    not_enabled = [k for k, v in block.items() if v is False or v is MISSING]
    unknown = [k for k, v in block.items() if v is DYNAMIC]
    if not_enabled:
        return Outcome(
            FAIL,
            "Not all four Block Public Access settings are enabled.",
            {"not_enabled": not_enabled},
        )
    if unknown:
        return Outcome(UNKNOWN, "Some Block Public Access settings are dynamic values.", {"unresolved": unknown})
    return Outcome(PASS, "All four Block Public Access settings are enabled.")


def s3_encryption(r: Resource) -> Outcome:
    value = r.data["encryption"]
    if value is MISSING:
        return Outcome(
            FAIL,
            "No explicit encryption configuration (BucketEncryption) is defined.",
            {"BucketEncryption": "not set"},
        )
    if value is DYNAMIC:
        return Outcome(UNKNOWN, "BucketEncryption is a dynamic value and cannot be evaluated.")
    return Outcome(PASS, "An explicit encryption configuration is defined.")


def s3_versioning(r: Resource) -> Outcome:
    value = r.data["versioning"]
    if value is DYNAMIC:
        return Outcome(UNKNOWN, "Versioning status is a dynamic value and cannot be evaluated.")
    if value == "Enabled":
        return Outcome(PASS, "Versioning is enabled.")
    return Outcome(
        FAIL,
        "Versioning is not enabled.",
        {"VersioningConfiguration.Status": clean(value)},
    )


def s3_logging(r: Resource) -> Outcome:
    value = r.data["logging"]
    if value is MISSING and r.data["is_log_destination"]:
        return Outcome(
            NOT_APPLICABLE,
            "This bucket receives access logs from another bucket in the template. Log buckets are normally not configured to log themselves.",
        )
    if value is MISSING:
        return Outcome(FAIL, "Server access logging is not configured.", {"LoggingConfiguration": "not set"})
    if value is DYNAMIC:
        return Outcome(UNKNOWN, "LoggingConfiguration is a dynamic value and cannot be evaluated.")
    return Outcome(PASS, "Server access logging is configured.")


# ================================================== Security Group (ingress)

def _world(item):
    if item.get("dynamic"):
        return DYNAMIC
    cidrs = item["cidrs"]
    if any(isinstance(c, str) and c in WORLD_CIDRS for c in cidrs):
        return True
    if any(c is DYNAMIC for c in cidrs):
        return DYNAMIC
    return False


def _covers_port(item, port):
    if item.get("dynamic"):
        return DYNAMIC
    protocol = item["protocol"]
    if protocol == "-1":
        return True
    if protocol == "tcp":
        low, high = item["from_port"], item["to_port"]
        if not isinstance(low, int) or not isinstance(high, int):
            return DYNAMIC
        return low <= port <= high
    if isinstance(protocol, str):
        return False  # udp / icmp ... مش بتغطي بورتات TCP
    return DYNAMIC


def _covers_all_ports(item):
    if item.get("dynamic"):
        return DYNAMIC
    protocol = item["protocol"]
    if protocol == "-1":
        return True
    if protocol in ("tcp", "udp"):
        low, high = item["from_port"], item["to_port"]
        if not isinstance(low, int) or not isinstance(high, int):
            return DYNAMIC
        return low <= 0 and high >= 65535
    if isinstance(protocol, str):
        return False
    return DYNAMIC


def _describe(index, item, extra=None):
    evidence = {
        "ingress_rule_index": index,
        "protocol": clean(item["protocol"]),
        "from_port": clean(item["from_port"]),
        "to_port": clean(item["to_port"]),
        "source": [c for c in item["cidrs"] if isinstance(c, str) and c in WORLD_CIDRS],
    }
    if extra:
        evidence.update(extra)
    return evidence


def _scan_ingress(r: Resource, evaluate, what: str) -> Outcome:
    """evaluate(item) -> (verdict, extra_evidence). verdict: True / False / DYNAMIC."""
    ingress = r.data["ingress"]
    if ingress is DYNAMIC:
        return Outcome(UNKNOWN, "SecurityGroupIngress is a dynamic value and cannot be evaluated.")

    matches, unresolved = [], 0
    for index, item in enumerate(ingress):
        verdict, extra = evaluate(item)
        if verdict is True:
            matches.append(_describe(index, item, extra))
        elif verdict is DYNAMIC:
            unresolved += 1

    if matches:
        return Outcome(FAIL, f"{len(matches)} ingress rule(s) allow {what} from the internet.", matches)
    if unresolved:
        return Outcome(
            UNKNOWN,
            f"{unresolved} ingress rule(s) contain dynamic values, so exposure of {what} cannot be confirmed.",
        )
    return Outcome(PASS, f"No ingress rule allows {what} from the internet.")


def sg_ssh(r: Resource) -> Outcome:
    return _scan_ingress(r, lambda i: (and3(_world(i), _covers_port(i, 22)), None), "SSH (port 22)")


def sg_rdp(r: Resource) -> Outcome:
    return _scan_ingress(r, lambda i: (and3(_world(i), _covers_port(i, 3389)), None), "RDP (port 3389)")


def sg_all_ports(r: Resource) -> Outcome:
    return _scan_ingress(r, lambda i: (and3(_world(i), _covers_all_ports(i)), None), "all ports")


def _sensitive(item):
    covered = [p for p in SENSITIVE_PORTS if _covers_port(item, p) is True]
    maybe = any(_covers_port(item, p) is DYNAMIC for p in SENSITIVE_PORTS)
    covers = True if covered else (DYNAMIC if maybe else False)
    return and3(_world(item), covers), {"data_store_ports": covered}


def sg_data_ports(r: Resource) -> Outcome:
    return _scan_ingress(r, _sensitive, "database/data-store ports")


# ==================================================================== RDS

def rds_public(r: Resource) -> Outcome:
    value = r.data["publicly_accessible"]
    if value is True:
        return Outcome(FAIL, "The database instance is publicly accessible.", {"PubliclyAccessible": True})
    if value is False:
        return Outcome(PASS, "The database instance is not publicly accessible.")
    if value is MISSING:
        return Outcome(UNKNOWN, "PubliclyAccessible is not set; the default depends on the VPC/subnet group.")
    return Outcome(UNKNOWN, "PubliclyAccessible is a dynamic value and cannot be evaluated.")


def rds_encryption(r: Resource) -> Outcome:
    value = r.data["storage_encrypted"]
    if value is True:
        return Outcome(PASS, "Storage encryption is enabled.")
    if value is False:
        return Outcome(FAIL, "Storage encryption is explicitly disabled.", {"StorageEncrypted": False})
    if value is MISSING:
        if r.data["derived"]:
            return Outcome(UNKNOWN, "StorageEncrypted is not set; the instance is a replica, a restore, or a cluster member, so encryption is inherited or defined on the cluster (not analyzed).")
        return Outcome(FAIL, "StorageEncrypted is not set, so the instance is not encrypted by default.", {"StorageEncrypted": "not set"})
    return Outcome(UNKNOWN, "StorageEncrypted is a dynamic value and cannot be evaluated.")


def rds_backups(r: Resource) -> Outcome:
    value = r.data["backup_retention"]
    if isinstance(value, int):
        if value == 0:
            return Outcome(FAIL, "Automated backups are disabled (retention period is 0).", {"BackupRetentionPeriod": 0})
        return Outcome(PASS, f"Automated backups are enabled (retention {value} day(s)).")
    if value is MISSING:
        if r.data["derived"]:
            return Outcome(UNKNOWN, "BackupRetentionPeriod is not set on a replica, a restore, or a cluster member; it is inherited or defined elsewhere (not analyzed).")
        return Outcome(PASS, "BackupRetentionPeriod is not set; the CloudFormation default (1 day) enables backups.")
    return Outcome(UNKNOWN, "BackupRetentionPeriod is a dynamic value and cannot be evaluated.")


def rds_password(r: Resource) -> Outcome:
    value = r.data["password"]
    if value is MISSING:
        return Outcome(NOT_APPLICABLE, "No MasterUserPassword is defined in the template.")
    if value == "literal":
        # بنقول إنه literal من غير ما نعرض قيمته
        return Outcome(
            FAIL,
            "MasterUserPassword is written as a plain-text value in the template (value hidden).",
            {"MasterUserPassword": "literal string (hidden)"},
        )
    if value == "reference":
        return Outcome(PASS, "MasterUserPassword comes from a reference (parameter or secret), not a literal.")
    return Outcome(UNKNOWN, "MasterUserPassword has an unrecognized shape.")


# ==================================================================== IAM

def _allow(statement):
    if statement.get("dynamic"):
        return DYNAMIC
    effect = statement["effect"]
    if effect == "Allow":
        return True
    if effect == "Deny":
        return False
    return DYNAMIC


def _has(values, predicate):
    if any(isinstance(v, str) and predicate(v) for v in values):
        return True
    if any(v is DYNAMIC for v in values):
        return DYNAMIC
    return False


def _scan_statements(r: Resource, evaluate, what: str, pass_text: str) -> Outcome:
    matches, unresolved, severity = [], 0, None
    for index, statement in enumerate(r.data["statements"]):
        allow = _allow(statement)
        if allow is False:
            continue
        if statement.get("dynamic") or statement["not_action"] or statement["not_resource"]:
            unresolved += 1
            continue
        verdict, evidence, sev = evaluate(statement, allow)
        if verdict is True:
            matches.append({"statement_index": index, **evidence})
            severity = severity or sev
        elif verdict is DYNAMIC:
            unresolved += 1

    if matches:
        return Outcome(FAIL, f"{len(matches)} statement(s) {what}.", matches, severity)
    if unresolved:
        return Outcome(UNKNOWN, "Some statements are dynamic or use NotAction/NotResource and were not analyzed.")
    return Outcome(PASS, pass_text)


def iam_full_admin(r: Resource) -> Outcome:
    def evaluate(s, allow):
        verdict = and3(allow, _has(s["actions"], lambda a: a == "*"), _has(s["resources"], lambda x: x == "*"))
        return verdict, {"actions": clean(s["actions"]), "resources": clean(s["resources"])}, None

    return _scan_statements(r, evaluate, "allow all actions on all resources", "No statement allows all actions on all resources.")


def iam_service_wildcard(r: Resource) -> Outcome:
    def evaluate(s, allow):
        matched = [a for a in s["actions"] if isinstance(a, str) and a.endswith(":*")]
        actions = True if matched else or3(*[DYNAMIC for a in s["actions"] if a is DYNAMIC])
        verdict = and3(allow, actions, _has(s["resources"], lambda x: x == "*"))
        severity = "HIGH" if any(a.lower().startswith("iam:") for a in matched) else None
        return verdict, {"actions": matched, "resources": clean(s["resources"])}, severity

    return _scan_statements(
        r,
        evaluate,
        "allow a service-wide wildcard action on all resources",
        "No statement allows a service-wide wildcard action on all resources.",
    )


# =============================================================== registry

RULES = [
    Rule(
        "S3-001", "Public bucket ACL", "HIGH", "storage",
        "Anyone on the internet may be able to read (or write) objects in the bucket.",
        "Use a private ACL, enable Block Public Access, and grant access to specific identities only.",
        "AWS Docs: Blocking public access to your Amazon S3 storage",
        s3_public_acl,
    ),
    Rule(
        "S3-002", "Block Public Access not fully enabled", "MEDIUM", "storage",
        "Without all four Block Public Access settings, a future ACL or policy change can make data public by mistake.",
        "Enable BlockPublicAcls, BlockPublicPolicy, IgnorePublicAcls and RestrictPublicBuckets.",
        "AWS Docs: Blocking public access to your Amazon S3 storage",
        s3_block_public_access,
    ),
    Rule(
        "S3-003", "No explicit bucket encryption", "LOW", "storage",
        "New S3 objects are encrypted by default, but without an explicit configuration you cannot enforce the key type or use your own KMS key.",
        "Define BucketEncryption (SSE-S3 or SSE-KMS) explicitly.",
        "AWS Docs: Protecting data with server-side encryption",
        s3_encryption,
    ),
    Rule(
        "S3-004", "Versioning not enabled", "LOW", "storage",
        "Deleted or overwritten objects (including by ransomware or mistakes) cannot be restored.",
        "Enable versioning with VersioningConfiguration.Status = Enabled.",
        "AWS Docs: Using versioning in S3 buckets",
        s3_versioning,
    ),
    Rule(
        "S3-005", "Server access logging not configured", "LOW", "storage",
        "There is no audit trail of requests made to the bucket.",
        "Configure LoggingConfiguration to a separate, protected log bucket.",
        "AWS Docs: Logging requests with server access logging",
        s3_logging,
    ),
    Rule(
        "SG-001", "SSH open to the internet", "HIGH", "firewall",
        "Attackers can continuously attempt brute-force or credential-stuffing attacks against SSH.",
        "Restrict port 22 to trusted CIDR ranges, or use a VPN / Session Manager.",
        "AWS Docs: Security group rules for different use cases",
        sg_ssh,
    ),
    Rule(
        "SG-002", "RDP open to the internet", "HIGH", "firewall",
        "RDP exposed to the internet is a common target for brute force and ransomware.",
        "Restrict port 3389 to trusted CIDR ranges, or use a VPN / bastion host.",
        "AWS Docs: Security group rules for different use cases",
        sg_rdp,
    ),
    Rule(
        "SG-003", "All ports open to the internet", "CRITICAL", "firewall",
        "Every service on the instance is reachable from anywhere, which greatly increases the attack surface.",
        "Allow only the specific ports the workload needs, from the narrowest possible source.",
        "AWS Docs: Security group best practices",
        sg_all_ports,
    ),
    Rule(
        "SG-004", "Database/data-store ports open to the internet", "HIGH", "firewall",
        "Databases and caches exposed to the internet can be attacked directly (weak credentials, unpatched vulnerabilities).",
        "Allow database ports only from application security groups or private ranges.",
        "AWS Docs: Security group best practices",
        sg_data_ports,
    ),
    Rule(
        "RDS-001", "Database publicly accessible", "CRITICAL", "database",
        "The database endpoint can be reached from the internet, exposing it to direct attacks.",
        "Set PubliclyAccessible to false and place the database in private subnets.",
        "AWS Docs: Working with a DB instance in a VPC",
        rds_public,
    ),
    Rule(
        "RDS-002", "Database storage not encrypted", "HIGH", "database",
        "Data at rest, snapshots and backups can be read in plain text if the underlying storage is accessed.",
        "Set StorageEncrypted to true (and use a KMS key you control for sensitive data).",
        "AWS Docs: Encrypting Amazon RDS resources",
        rds_encryption,
    ),
    Rule(
        "RDS-003", "Automated backups disabled", "MEDIUM", "database",
        "Data loss from failure, deletion or attack may be unrecoverable.",
        "Set BackupRetentionPeriod to at least 7 and test restoring from backups.",
        "AWS Docs: Working with backups",
        rds_backups,
    ),
    Rule(
        "RDS-004", "Master password written in the template", "CRITICAL", "database",
        "Anyone with access to the template or repository can read the database password.",
        "Use a NoEcho parameter, AWS Secrets Manager, or ManageMasterUserPassword instead of a literal value.",
        "AWS Docs: Dynamic references / Secrets Manager with CloudFormation",
        rds_password,
    ),
    Rule(
        "IAM-001", "Full administrator permissions", "CRITICAL", "iam_policy",
        "If this identity is compromised, the attacker gets full control of the account.",
        "Grant only the specific actions and resources the identity needs (least privilege).",
        "AWS Docs: IAM security best practices (least privilege)",
        iam_full_admin,
    ),
    Rule(
        "IAM-002", "Service-wide wildcard on all resources", "MEDIUM", "iam_policy",
        "Allowing every action of a service on every resource is broader than most workloads need.",
        "Replace the wildcard with the specific actions required and scope resources to ARNs.",
        "AWS Docs: IAM security best practices (least privilege)",
        iam_service_wildcard,
    ),
]
