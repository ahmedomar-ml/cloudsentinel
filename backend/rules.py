"""
CloudSentinel - Security Rules Engine

كل قاعدة (rule) هي function بتاخد الـ config كله وبترجع:
  - dict فيه المشكلة لو لقت مشكلة
  - None لو الإعداد سليم

الـ config بيبقى شكله كده:
{
  "storage": {...}, "network": {...}, "database": {...}, "compute": {...}, "iam": {...}
}
"""

from typing import Callable, Optional

Finding = dict
Rule = Callable[[dict], Optional[Finding]]


def _finding(rule_id, title, severity, resource, description, impact, recommendation, reference, evidence):
    return {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "resource": resource,
        "description": description,
        "impact": impact,
        "recommendation": recommendation,
        "reference": reference,
        "evidence": evidence,  # الإعداد اللي اتسبب في اكتشاف المشكلة
    }


# ---------------------------------------------------------------- Storage

def check_public_storage(config: dict) -> Optional[Finding]:
    storage = config.get("storage", {})
    if storage.get("public_access") is True:
        return _finding(
            "CLOUD-001", "Public Storage Access", "HIGH",
            f"storage:{storage.get('name', 'unknown')}",
            "The storage bucket allows public access.",
            "Anyone on the internet may be able to read the stored files. If they contain sensitive data, this can lead to a data breach.",
            "Disable public access and grant access only to specific identities that need it.",
            "CIS Cloud Benchmarks - Storage Access Control",
            {"public_access": True},
        )
    return None


def check_storage_encryption(config: dict) -> Optional[Finding]:
    storage = config.get("storage", {})
    if storage.get("encryption_enabled") is False:
        return _finding(
            "CLOUD-002", "Storage Encryption Disabled", "HIGH",
            f"storage:{storage.get('name', 'unknown')}",
            "Data at rest in the storage is not encrypted.",
            "If the underlying disks or backups are accessed, the data can be read in plain text.",
            "Enable server-side encryption (preferably with customer-managed keys for sensitive data).",
            "OWASP Cloud-Native Application Security - Data Protection",
            {"encryption_enabled": False},
        )
    return None


def check_storage_versioning(config: dict) -> Optional[Finding]:
    storage = config.get("storage", {})
    if storage.get("versioning_enabled") is False:
        return _finding(
            "CLOUD-003", "Storage Versioning Disabled", "LOW",
            f"storage:{storage.get('name', 'unknown')}",
            "Object versioning is turned off for the storage.",
            "Accidental deletion or overwriting (including by ransomware) cannot be easily recovered.",
            "Enable versioning so previous versions of objects can be restored.",
            "CIS Cloud Benchmarks - Storage Resilience",
            {"versioning_enabled": False},
        )
    return None


def check_storage_logging(config: dict) -> Optional[Finding]:
    storage = config.get("storage", {})
    if storage.get("access_logging") is False:
        return _finding(
            "CLOUD-004", "Storage Access Logging Disabled", "MEDIUM",
            f"storage:{storage.get('name', 'unknown')}",
            "Access to the storage is not being logged.",
            "If data is accessed or leaked, there is no audit trail to investigate what happened.",
            "Enable access logging and send logs to a separate, protected location.",
            "CIS Cloud Benchmarks - Logging and Monitoring",
            {"access_logging": False},
        )
    return None


# ---------------------------------------------------------------- Network

def check_ssh_open(config: dict) -> Optional[Finding]:
    network = config.get("network", {})
    if network.get("ssh_open_to_all") is True:
        return _finding(
            "CLOUD-005", "SSH Open to the Internet", "HIGH",
            "network:firewall",
            "SSH (port 22) accepts connections from any IP address (0.0.0.0/0).",
            "Attackers can continuously attempt brute-force logins against the servers.",
            "Restrict SSH to specific trusted IP ranges, or use a VPN / bastion host.",
            "CIS Cloud Benchmarks - Network Security",
            {"ssh_open_to_all": True},
        )
    return None


def check_rdp_open(config: dict) -> Optional[Finding]:
    network = config.get("network", {})
    if network.get("rdp_open_to_all") is True:
        return _finding(
            "CLOUD-006", "RDP Open to the Internet", "HIGH",
            "network:firewall",
            "Remote Desktop (port 3389) accepts connections from any IP address.",
            "RDP exposed to the internet is a common target for brute-force and ransomware attacks.",
            "Close RDP to the public internet and access it through a VPN or bastion host.",
            "CIS Cloud Benchmarks - Network Security",
            {"rdp_open_to_all": True},
        )
    return None


def check_https(config: dict) -> Optional[Finding]:
    network = config.get("network", {})
    if network.get("https_enabled") is False:
        return _finding(
            "CLOUD-007", "HTTPS Not Enforced", "MEDIUM",
            "network:load_balancer",
            "Traffic is allowed over unencrypted HTTP.",
            "Data (including credentials) can be intercepted or modified in transit.",
            "Enforce HTTPS and redirect all HTTP traffic to HTTPS.",
            "OWASP Transport Layer Protection Cheat Sheet",
            {"https_enabled": False},
        )
    return None


# --------------------------------------------------------------- Database

def check_database_public(config: dict) -> Optional[Finding]:
    db = config.get("database", {})
    if db.get("publicly_accessible") is True:
        return _finding(
            "CLOUD-008", "Database Publicly Accessible", "CRITICAL",
            f"database:{db.get('name', 'unknown')}",
            "The database can be reached directly from the internet.",
            "Attackers can attempt to connect directly, exploit weak credentials, or exploit database vulnerabilities.",
            "Place the database in a private network and allow access only from the application servers.",
            "CIS Cloud Benchmarks - Database Services",
            {"publicly_accessible": True},
        )
    return None


def check_database_backups(config: dict) -> Optional[Finding]:
    db = config.get("database", {})
    if db.get("backups_enabled") is False:
        return _finding(
            "CLOUD-009", "Database Backups Disabled", "MEDIUM",
            f"database:{db.get('name', 'unknown')}",
            "Automated backups are not enabled for the database.",
            "Data loss from failure, deletion, or attack may be unrecoverable.",
            "Enable automated backups with a suitable retention period and test restoring them.",
            "CIS Cloud Benchmarks - Database Services",
            {"backups_enabled": False},
        )
    return None


# ----------------------------------------------------- Secrets / IAM / Compute

SECRET_KEYWORDS = ("password", "secret", "api_key", "apikey", "token", "private_key")


def check_hardcoded_secrets(config: dict) -> Optional[Finding]:
    compute = config.get("compute", {})
    env = compute.get("environment_variables", {})
    leaked = [
        key for key, value in env.items()
        if any(word in key.lower() for word in SECRET_KEYWORDS)
        and isinstance(value, str)
        and value
        and not value.startswith("secretmanager://")
    ]
    if leaked:
        return _finding(
            "CLOUD-010", "Secrets Stored in Plain Configuration", "CRITICAL",
            "compute:environment",
            "Sensitive values appear to be stored directly in configuration.",
            "Anyone with access to the configuration or repository can obtain the credentials.",
            "Move secrets to a secrets manager and reference them instead of storing values directly.",
            "OWASP Secrets Management Cheat Sheet",
            {"keys_with_plain_values": leaked},  # بنعرض أسماء المفاتيح بس، مش القيم
        )
    return None


def check_iam_wildcard(config: dict) -> Optional[Finding]:
    iam = config.get("iam", {})
    if iam.get("allows_all_actions") is True:
        return _finding(
            "CLOUD-011", "Overly Permissive IAM Policy", "HIGH",
            f"iam:{iam.get('role_name', 'unknown')}",
            "A role/policy allows all actions on all resources.",
            "If this identity is compromised, the attacker gets full control of the environment.",
            "Apply the principle of least privilege: grant only the specific actions each role needs.",
            "CIS Cloud Benchmarks - Identity and Access Management",
            {"allows_all_actions": True},
        )
    return None


def check_mfa(config: dict) -> Optional[Finding]:
    iam = config.get("iam", {})
    if iam.get("mfa_enabled") is False:
        return _finding(
            "CLOUD-012", "MFA Not Enabled", "HIGH",
            "iam:users",
            "Multi-factor authentication is not enabled for user accounts.",
            "A stolen or guessed password alone is enough to take over the account.",
            "Require MFA for all users, especially administrators.",
            "CIS Cloud Benchmarks - Identity and Access Management",
            {"mfa_enabled": False},
        )
    return None


ALL_RULES: list[Rule] = [
    check_public_storage,
    check_storage_encryption,
    check_storage_versioning,
    check_storage_logging,
    check_ssh_open,
    check_rdp_open,
    check_https,
    check_database_public,
    check_database_backups,
    check_hardcoded_secrets,
    check_iam_wildcard,
    check_mfa,
]
