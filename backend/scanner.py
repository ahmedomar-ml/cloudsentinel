"""
CloudSentinel - Scanner

بياخد الـ config، يشغّل كل القواعد عليه، ويطلّع تقرير فيه ملخص + المشاكل.
"""

from rules import ALL_RULES

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def scan(config: dict) -> dict:
    findings = []

    for rule in ALL_RULES:
        result = rule(config)
        if result is not None:
            findings.append(result)

    # نرتب المشاكل من الأخطر للأقل خطورة
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))

    total = len(ALL_RULES)
    failed = len(findings)

    summary = {
        "total_checks": total,
        "passed": total - failed,
        "failed": failed,
        "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
        "high": sum(1 for f in findings if f["severity"] == "HIGH"),
        "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
        "low": sum(1 for f in findings if f["severity"] == "LOW"),
    }

    return {"summary": summary, "findings": findings}
