"""
CloudSentinel - CloudFormation scanner

بيشغّل كل القواعد على كل Resource مناسب، ويطلّع كل النتايج (PASS / FAIL / UNKNOWN / NOT_APPLICABLE)
مع ملخص. القواعد اللي مبتنطبقش على نوع المورد (مثلًا قاعدة S3 على Security Group) مش بتظهر.
"""

import logging

from .model import FAIL, NOT_APPLICABLE, PASS, UNKNOWN, Outcome
from .parser import parse_template
from .rules import RULES

log = logging.getLogger("cloudsentinel")

STATUS_ORDER = {FAIL: 0, UNKNOWN: 1, PASS: 2, NOT_APPLICABLE: 3}
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _evaluate(rule, resource) -> Outcome:
    try:
        return rule.check(resource)
    except Exception as exc:  # قاعدة واحدة بتفشل مايفروضش توقّع الفحص كله
        log.exception("Rule %s failed on %s", rule.id, resource.logical_id)
        return Outcome(UNKNOWN, "The rule could not be evaluated.", {"error": type(exc).__name__})


def scan_template(template) -> dict:
    parsed = parse_template(template)

    results = []
    for resource in parsed.resources:
        for rule in RULES:
            if rule.applies_to != resource.kind:
                continue
            outcome = _evaluate(rule, resource)
            results.append(
                {
                    "rule_id": rule.id,
                    "title": rule.title,
                    "resource_id": resource.logical_id,
                    "resource_type": resource.cfn_type,
                    "status": outcome.status,
                    "severity": outcome.severity or rule.severity,
                    "reason": outcome.reason,
                    "evidence": outcome.evidence,
                    "impact": rule.impact,
                    "recommendation": rule.recommendation,
                    "reference": rule.reference,
                    "depends_on_parameter_defaults": resource.param_defaults,
                }
            )

    results.sort(
        key=lambda x: (
            STATUS_ORDER[x["status"]],
            SEVERITY_ORDER.get(x["severity"], 9),
            x["resource_id"],
            x["rule_id"],
        )
    )

    def count(status):
        return sum(1 for x in results if x["status"] == status)

    def failed(severity):
        return sum(1 for x in results if x["status"] == FAIL and x["severity"] == severity)

    summary = {
        "resources_analyzed": len(parsed.resources),
        "resources_unsupported": len(parsed.unsupported),
        "total_checks": len(results),
        "passed": count(PASS),
        "failed": count(FAIL),
        "unknown": count(UNKNOWN),
        "not_applicable": count(NOT_APPLICABLE),
        "critical": failed("CRITICAL"),
        "high": failed("HIGH"),
        "medium": failed("MEDIUM"),
        "low": failed("LOW"),
    }

    return {
        "summary": summary,
        "results": results,
        "unsupported": parsed.unsupported,
        "warnings": parsed.warnings,
    }
