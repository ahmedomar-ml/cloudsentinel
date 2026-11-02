"""
CloudSentinel - Before / After comparison

بيقارن فحصين (قبل وبعد التعديل) على أساس (rule_id, resource_id):
  resolved         كانت FAIL وبقت PASS
  new              بقت FAIL وماكانتش FAIL قبل كده
  unchanged        FAIL في الفحصين
  not_reevaluated  كانت FAIL ومقدرناش نتأكد إنها اتصلحت (UNKNOWN / NOT_APPLICABLE / المورد اتشال)
"""

from .model import FAIL, PASS


def _key(result):
    return (result["rule_id"], result["resource_id"])


def _brief(result, before_status, after_status, note=None):
    item = {
        "rule_id": result["rule_id"],
        "title": result["title"],
        "resource_id": result["resource_id"],
        "severity": result["severity"],
        "before_status": before_status,
        "after_status": after_status,
    }
    if note:
        item["note"] = note
    return item


def compare_scans(before: dict, after: dict) -> dict:
    before_map = {_key(r): r for r in before["results"]}
    after_map = {_key(r): r for r in after["results"]}

    resolved, new, unchanged, not_reevaluated = [], [], [], []

    for key, old in before_map.items():
        if old["status"] != FAIL:
            continue
        current = after_map.get(key)
        if current is None:
            not_reevaluated.append(_brief(old, FAIL, None, "The resource or rule no longer appears in the second scan."))
        elif current["status"] == PASS:
            resolved.append(_brief(old, FAIL, PASS))
        elif current["status"] == FAIL:
            unchanged.append(_brief(current, FAIL, FAIL))
        else:
            not_reevaluated.append(_brief(current, FAIL, current["status"], current["reason"]))

    for key, current in after_map.items():
        if current["status"] != FAIL:
            continue
        old = before_map.get(key)
        if old is None or old["status"] != FAIL:
            new.append(_brief(current, old["status"] if old else None, FAIL))

    return {
        "before": before["summary"],
        "after": after["summary"],
        "resolved": resolved,
        "new": new,
        "unchanged": unchanged,
        "not_reevaluated": not_reevaluated,
        "counts": {
            "resolved": len(resolved),
            "new": len(new),
            "unchanged": len(unchanged),
            "not_reevaluated": len(not_reevaluated),
        },
    }
