"""
CloudSentinel - Normalized resource model

الفكرة: الـ Parser بيحوّل أي Resource من CloudFormation لشكل داخلي موحّد (Resource).
القواعد (rules) بتشتغل على الشكل ده بس، ومش بتعرف أسماء الـ properties بتاعة CloudFormation.

كل قيمة جوه Resource.data ممكن تبقى:
  - قيمة معروفة (True / False / رقم / نص)
  - MISSING : الـ property مش مكتوبة في الـ template
  - DYNAMIC : القيمة مش معروفة وقت الفحص (Ref / Fn::If / dynamic reference ...)

وده اللي بيخلي النتيجة UNKNOWN بدل ما نخمّن.
"""

from dataclasses import dataclass, field
from typing import Any, Callable, Optional


class _Sentinel:
    def __init__(self, name: str):
        self._name = name

    def __repr__(self) -> str:
        return self._name


MISSING = _Sentinel("MISSING")
DYNAMIC = _Sentinel("DYNAMIC")

# حالات النتيجة
PASS = "PASS"
FAIL = "FAIL"
UNKNOWN = "UNKNOWN"
NOT_APPLICABLE = "NOT_APPLICABLE"


def and3(*values):
    """AND بـ 3 حالات: False لو أي واحدة False، وإلا DYNAMIC لو في واحدة مجهولة، وإلا True."""
    if any(v is False for v in values):
        return False
    if any(v is DYNAMIC for v in values):
        return DYNAMIC
    return True


def or3(*values):
    """OR بـ 3 حالات: True لو أي واحدة True، وإلا DYNAMIC لو في واحدة مجهولة، وإلا False."""
    if any(v is True for v in values):
        return True
    if any(v is DYNAMIC for v in values):
        return DYNAMIC
    return False


def clean(value: Any) -> Any:
    """بيحوّل الـ sentinels لنص مفهوم عشان يظهر في الـ Evidence."""
    if value is MISSING:
        return "not set"
    if value is DYNAMIC:
        return "dynamic value"
    if isinstance(value, list):
        return [clean(v) for v in value]
    if isinstance(value, dict):
        return {k: clean(v) for k, v in value.items()}
    return value


@dataclass
class Resource:
    logical_id: str
    kind: str  # storage | firewall | database | iam_policy
    cfn_type: str
    data: dict = field(default_factory=dict)
    # أسماء الـ Parameters اللي اتقيّمت بقيمتها الافتراضية (القيمة وقت النشر ممكن تختلف)
    param_defaults: list = field(default_factory=list)


@dataclass
class ParsedTemplate:
    resources: list
    unsupported: list
    warnings: list = field(default_factory=list)


@dataclass
class Outcome:
    status: str
    reason: str
    evidence: Optional[Any] = None
    severity: Optional[str] = None  # لو القاعدة عايزة تغيّر الخطورة الافتراضية


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    applies_to: str
    impact: str
    recommendation: str
    reference: str
    check: Callable[[Resource], Outcome]
