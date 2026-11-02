"""
بيحمّل الـ templates التجريبية من فولدر samples_cfn (كلها بيانات وهمية).
اسم الملف هو الـ id، و"Description" جوه الـ template هو الوصف.
"""

import json
from pathlib import Path

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples_cfn"


def load_samples() -> dict:
    samples = {}
    for path in sorted(SAMPLES_DIR.glob("*.json")):
        try:
            template = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        samples[path.stem] = {
            "label": path.stem.replace("-", " ").title(),
            "description": template.get("Description", "") if isinstance(template, dict) else "",
            "template": template,
        }
    return samples


CFN_SAMPLES = load_samples()
