"""
بيفحص كل ملفات CloudFormation (JSON) في فولدر، ويطلّع إحصائيات: كام template اتفحص، كام مورد اتحلل،
وإيه الأنواع اللي مش مدعومة. مفيد لتجربة الأداة على templates حقيقية.

التشغيل:
    python scan_folder.py PATH_TO_FOLDER
مثال (الـ templates الرسمية من AWS):
    git clone --depth 1 https://github.com/aws-cloudformation/aws-cloudformation-templates.git
    python scan_folder.py aws-cloudformation-templates
"""

import collections
import json
import sys
from pathlib import Path

from cfn.parser import TemplateError
from cfn.scanner import scan_template


def main(folder: str) -> None:
    stats = collections.Counter()
    totals = collections.Counter()
    unsupported = collections.Counter()
    crashes = []

    for path in sorted(Path(folder).rglob("*.json")):
        if ".git" in path.parts:
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            stats["invalid JSON"] += 1
            continue
        try:
            result = scan_template(data)
        except TemplateError:
            stats["not a CloudFormation template"] += 1
            continue
        except Exception as exc:  # لو ده حصل يبقى في bug
            stats["CRASH"] += 1
            crashes.append((str(path), repr(exc)))
            continue

        stats["scanned"] += 1
        if result["summary"]["resources_analyzed"]:
            stats["with at least one supported resource"] += 1
        for key in ("resources_analyzed", "resources_unsupported", "total_checks", "passed", "failed", "unknown", "not_applicable"):
            totals[key] += result["summary"][key]
        for item in result["unsupported"]:
            unsupported[item["type"]] += 1

    print("== files ==")
    for key, value in stats.items():
        print(f"{key}: {value}")
    print("\n== totals ==")
    for key, value in totals.items():
        print(f"{key}: {value}")
    print("\n== most common unsupported types ==")
    for kind, count in unsupported.most_common(10):
        print(f"{count:4d}  {kind}")
    if crashes:
        print("\n== CRASHES (please report) ==")
        for path, error in crashes:
            print(path, error)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python scan_folder.py PATH_TO_FOLDER")
    main(sys.argv[1])
