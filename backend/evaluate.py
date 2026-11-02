"""
تقييم الأداة على الـ sample templates مقابل النتايج المتوقعة (ground_truth.py).

التشغيل:  python evaluate.py

ملحوظة للمناقشة: النتايج المتوقعة كتبناها إحنا لنفس القواعد، فده اختبار انحدار
(regression) أكتر منه قياس علمي مستقل. عشان القياس يبقى أقوى، ضيف templates حقيقية
من مصدر خارجي (مثلًا أمثلة AWS الرسمية) واكتب نتايجها المتوقعة يدويًا قبل ما تشغّل الأداة.
"""

import time

from cfn.samples import CFN_SAMPLES
from cfn.scanner import scan_template
from ground_truth import GROUND_TRUTH, as_pairs


def score(expected: set, actual: set):
    tp = len(expected & actual)
    precision = tp / len(actual) if actual else 1.0
    recall = tp / len(expected) if expected else 1.0
    return tp, precision, recall


def main():
    totals = {"FAIL": [0, 0, 0], "UNKNOWN": [0, 0, 0]}  # tp, predicted, expected
    print(f"{'template':<24}{'checks':>7}{'FAIL tp/exp/pred':>20}{'UNKNOWN tp/exp/pred':>22}{'ms':>8}")

    for sample_id, truth in GROUND_TRUTH.items():
        start = time.perf_counter()
        result = scan_template(CFN_SAMPLES[sample_id]["template"])
        elapsed = (time.perf_counter() - start) * 1000

        row = []
        for status in ("FAIL", "UNKNOWN"):
            expected = as_pairs(truth[status])
            actual = {(r["rule_id"], r["resource_id"]) for r in result["results"] if r["status"] == status}
            tp = len(expected & actual)
            totals[status][0] += tp
            totals[status][1] += len(actual)
            totals[status][2] += len(expected)
            row.append(f"{tp}/{len(expected)}/{len(actual)}")

        print(f"{sample_id:<24}{result['summary']['total_checks']:>7}{row[0]:>20}{row[1]:>22}{elapsed:>8.2f}")

    print()
    for status, (tp, predicted, expected) in totals.items():
        precision = tp / predicted if predicted else 1.0
        recall = tp / expected if expected else 1.0
        print(f"{status:<8} precision={precision:.2f}  recall={recall:.2f}  (tp={tp}, predicted={predicted}, expected={expected})")


if __name__ == "__main__":
    main()
