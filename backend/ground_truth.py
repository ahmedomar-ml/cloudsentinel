"""
النتايج المتوقعة لكل sample template، متكتبة بإيدي من تحليل الـ template نفسه
(مش منسوخة من خرج الأداة). بتتستخدم في الاختبارات وفي evaluate.py.

الشكل: {template_id: {"FAIL": {resource: {rule_ids}}, "UNKNOWN": {resource: {rule_ids}}}}
أي check مش مذكور هنا يُعتبر متوقع منه PASS أو NOT_APPLICABLE.
"""

GROUND_TRUTH = {
    "insecure-stack": {
        "FAIL": {
            "DataBucket": {"S3-001", "S3-002", "S3-003", "S3-004", "S3-005"},
            "WebServerSG": {"SG-001", "SG-002", "SG-004"},
            "OpenToWorldSG": {"SG-001", "SG-002", "SG-003", "SG-004"},
            "AppDatabase": {"RDS-001", "RDS-002", "RDS-003", "RDS-004"},
            "AdminPolicy": {"IAM-001"},
        },
        "UNKNOWN": {},
    },
    "insecure-stack-fixed": {"FAIL": {}, "UNKNOWN": {}},
    "mixed-stack": {
        "FAIL": {
            "AppBucket": {"S3-002", "S3-004", "S3-005"},
            "ReportsRole": {"IAM-002"},
        },
        "UNKNOWN": {
            "AdminSG": {"SG-001"},
            "OrdersDB": {"RDS-002"},
        },
    },
    "secure-stack": {"FAIL": {}, "UNKNOWN": {}},
}


def as_pairs(mapping):
    return {(rule, resource) for resource, rules in mapping.items() for rule in rules}
