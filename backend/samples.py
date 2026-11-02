"""
بيئات تجريبية (بيانات وهمية، مش من حساب سحابي حقيقي).
كل بيئة فيها مستوى مختلف من المشاكل عشان نختبر بيها الـ Dashboard.
"""

SAMPLE_ENVIRONMENTS = {
    "insecure-startup": {
        "label": "Insecure Startup",
        "description": "A rushed startup setup with many serious misconfigurations.",
        "config": {
            "storage": {
                "name": "medical-records",
                "public_access": True,
                "encryption_enabled": False,
                "versioning_enabled": False,
                "access_logging": False,
            },
            "network": {
                "ssh_open_to_all": True,
                "rdp_open_to_all": False,
                "https_enabled": False,
            },
            "database": {
                "name": "users-db",
                "publicly_accessible": True,
                "backups_enabled": False,
            },
            "compute": {
                "environment_variables": {
                    "DB_PASSWORD": "admin123",
                    "API_KEY": "sk-demo-not-a-real-key",
                    "APP_MODE": "production",
                }
            },
            "iam": {
                "role_name": "app-admin",
                "allows_all_actions": True,
                "mfa_enabled": False,
            },
        },
    },
    "mixed-environment": {
        "label": "Mixed Environment",
        "description": "A mostly reasonable setup with a few issues left behind.",
        "config": {
            "storage": {
                "name": "company-assets",
                "public_access": False,
                "encryption_enabled": True,
                "versioning_enabled": False,
                "access_logging": False,
            },
            "network": {
                "ssh_open_to_all": True,
                "rdp_open_to_all": False,
                "https_enabled": True,
            },
            "database": {
                "name": "orders-db",
                "publicly_accessible": False,
                "backups_enabled": True,
            },
            "compute": {
                "environment_variables": {
                    "SECRET_KEY": "secretmanager://prod/app-secret",
                    "APP_MODE": "production",
                }
            },
            "iam": {
                "role_name": "deploy-role",
                "allows_all_actions": False,
                "mfa_enabled": False,
            },
        },
    },
    "well-configured": {
        "label": "Well Configured",
        "description": "A hardened setup that passes every check in the rule set.",
        "config": {
            "storage": {
                "name": "secure-bucket",
                "public_access": False,
                "encryption_enabled": True,
                "versioning_enabled": True,
                "access_logging": True,
            },
            "network": {
                "ssh_open_to_all": False,
                "rdp_open_to_all": False,
                "https_enabled": True,
            },
            "database": {
                "name": "main-db",
                "publicly_accessible": False,
                "backups_enabled": True,
            },
            "compute": {
                "environment_variables": {
                    "DB_PASSWORD": "secretmanager://prod/db-password",
                    "APP_MODE": "production",
                }
            },
            "iam": {
                "role_name": "least-privilege-role",
                "allows_all_actions": False,
                "mfa_enabled": True,
            },
        },
    },
}
