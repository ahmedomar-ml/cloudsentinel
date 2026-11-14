from fastapi.testclient import TestClient

from main import app
from cfn.samples import CFN_SAMPLES

client = TestClient(app)


def test_cfn_rules_catalog():
    rules = client.get("/api/cfn/rules").json()
    assert len(rules) == 15
    assert {"id", "title", "severity", "impact", "recommendation"} <= set(rules[0])


def test_cfn_samples_list_and_get():
    samples = client.get("/api/cfn/samples").json()
    assert {s["id"] for s in samples} == set(CFN_SAMPLES)
    assert "Resources" in client.get("/api/cfn/samples/insecure-stack").json()["template"]
    assert client.get("/api/cfn/samples/nope").status_code == 404


def test_cfn_scan_sample():
    r = client.post("/api/cfn/scan/sample/insecure-stack")
    assert r.status_code == 200
    assert r.json()["summary"]["failed"] == 17
    assert client.post("/api/cfn/scan/sample/nope").status_code == 404


def test_cfn_scan_uploaded_template():
    template = CFN_SAMPLES["mixed-stack"]["template"]
    r = client.post("/api/cfn/scan", json={"template": template})
    assert r.status_code == 200
    assert r.json()["summary"]["unknown"] == 2


def test_cfn_scan_invalid_template_returns_422():
    assert client.post("/api/cfn/scan", json={"template": {}}).status_code == 422
    assert client.post("/api/cfn/scan", json={"template": {"Resources": {"X": {}}}}).status_code == 422


def test_cfn_compare():
    r = client.post(
        "/api/cfn/compare",
        json={
            "before": CFN_SAMPLES["insecure-stack"]["template"],
            "after": CFN_SAMPLES["insecure-stack-fixed"]["template"],
        },
    )
    assert r.status_code == 200
    assert r.json()["counts"]["resolved"] == 17


def test_legacy_endpoints_still_work():
    assert client.post("/api/scan/sample/insecure-startup").json()["summary"]["failed"] == 11


YAML_TEXT = """
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: PublicRead
"""
YAML_FIXED = """
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: Private
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
"""


def test_cfn_scan_yaml_text():
    r = client.post("/api/cfn/scan", json={"template_text": YAML_TEXT})
    assert r.status_code == 200
    s1 = next(x for x in r.json()["results"] if x["rule_id"] == "S3-001")
    assert s1["status"] == "FAIL"


def test_cfn_scan_needs_exactly_one_input():
    assert client.post("/api/cfn/scan", json={}).status_code == 422
    both = {"template": {"Resources": {}}, "template_text": YAML_TEXT}
    assert client.post("/api/cfn/scan", json=both).status_code == 422


def test_cfn_scan_bad_yaml_is_422():
    r = client.post("/api/cfn/scan", json={"template_text": "Resources: [unclosed"})
    assert r.status_code == 422
    assert "Invalid" in r.json()["detail"]


def test_cfn_scan_yaml_alias_is_422():
    r = client.post("/api/cfn/scan", json={"template_text": "Resources:\n  A: &x\n    Type: AWS::S3::Bucket\n  B: *x\n"})
    assert r.status_code == 422


def test_cfn_compare_with_yaml_text():
    r = client.post("/api/cfn/compare", json={"before_text": YAML_TEXT, "after_text": YAML_FIXED})
    assert r.status_code == 200
    assert r.json()["counts"]["resolved"] >= 1
