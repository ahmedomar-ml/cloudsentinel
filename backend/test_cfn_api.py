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
