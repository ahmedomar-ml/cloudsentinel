from fastapi.testclient import TestClient

from main import app
from samples import SAMPLE_ENVIRONMENTS
from scanner import scan

client = TestClient(app)


def test_insecure_environment_finds_everything():
    result = scan(SAMPLE_ENVIRONMENTS["insecure-startup"]["config"])
    assert result["summary"]["total_checks"] == 12
    # كل القواعد بتلاقي مشكلة ماعدا RDP (مقفول في البيئة دي)
    assert result["summary"]["failed"] == 11
    assert result["summary"]["critical"] == 2


def test_well_configured_environment_passes_all():
    result = scan(SAMPLE_ENVIRONMENTS["well-configured"]["config"])
    assert result["summary"]["failed"] == 0
    assert result["findings"] == []


def test_mixed_environment():
    result = scan(SAMPLE_ENVIRONMENTS["mixed-environment"]["config"])
    ids = {f["rule_id"] for f in result["findings"]}
    assert ids == {"CLOUD-003", "CLOUD-004", "CLOUD-005", "CLOUD-012"}


def test_findings_sorted_by_severity():
    result = scan(SAMPLE_ENVIRONMENTS["insecure-startup"]["config"])
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    ranks = [order[f["severity"]] for f in result["findings"]]
    assert ranks == sorted(ranks)


def test_secret_values_are_never_returned():
    result = scan(SAMPLE_ENVIRONMENTS["insecure-startup"]["config"])
    text = str(result)
    assert "admin123" not in text
    assert "sk-demo-not-a-real-key" not in text


def test_secrets_manager_reference_is_not_flagged():
    config = {"compute": {"environment_variables": {"DB_PASSWORD": "secretmanager://prod/x"}}}
    assert scan(config)["findings"] == []


def test_empty_config_does_not_crash():
    assert scan({})["summary"]["failed"] == 0


def test_api_endpoints():
    assert client.get("/").status_code == 200
    assert len(client.get("/api/samples").json()) == 3
    r = client.post("/api/scan/sample/insecure-startup")
    assert r.status_code == 200 and r.json()["summary"]["failed"] == 11
    assert client.post("/api/scan/sample/nope").status_code == 404
    r = client.post("/api/scan", json={"config": {"network": {"ssh_open_to_all": True}}})
    assert r.json()["summary"]["failed"] == 1
