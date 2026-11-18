import pytest

from app.main import create_app


@pytest.fixture
def api_client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as test_client:
        yield test_client


def test_invalid_start_date_returns_400(api_client):
    r = api_client.get("/api/alerts?start_date=2026-13-01")
    assert r.status_code == 400
    assert "Invalid start_date" in r.get_json()["error"]


def test_invalid_end_date_returns_400(api_client):
    r = api_client.get("/api/alerts?end_date=not-a-date")
    assert r.status_code == 400
    assert "Invalid end_date" in r.get_json()["error"]


def test_reversed_date_range_returns_400(api_client):
    r = api_client.get("/api/alerts?start_date=2026-10-16&end_date=2026-10-01")
    assert r.status_code == 400
    assert "on or before" in r.get_json()["error"]


def test_future_start_date_returns_no_alerts(api_client):
    r = api_client.get("/api/alerts?start_date=2099-01-01")
    assert r.status_code == 200
    assert r.get_json()["count"] == 0


def test_past_end_date_returns_no_alerts(api_client):
    r = api_client.get("/api/alerts?end_date=2000-01-01")
    assert r.status_code == 200
    assert r.get_json()["count"] == 0


def test_export_with_future_start_has_header_only(api_client):
    r = api_client.get("/api/alerts/export?start_date=2099-01-01")
    assert r.status_code == 200
    assert r.mimetype == "text/csv"
    rows = [ln for ln in r.get_data(as_text=True).splitlines()[1:] if ln.strip()]
    assert rows == []

def test_health_endpoint(api_client):
    r = api_client.get("/health")
    assert r.status_code == 200
    body = r.get_json()
    assert body["status"] == "ok"
    assert body["service"] == "SentinelSOC API"


def test_alerts_endpoint(api_client):
    r = api_client.get("/api/alerts")
    assert r.status_code == 200
    body = r.get_json()
    assert isinstance(body["alerts"], list)
    assert body["count"] == len(body["alerts"])
    for key in (
        "total_alerts",
        "high_severity",
        "medium_severity",
        "low_severity",
        "unique_source_ips",
    ):
        assert key in body["summary"]


def test_alerts_include_mitre_fields(api_client):
    r = api_client.get("/api/alerts")
    for alert in r.get_json()["alerts"]:
        assert "mitre_id" in alert
        assert "mitre_tactic" in alert


def test_severity_filter(api_client):
    r = api_client.get("/api/alerts?severity=high")
    assert r.status_code == 200
    assert all(a["severity"] == "HIGH" for a in r.get_json()["alerts"])


def test_source_ip_filter(api_client):
    r = api_client.get("/api/alerts?source_ip=203.0.113")
    assert r.status_code == 200
    assert all("203.0.113" in a["source_ip"] for a in r.get_json()["alerts"])


def test_invalid_severity_filter(api_client):
    r = api_client.get("/api/alerts?severity=CRITICAL")
    assert r.status_code == 400
    assert "Invalid severity" in r.get_json()["error"]