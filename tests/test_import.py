import io

import pytest

from app.main import create_app

HEADER = "rule,source_ip,failed_attempts,severity,message\n"


@pytest.fixture
def import_client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def _post(client, content, filename="alerts.csv"):
    data = {"file": (io.BytesIO(content.encode("utf-8")), filename)}
    return client.post(
        "/api/alerts/import", data=data, content_type="multipart/form-data"
    )


def test_import_without_file_returns_400(import_client):
    r = import_client.post("/api/alerts/import")
    assert r.status_code == 400
    assert "error" in r.get_json()


def test_import_rejects_non_csv_extension(import_client):
    r = _post(import_client, HEADER, filename="alerts.txt")
    assert r.status_code == 400


def test_import_rejects_missing_columns(import_client):
    r = _post(import_client, "rule,source_ip\nBrute Force,203.0.113.5\n")
    assert r.status_code == 400
    assert "Missing required column" in r.get_json()["error"]


def test_import_rejects_invalid_severity(import_client):
    r = _post(import_client, HEADER + "Brute Force,203.0.113.5,10,CRITICAL,msg\n")
    assert r.status_code == 400
    assert "Row 2" in r.get_json()["error"]


def test_import_rejects_invalid_ip(import_client):
    r = _post(import_client, HEADER + "Brute Force,not-an-ip,10,HIGH,msg\n")
    assert r.status_code == 400
    assert "source_ip" in r.get_json()["error"]


def test_import_rejects_negative_attempts(import_client):
    r = _post(import_client, HEADER + "Brute Force,203.0.113.5,-3,HIGH,msg\n")
    assert r.status_code == 400
    assert "failed_attempts" in r.get_json()["error"]