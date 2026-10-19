
from app.main import create_app


def test_health_endpoint():
    client = create_app().test_client()

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json["status"] == "ok"


def test_alerts_endpoint():
    client = create_app().test_client()

    response = client.get("/api/alerts")

    assert response.status_code == 200
    assert isinstance(response.json["alerts"], list)
    assert response.json["count"] == len(response.json["alerts"])

def test_severity_filter():
    from app.main import create_app

    app = create_app()
    app.config["TESTING"] = True
    client = app.test_client()

    response = client.get("/api/alerts?severity=HIGH")

    assert response.status_code == 200

    data = response.get_json()

    assert all(
        alert["severity"] == "HIGH"
        for alert in data["alerts"]
    )


def test_source_ip_filter():
    from app.main import create_app

    app = create_app()
    app.config["TESTING"] = True
    client = app.test_client()

    response = client.get(
        "/api/alerts?source_ip=192.168.1.50"
    )

    assert response.status_code == 200

    data = response.get_json()

    assert all(
        "192.168.1.50" in alert["source_ip"]
        for alert in data["alerts"]
    )


def test_invalid_severity_filter():
    from app.main import create_app

    app = create_app()
    app.config["TESTING"] = True
    client = app.test_client()

    response = client.get("/api/alerts?severity=INVALID")

    assert response.status_code == 400
    assert "error" in response.get_json()
