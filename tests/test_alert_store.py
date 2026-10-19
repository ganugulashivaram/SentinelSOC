
from app.database.alert_store import (
    initialize_database,
    save_alert,
    get_alerts,
)


def test_save_and_retrieve_alert(tmp_path):
    db_path = tmp_path / "test.db"

    alert = {
        "rule": "Repeated Failed Logins",
        "source_ip": "192.168.1.50",
        "failed_attempts": 3,
        "severity": "HIGH",
        "message": "3 failed login attempts from 192.168.1.50",
    }

    initialize_database(db_path)
    alert_id = save_alert(alert, db_path)
    saved_alerts = get_alerts(db_path)

    assert alert_id == 1
    assert len(saved_alerts) == 1
    assert saved_alerts[0]["source_ip"] == "192.168.1.50"
    assert saved_alerts[0]["severity"] == "HIGH"


def test_duplicate_alert_is_not_saved_twice(tmp_path):
    db_path = tmp_path / "duplicate_test.db"

    alert = {
        "rule": "Repeated Failed Logins",
        "source_ip": "192.168.1.50",
        "failed_attempts": 3,
        "severity": "HIGH",
        "message": "3 failed login attempts from 192.168.1.50",
    }

    initialize_database(db_path)

    first_id = save_alert(alert, db_path)
    second_id = save_alert(alert, db_path)

    assert first_id == 1
    assert second_id is None
    assert len(get_alerts(db_path)) == 1


def test_duplicate_alert_is_not_saved_twice(tmp_path):
    db_path = tmp_path / "duplicate_test.db"

    alert = {
        "rule": "Repeated Failed Logins",
        "source_ip": "192.168.1.50",
        "failed_attempts": 3,
        "severity": "HIGH",
        "message": "3 failed login attempts from 192.168.1.50",
    }

    initialize_database(db_path)

    first_id = save_alert(alert, db_path)
    second_id = save_alert(alert, db_path)

    assert first_id == 1
    assert second_id is None
    assert len(get_alerts(db_path)) == 1

