
import app.services.alert_pipeline as pipeline

from app.database.alert_store import (
    initialize_database,
    get_alerts,
    save_alert,
)


def test_pipeline_runs_both_detection_rules(tmp_path, monkeypatch):
    log_file = tmp_path / "auth.log"
    db_file = tmp_path / "test_alerts.db"

    log_file.write_text(
        "".join(
            f"2026-10-14 10:00:{second:02d} "
            "FAILED_LOGIN user=admin source_ip=10.0.0.5\n"
            for second in range(10)
        ),
        encoding="utf-8",
    )

    # Direct all database operations to the temporary test database.
    monkeypatch.setattr(
        pipeline,
        "initialize_database",
        lambda: initialize_database(db_file),
    )

    monkeypatch.setattr(
        pipeline,
        "save_alert",
        lambda alert: save_alert(alert, db_path=db_file),
    )

    alerts = pipeline.run_pipeline(log_file)

    # Verify that both detection rules generated alerts.
    assert any(
        alert["rule"] == "Repeated Failed Logins"
        for alert in alerts
    )

    assert any(
        alert["rule"] == "Brute-Force Login Detection"
        for alert in alerts
    )

    # Verify that both types of alerts were stored.
    stored_alerts = get_alerts(db_file)

    stored_rules = {
        alert["rule"] for alert in stored_alerts
    }

    assert "Repeated Failed Logins" in stored_rules
    assert "Brute-Force Login Detection" in stored_rules


def test_pipeline_rejects_missing_log_file(tmp_path):
    import pytest

    missing_file = tmp_path / "missing.log"

    with pytest.raises(FileNotFoundError):
        pipeline.run_pipeline(missing_file)
