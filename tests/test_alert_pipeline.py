
from app.services.alert_pipeline import run_pipeline
from app.database.alert_store import get_alerts


def test_pipeline_saves_detected_alert(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    log_path = tmp_path / "auth.log"

    log_path.write_text(
        "2026-10-16 09:00:01 FAILED_LOGIN user=admin source_ip=192.168.1.50\n"
        "2026-10-16 09:00:05 FAILED_LOGIN user=admin source_ip=192.168.1.50\n"
        "2026-10-16 09:00:09 FAILED_LOGIN user=admin source_ip=192.168.1.50\n",
       encoding="utf-8",
    )

    monkeypatch.setattr(
        "app.services.alert_pipeline.initialize_database",
        lambda: __import__(
            "app.database.alert_store",
            fromlist=["initialize_database"],
        ).initialize_database(db_path),
    )
    monkeypatch.setattr(
        "app.services.alert_pipeline.save_alert",
        lambda alert: __import__(
            "app.database.alert_store",
            fromlist=["save_alert"],
        ).save_alert(alert, db_path),
    )

    alerts = run_pipeline(log_path)
    saved = get_alerts(db_path)

    assert len(alerts) == 1
    assert len(saved) == 1
    assert saved[0]["source_ip"] == "192.168.1.50"
