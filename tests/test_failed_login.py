
from app.detection.failed_login import detect_failed_logins


def test_detects_repeated_failed_logins(tmp_path):
    log_file = tmp_path / "auth.log"

    log_file.write_text(
        "2026-10-16 09:00:01 FAILED_LOGIN user=admin source_ip=192.168.1.50\n"
        "2026-10-16 09:00:05 FAILED_LOGIN user=admin source_ip=192.168.1.50\n"
        "2026-10-16 09:00:09 FAILED_LOGIN user=admin source_ip=192.168.1.50\n"
        "2026-10-16 09:01:00 SUCCESS_LOGIN user=shiva source_ip=192.168.1.20\n",
        encoding="utf-8",
    )

    alerts = detect_failed_logins(log_file)

    assert len(alerts) == 1
    assert alerts[0]["source_ip"] == "192.168.1.50"
    assert alerts[0]["failed_attempts"] == 3
    assert alerts[0]["severity"] == "HIGH"


def test_no_alert_below_threshold(tmp_path):
    log_file = tmp_path / "auth.log"

    log_file.write_text(
        "2026-10-16 09:00:01 FAILED_LOGIN user=admin source_ip=192.168.1.50\n"
        "2026-10-16 09:00:05 FAILED_LOGIN user=admin source_ip=192.168.1.50\n",
        encoding="utf-8",
    )

    alerts = detect_failed_logins(log_file)

    assert alerts == []

def test_no_alert_when_failures_are_spread_out(tmp_path):
    log_file = tmp_path / "auth.log"

    log_file.write_text(
        "2026-10-16 09:00:00 FAILED_LOGIN user=admin source_ip=192.168.1.50\n"
        "2026-10-16 09:03:00 FAILED_LOGIN user=admin source_ip=192.168.1.50\n"
        "2026-10-16 09:06:00 FAILED_LOGIN user=admin source_ip=192.168.1.50\n",
        encoding="utf-8",
    )

    alerts = detect_failed_logins(log_file)

    assert alerts == []

def test_alert_triggers_at_threshold_within_window(tmp_path):
    log_file = tmp_path / "auth.log"

    log_file.write_text(
        "2026-10-16 09:00:00 FAILED_LOGIN user=admin source_ip=192.168.1.50\n"
        "2026-10-16 09:02:00 FAILED_LOGIN user=admin source_ip=192.168.1.50\n"
        "2026-10-16 09:04:00 FAILED_LOGIN user=admin source_ip=192.168.1.50\n",
        encoding="utf-8",
    )

    alerts = detect_failed_logins(log_file, threshold=3, window_minutes=5)

    assert len(alerts) == 1
    assert alerts[0]["failed_attempts"] == 3
    assert alerts[0]["source_ip"] == "192.168.1.50"
