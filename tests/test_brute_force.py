
from app.detection.brute_force import detect_brute_force


def test_detects_brute_force(tmp_path):
    log_file = tmp_path / "auth.log"

    log_file.write_text(
        "".join(
            f"2026-10-14 10:00:{second:02d} "
            "FAILED_LOGIN user=admin source_ip=10.0.0.5\n"
            for second in range(10)
        ),
        encoding="utf-8",
    )

    alerts = detect_brute_force(log_file)

    assert len(alerts) == 1
    assert alerts[0]["rule"] == "Brute-Force Login Detection"
    assert alerts[0]["source_ip"] == "10.0.0.5"
    assert alerts[0]["severity"] == "HIGH"


def test_no_alert_below_threshold(tmp_path):
    log_file = tmp_path / "auth.log"

    log_file.write_text(
        "2026-10-14 10:00:01 FAILED_LOGIN "
        "user=admin source_ip=10.0.0.5\n",
        encoding="utf-8",
    )

    alerts = detect_brute_force(log_file)

    assert alerts == []


def test_missing_log_file():
    import pytest

    with pytest.raises(FileNotFoundError):
        detect_brute_force("missing_brute_force.log")
