
from pathlib import Path

from app.detection.failed_login import detect_failed_logins
from app.detection.brute_force import detect_brute_force
from app.enrichment.ip_reputation import enrich_ip
from app.database.alert_store import initialize_database, save_alert


def run_pipeline(log_path):
    """Detect login attacks, enrich IPs, and save alerts."""

    log_path = Path(log_path)

    if not log_path.is_file():
        raise FileNotFoundError(
            f"Log file not found: {log_path}"
        )

    initialize_database()
    print(f"[INFO] Analyzing log file: {log_path}")

    failed_login_alerts = detect_failed_logins(log_path)
    brute_force_alerts = detect_brute_force(log_path)

    alerts = failed_login_alerts + brute_force_alerts

    if not alerts:
        print("[INFO] No alerts detected.")
        return []

    saved_count = 0

    for alert in alerts:
        ip_context = enrich_ip(alert["source_ip"])

        alert.update({
            "ip_type": ip_context["ip_type"],
            "reputation": ip_context["reputation"],
            "is_global": ip_context["is_global"],
            "enrichment_note": ip_context["enrichment_note"],
            "malicious_detections": ip_context.get(
                "malicious_detections", 0
            ),
            "suspicious_detections": ip_context.get(
                "suspicious_detections", 0
            ),
            "harmless_detections": ip_context.get(
                "harmless_detections", 0
            ),
        })

        alert_id = save_alert(alert)

        if alert_id is None:
            print(
                f"[SKIPPED] Duplicate alert: "
                f"{alert['rule']} from {alert['source_ip']}"
            )
            continue

        saved_count += 1

        print(
            f"[SAVED] Alert ID: {alert_id} | "
            f"Rule: {alert['rule']} | "
            f"Severity: {alert['severity']} | "
            f"Source IP: {alert['source_ip']} | "
            f"IP Type: {alert['ip_type']} | "
            f"Reputation: {alert['reputation']}"
        )

    print(
        f"[INFO] Detection complete. "
        f"Detected: {len(alerts)}, "
        f"New alerts saved: {saved_count}."
    )

    return alerts


if __name__ == "__main__":
    default_log_path = (
        Path(__file__).resolve().parents[2]
        / "sample_logs"
        / "auth.log"
    )

    run_pipeline(default_log_path)
