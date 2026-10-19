
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path


def detect_failed_logins(
    log_path,
    threshold=3,
    window_minutes=5,
):
    failures = defaultdict(deque)
    alerts = []

    window = timedelta(minutes=window_minutes)

    with Path(log_path).open("r", encoding="utf-8") as log_file:
        for line in log_file:
            if "FAILED_LOGIN" not in line:
                continue

            parts = line.split(maxsplit=2)

            if len(parts) < 3:
                continue

            try:
                timestamp = datetime.strptime(
                    f"{parts[0]} {parts[1]}",
                    "%Y-%m-%d %H:%M:%S",
                )
            except ValueError:
                continue

            fields = dict(
                item.split("=", 1)
                for item in parts[2].split()
                if "=" in item
            )

            source_ip = fields.get("source_ip")

            if not source_ip:
                continue

            attempts = failures[source_ip]

            while attempts and timestamp - attempts[0] > window:
                attempts.popleft()

            attempts.append(timestamp)

            if len(attempts) == threshold:
                alerts.append({
                    "rule": "Repeated Failed Logins",
                    "source_ip": source_ip,
                    "failed_attempts": len(attempts),
                    "severity": "HIGH",
                    "message": (
                        f"{len(attempts)} failed login attempts "
                        f"from {source_ip} within "
                        f"{window_minutes} minutes"
                    ),
                })

    return alerts


if __name__ == "__main__":
    log_path = (
        Path(__file__).resolve().parents[2]
        / "sample_logs"
        / "auth.log"
    )

    for alert in detect_failed_logins(log_path):
        print(alert)
