
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
import re


TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"

FAILED_LOGIN_PATTERN = re.compile(
    r"FAILED_LOGIN\s+user=(\S+)\s+source_ip=(\S+)"
)


def detect_brute_force(
    log_path,
    threshold=10,
    window_minutes=5,
):
    """
    Detect repeated failed login attempts from one source IP
    within a configurable time window.
    """

    if threshold < 1:
        raise ValueError("Threshold must be at least 1.")

    if window_minutes < 1:
        raise ValueError("Window must be at least 1 minute.")

    log_path = Path(log_path)

    if not log_path.is_file():
        raise FileNotFoundError(
            f"Log file not found: {log_path}"
        )

    attempts_by_ip = defaultdict(deque)
    alerts = []
    window = timedelta(minutes=window_minutes)
    alerted_ips = set()

    with log_path.open("r", encoding="utf-8") as log_file:
        for line in log_file:
            match = FAILED_LOGIN_PATTERN.search(line)

            if not match:
                continue

            username, source_ip = match.groups()

            timestamp_text = line[:19]

            try:
                timestamp = datetime.strptime(
                    timestamp_text,
                    TIMESTAMP_FORMAT,
                )
            except ValueError:
                continue

            attempts = attempts_by_ip[source_ip]

            while attempts and timestamp - attempts[0] > window:
                attempts.popleft()

            attempts.append(timestamp)

            if (
                len(attempts) >= threshold
                and source_ip not in alerted_ips
            ):
                alerts.append({
                    "rule": "Brute-Force Login Detection",
                    "source_ip": source_ip,
                    "failed_attempts": len(attempts),
                    "severity": "HIGH",
                    "message": (
                        f"Detected {len(attempts)} failed login "
                        f"attempts from {source_ip} within "
                        f"{window_minutes} minutes. "
                        f"Latest targeted username: {username}."
                    ),
                })

                alerted_ips.add(source_ip)

    return alerts
