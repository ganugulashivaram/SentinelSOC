
import sqlite3
from pathlib import Path


DB_PATH = Path(__file__).resolve().parents[2] / "sentinelsoc.db"

ALLOWED_STATUSES = {"New", "Investigating", "Resolved"}


def initialize_database(db_path=DB_PATH):
    """Create tables and safely migrate existing databases."""

    with sqlite3.connect(db_path) as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                failed_attempts INTEGER NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)

        columns = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(alerts)"
            ).fetchall()
        }

        migrations = {
            "status": """
                ALTER TABLE alerts ADD COLUMN
                status TEXT NOT NULL DEFAULT 'New'
            """,
            "ip_type": """
                ALTER TABLE alerts ADD COLUMN
                ip_type TEXT NOT NULL DEFAULT 'Unknown'
            """,
            "reputation": """
                ALTER TABLE alerts ADD COLUMN
                reputation TEXT NOT NULL DEFAULT 'Unknown'
            """,
            "is_global": """
                ALTER TABLE alerts ADD COLUMN
                is_global INTEGER NOT NULL DEFAULT 0
            """,
            "enrichment_note": """
                ALTER TABLE alerts ADD COLUMN
                enrichment_note TEXT NOT NULL DEFAULT
                'No enrichment information available.'
            """,
            "malicious_detections": """
                ALTER TABLE alerts ADD COLUMN
                malicious_detections INTEGER NOT NULL DEFAULT 0
            """,
            "suspicious_detections": """
                ALTER TABLE alerts ADD COLUMN
                suspicious_detections INTEGER NOT NULL DEFAULT 0
            """,
            "harmless_detections": """
                ALTER TABLE alerts ADD COLUMN
                harmless_detections INTEGER NOT NULL DEFAULT 0
            """,
        }

        for column, statement in migrations.items():
            if column not in columns:
                connection.execute(statement)


def save_alert(alert, db_path=DB_PATH):
    """Save an alert and skip duplicate detection records."""

    initialize_database(db_path)

    ip_type = alert.get("ip_type", "Unknown")
    reputation = alert.get("reputation", "Unknown")
    is_global = int(bool(alert.get("is_global", False)))
    enrichment_note = alert.get(
        "enrichment_note",
        alert.get("note", "No enrichment information available."),
    )

    malicious = int(alert.get("malicious_detections", 0) or 0)
    suspicious = int(alert.get("suspicious_detections", 0) or 0)
    harmless = int(alert.get("harmless_detections", 0) or 0)

    with sqlite3.connect(db_path) as connection:
        existing = connection.execute("""
            SELECT id
            FROM alerts
            WHERE rule = ?
              AND source_ip = ?
              AND failed_attempts = ?
              AND severity = ?
              AND message = ?
            LIMIT 1
        """, (
            alert["rule"],
            alert["source_ip"],
            alert["failed_attempts"],
            alert["severity"],
            alert["message"],
        )).fetchone()

        if existing:
            return None

        cursor = connection.execute("""
            INSERT INTO alerts (
                rule,
                source_ip,
                failed_attempts,
                severity,
                message,
                ip_type,
                reputation,
                is_global,
                enrichment_note,
                malicious_detections,
                suspicious_detections,
                harmless_detections
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert["rule"],
            alert["source_ip"],
            alert["failed_attempts"],
            alert["severity"],
            alert["message"],
            ip_type,
            reputation,
            is_global,
            enrichment_note,
            malicious,
            suspicious,
            harmless,
        ))

        return cursor.lastrowid


def get_alerts(db_path=DB_PATH):
    """Return stored alerts, newest first."""

    initialize_database(db_path)

    with sqlite3.connect(db_path) as connection:
        connection.row_factory = sqlite3.Row

        rows = connection.execute("""
            SELECT
                id,
                rule,
                source_ip,
                failed_attempts,
                severity,
                message,
                created_at,
                status,
                ip_type,
                reputation,
                is_global,
                enrichment_note,
                malicious_detections,
                suspicious_detections,
                harmless_detections
            FROM alerts
            ORDER BY id DESC
        """).fetchall()

        alerts = [dict(row) for row in rows]

        for alert in alerts:
            alert["is_global"] = bool(alert["is_global"])

        return alerts


def update_alert_status(alert_id, status, db_path=DB_PATH):
    """Update an alert status and report whether it exists."""

    if status not in ALLOWED_STATUSES:
        raise ValueError(
            "Status must be New, Investigating, or Resolved."
        )

    initialize_database(db_path)

    with sqlite3.connect(db_path) as connection:
        cursor = connection.execute("""
            UPDATE alerts
            SET status = ?
            WHERE id = ?
        """, (status, alert_id))

        return cursor.rowcount > 0
