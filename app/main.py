
from pathlib import Path
from datetime import date
import csv
import io
import ipaddress

from flask import Flask, jsonify, request, send_from_directory, Response

from app.database.alert_store import (
    ALLOWED_STATUSES,
    get_alerts,
    initialize_database,
    save_alert,
    update_alert_status,
)


FRONTEND_DIR = Path(__file__).resolve().parents[1] / "frontend"
ALLOWED_SEVERITIES = {"HIGH", "MEDIUM", "LOW"}
IMPORT_FIELDS = {
    "rule",
    "source_ip",
    "failed_attempts",
    "severity",
    "message",
}
MAX_IMPORT_BYTES = 1 * 1024 * 1024
MAX_IMPORT_ROWS = 500


def filter_alerts(alerts):
    """Filter alerts by severity, source IP, and date range."""
    severity = request.args.get("severity", "").strip().upper()
    source_ip = request.args.get("source_ip", "").strip()
    start_date = request.args.get("start_date", "").strip()
    end_date = request.args.get("end_date", "").strip()

    if severity and severity not in ALLOWED_SEVERITIES:
        return None, (
            jsonify({
                "error": "Invalid severity. Use HIGH, MEDIUM, or LOW."
            }),
            400,
        )

    try:
        parsed_start = date.fromisoformat(start_date) if start_date else None
        parsed_end = date.fromisoformat(end_date) if end_date else None
    except ValueError:
        return None, (
            jsonify({"error": "Dates must use YYYY-MM-DD format."}),
            400,
        )

    if parsed_start and parsed_end and parsed_start > parsed_end:
        return None, (
            jsonify({"error": "start_date must not be after end_date."}),
            400,
        )

    filtered = alerts

    if severity:
        filtered = [
            alert for alert in filtered
            if alert["severity"] == severity
        ]

    if source_ip:
        filtered = [
            alert for alert in filtered
            if source_ip.casefold() in alert["source_ip"].casefold()
        ]

    if parsed_start:
        filtered = [
            alert for alert in filtered
            if (alert.get("created_at") or "")[:10] >= start_date
        ]

    if parsed_end:
        filtered = [
            alert for alert in filtered
            if (alert.get("created_at") or "")[:10] <= end_date
        ]

    return filtered, None


def validate_import_csv(file_storage):
    """Validate all CSV rows before writing any of them."""
    raw = file_storage.stream.read(MAX_IMPORT_BYTES + 1)

    if len(raw) > MAX_IMPORT_BYTES:
        raise ValueError("CSV file exceeds the 1 MB size limit.")

    if not raw.strip():
        raise ValueError("The uploaded CSV file is empty.")

    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("CSV must use UTF-8 encoding.") from exc

    reader = csv.DictReader(io.StringIO(text, newline=""))

    if not reader.fieldnames:
        raise ValueError("CSV must contain a header row.")

    reader.fieldnames = [
        (field or "").strip().lower()
        for field in reader.fieldnames
    ]

    if len(reader.fieldnames) != len(set(reader.fieldnames)):
        raise ValueError("CSV contains duplicate column names.")

    missing = IMPORT_FIELDS - set(reader.fieldnames)

    if missing:
        raise ValueError(
            "Missing required columns: " + ", ".join(sorted(missing))
        )

    records = []

    for line_number, row in enumerate(reader, start=2):
        if line_number > MAX_IMPORT_ROWS + 1:
            raise ValueError(
                f"CSV may contain at most {MAX_IMPORT_ROWS} data rows."
            )

        if None in row:
            raise ValueError(
                f"Row {line_number} has more columns than the header."
            )

        normalized = {
            (key or "").strip().lower(): (value or "").strip()
            for key, value in row.items()
            if key is not None
        }

        if not any(normalized.values()):
            continue

        rule = normalized.get("rule", "")
        source_ip = normalized.get("source_ip", "")
        severity = normalized.get("severity", "").upper()
        message = normalized.get("message", "")
        attempts_text = normalized.get("failed_attempts", "")

        if not rule or not source_ip or not message:
            raise ValueError(
                f"Row {line_number}: rule, source_ip, and message "
                "must not be empty."
            )

        if len(rule) > 200 or len(message) > 4000:
            raise ValueError(
                f"Row {line_number}: rule or message is too long."
            )

        if len(source_ip) > 45:
            raise ValueError(
                f"Row {line_number}: source_ip is too long."
            )

        try:
            ipaddress.ip_address(source_ip)
        except ValueError as exc:
            raise ValueError(
                f"Row {line_number}: source_ip must be a valid IP address."
            ) from exc

        if severity not in ALLOWED_SEVERITIES:
            raise ValueError(
                f"Row {line_number}: severity must be HIGH, MEDIUM, or LOW."
            )

        try:
            attempts = int(attempts_text)
        except ValueError as exc:
            raise ValueError(
                f"Row {line_number}: failed_attempts must be an integer."
            ) from exc

        if not 0 <= attempts <= 1_000_000:
            raise ValueError(
                f"Row {line_number}: failed_attempts must be between 0 "
                "and 1000000."
            )

        records.append({
            "rule": rule,
            "source_ip": source_ip,
            "failed_attempts": attempts,
            "severity": severity,
            "message": message,
        })

    if not records:
        raise ValueError("CSV contains no alert records.")

    return records


def create_app():
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_IMPORT_BYTES + 64 * 1024

    @app.errorhandler(413)
    def request_too_large(_error):
        return jsonify({"error": "Upload is too large."}), 413

    @app.get("/")
    def home():
        return send_from_directory(FRONTEND_DIR, "index.html")

    @app.get("/health")
    def health():
        return jsonify({
            "status": "ok",
            "service": "SentinelSOC API",
        })

    @app.get("/api/alerts")
    def list_alerts():
        initialize_database()
        all_alerts = get_alerts()

        summary = {
            "total_alerts": len(all_alerts),
            "high_severity": sum(
                alert["severity"] == "HIGH" for alert in all_alerts
            ),
            "medium_severity": sum(
                alert["severity"] == "MEDIUM" for alert in all_alerts
            ),
            "low_severity": sum(
                alert["severity"] == "LOW" for alert in all_alerts
            ),
            "unique_source_ips": len({
                alert["source_ip"] for alert in all_alerts
            }),
        }

        alerts, error = filter_alerts(all_alerts)

        if error:
            return error

        return jsonify({
            "count": len(alerts),
            "summary": summary,
            "alerts": alerts,
        })

    @app.post("/api/alerts/import")
    def import_alerts():
        uploaded_file = request.files.get("file")

        if uploaded_file is None or not uploaded_file.filename:
            return jsonify({
                "error": "Select a CSV file to import."
            }), 400

        if not uploaded_file.filename.lower().endswith(".csv"):
            return jsonify({
                "error": "Only CSV files can be imported."
            }), 400

        try:
            records = validate_import_csv(uploaded_file)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        # Validate every row before modifying the database.
        initialize_database()
        added = 0
        duplicates = 0

        for record in records:
            alert_id = save_alert(record)

            if alert_id is None:
                duplicates += 1
            else:
                added += 1

        return jsonify({
            "message": "CSV import completed.",
            "received": len(records),
            "added": added,
            "duplicates_skipped": duplicates,
            "total_alerts": len(get_alerts()),
        }), 200

    @app.get("/api/alerts/export")
    def export_alerts():
        initialize_database()
        all_alerts = get_alerts()

        alerts, error = filter_alerts(all_alerts)

        if error:
            return error

        output = io.StringIO()
        output.write("\ufeff")

        fieldnames = [
            "id", "created_at", "rule", "severity", "source_ip",
            "failed_attempts", "status", "ip_type", "reputation",
            "is_global", "malicious_detections",
            "suspicious_detections", "harmless_detections",
            "enrichment_note", "message",
        ]

        writer = csv.DictWriter(
            output,
            fieldnames=fieldnames,
            extrasaction="ignore",
        )
        writer.writeheader()

        for alert in alerts:
            writer.writerow({
                field: alert.get(field, "")
                for field in fieldnames
            })

        response = Response(
            output.getvalue(),
            mimetype="text/csv; charset=utf-8",
        )
        response.headers["Content-Disposition"] = (
            'attachment; filename="sentinelsoc_alerts.csv"'
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.patch("/api/alerts/<int:alert_id>/status")
    def change_alert_status(alert_id):
        data = request.get_json(silent=True) or {}
        status = data.get("status")

        if not isinstance(status, str) or status not in ALLOWED_STATUSES:
            return jsonify({
                "error": "Status must be New, Investigating, or Resolved."
            }), 400

        initialize_database()
        updated = update_alert_status(alert_id, status)

        if not updated:
            return jsonify({"error": "Alert not found."}), 404

        return jsonify({
            "message": "Alert status updated.",
            "id": alert_id,
            "status": status,
        }), 200

    @app.get("/<path:filename>")
    def serve_frontend_file(filename):
        return send_from_directory(FRONTEND_DIR, filename)

    return app


app = create_app()
