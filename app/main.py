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
from app.mitre import add_mitre


FRONTEND_DIR = Path(__file__).resolve().parents[1] / "frontend"
ALLOWED_SEVERITIES = {"HIGH", "MEDIUM", "LOW"}

MAX_IMPORT_BYTES = 1024 * 1024
MAX_IMPORT_ROWS = 1000
REQUIRED_IMPORT_COLUMNS = {
    "rule", "source_ip", "failed_attempts", "severity", "message",
}
OPTIONAL_COUNT_COLUMNS = (
    "malicious_detections",
    "suspicious_detections",
    "harmless_detections",
)


def _parse_iso_date(value):
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def _in_date_range(alert, start, end):
    alert_day = _parse_iso_date(str(alert.get("created_at") or "")[:10])
    if alert_day is None:
        return False
    if start and alert_day < start:
        return False
    if end and alert_day > end:
        return False
    return True


def filter_alerts(alerts):
    """Return (filtered_alerts, error_dict_or_None)."""
    severity = request.args.get("severity", "").strip().upper()
    source_ip = request.args.get("source_ip", "").strip()
    start_raw = request.args.get("start_date", "").strip()
    end_raw = request.args.get("end_date", "").strip()

    if severity and severity not in ALLOWED_SEVERITIES:
        return None, {"error": "Invalid severity. Use HIGH, MEDIUM, or LOW."}

    start = end = None
    if start_raw:
        start = _parse_iso_date(start_raw)
        if start is None:
            return None, {"error": "Invalid start_date. Use YYYY-MM-DD."}
    if end_raw:
        end = _parse_iso_date(end_raw)
        if end is None:
            return None, {"error": "Invalid end_date. Use YYYY-MM-DD."}
    if start and end and start > end:
        return None, {"error": "start_date must be on or before end_date."}

    result = alerts
    if severity:
        result = [a for a in result if a["severity"] == severity]
    if source_ip:
        needle = source_ip.casefold()
        result = [a for a in result if needle in a["source_ip"].casefold()]
    if start or end:
        result = [a for a in result if _in_date_range(a, start, end)]
    return result, None


def _clean_import_row(row, line_number):
    """Validate one CSV row. Return (alert_dict, None) or (None, error)."""

    def text(key, default=""):
        value = row.get(key)
        return value.strip() if isinstance(value, str) else default

    rule = text("rule")
    message = text("message")
    source_ip = text("source_ip")
    severity = text("severity").upper()

    if not rule or not message:
        return None, f"Row {line_number}: rule and message are required."
    if len(rule) > 200 or len(message) > 1000:
        return None, f"Row {line_number}: rule or message is too long."

    try:
        ipaddress.ip_address(source_ip)
    except ValueError:
        return None, f"Row {line_number}: invalid source_ip."

    if severity not in ALLOWED_SEVERITIES:
        return None, (
            f"Row {line_number}: severity must be HIGH, MEDIUM, or LOW."
        )

    try:
        failed_attempts = int(text("failed_attempts"))
    except ValueError:
        return None, f"Row {line_number}: failed_attempts must be a number."
    if failed_attempts < 0:
        return None, f"Row {line_number}: failed_attempts cannot be negative."

    alert = {
        "rule": rule,
        "source_ip": source_ip,
        "failed_attempts": failed_attempts,
        "severity": severity,
        "message": message,
        "ip_type": text("ip_type", "Unknown") or "Unknown",
        "reputation": text("reputation", "Unknown") or "Unknown",
        "is_global": text("is_global").lower() in {"true", "1", "yes"},
        "enrichment_note": (
            text("enrichment_note") or "No enrichment information available."
        ),
    }

    for column in OPTIONAL_COUNT_COLUMNS:
        try:
            value = int(text(column) or 0)
        except ValueError:
            return None, f"Row {line_number}: {column} must be a number."
        alert[column] = max(value, 0)

    return alert, None


def create_app():
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_IMPORT_BYTES

    @app.errorhandler(413)
    def file_too_large(_error):
        return jsonify({"error": "File is too large (limit 1 MB)."}), 413

    @app.get("/")
    def home():
        return send_from_directory(FRONTEND_DIR, "index.html")

    @app.get("/health")
    def health():
        return jsonify({"status": "ok", "service": "SentinelSOC API"})

    @app.get("/api/alerts")
    def list_alerts():
        initialize_database()
        all_alerts = get_alerts()

        summary = {
            "total_alerts": len(all_alerts),
            "high_severity": sum(a["severity"] == "HIGH" for a in all_alerts),
            "medium_severity": sum(a["severity"] == "MEDIUM" for a in all_alerts),
            "low_severity": sum(a["severity"] == "LOW" for a in all_alerts),
            "unique_source_ips": len({a["source_ip"] for a in all_alerts}),
        }

        alerts, error = filter_alerts(all_alerts)
        if error:
            return jsonify(error), 400

        alerts = [add_mitre(a) for a in alerts]

        return jsonify({
            "count": len(alerts),
            "summary": summary,
            "alerts": alerts,
        })

    @app.get("/api/alerts/export")
    def export_alerts():
        initialize_database()
        alerts, error = filter_alerts(get_alerts())
        if error:
            return jsonify(error), 400

        alerts = [add_mitre(a) for a in alerts]

        fieldnames = [
            "id", "created_at", "rule", "severity", "source_ip",
            "failed_attempts", "status", "ip_type", "reputation",
            "is_global", "malicious_detections", "suspicious_detections",
            "harmless_detections", "enrichment_note",
            "mitre_id", "mitre_technique", "mitre_tactic",
            "message",
        ]

        output = io.StringIO()
        output.write("\ufeff")  # real BOM so Excel reads UTF-8
        writer = csv.DictWriter(
            output, fieldnames=fieldnames, extrasaction="ignore"
        )
        writer.writeheader()
        for alert in alerts:
            writer.writerow({f: alert.get(f, "") for f in fieldnames})

        response = Response(
            output.getvalue(), mimetype="text/csv; charset=utf-8"
        )
        response.headers["Content-Disposition"] = (
            'attachment; filename="sentinelsoc_alerts.csv"'
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.post("/api/alerts/import")
    def import_alerts():
        upload = request.files.get("file")
        if upload is None or not upload.filename:
            return jsonify({"error": "No CSV file uploaded."}), 400
        if not upload.filename.lower().endswith(".csv"):
            return jsonify({"error": "Please upload a .csv file."}), 400

        try:
            content = upload.read().decode("utf-8-sig")
        except UnicodeDecodeError:
            return jsonify({"error": "CSV must be UTF-8 encoded."}), 400

        reader = csv.DictReader(io.StringIO(content))
        if not reader.fieldnames:
            return jsonify({"error": "CSV file is empty."}), 400
        reader.fieldnames = [h.strip() for h in reader.fieldnames if h]

        missing = REQUIRED_IMPORT_COLUMNS - set(reader.fieldnames)
        if missing:
            return jsonify({
                "error": "Missing required column(s): "
                + ", ".join(sorted(missing))
            }), 400

        valid_alerts = []
        for line_number, row in enumerate(reader, start=2):
            if len(valid_alerts) >= MAX_IMPORT_ROWS:
                return jsonify({
                    "error": f"Too many rows (limit {MAX_IMPORT_ROWS})."
                }), 400
            alert, problem = _clean_import_row(row, line_number)
            if problem:
                return jsonify({"error": problem}), 400
            valid_alerts.append(alert)

        if not valid_alerts:
            return jsonify({"error": "CSV has no data rows."}), 400

        initialize_database()
        added = 0
        duplicates = 0
        for alert in valid_alerts:
            if save_alert(alert) is None:
                duplicates += 1
            else:
                added += 1

        return jsonify({
            "added": added,
            "duplicates_skipped": duplicates,
            "total_alerts": len(get_alerts()),
        }), 200

    @app.patch("/api/alerts/<int:alert_id>/status")
    def change_alert_status(alert_id):
        data = request.get_json(silent=True) or {}
        status = data.get("status")

        if not isinstance(status, str) or status not in ALLOWED_STATUSES:
            return jsonify({
                "error": "Status must be New, Investigating, or Resolved."
            }), 400

        initialize_database()
        if not update_alert_status(alert_id, status):
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