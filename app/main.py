from pathlib import Path
from datetime import date
import csv
import io

from flask import Flask, jsonify, request, send_from_directory, Response

from app.database.alert_store import (
    ALLOWED_STATUSES,
    get_alerts,
    initialize_database,
    update_alert_status,
)
from app.mitre import add_mitre


FRONTEND_DIR = Path(__file__).resolve().parents[1] / "frontend"
ALLOWED_SEVERITIES = {"HIGH", "MEDIUM", "LOW"}


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


def create_app():
    app = Flask(__name__)

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