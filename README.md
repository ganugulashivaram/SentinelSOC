# SentinelSOC - Security Operations Center Dashboard

SentinelSOC is a Python-based Security Operations Center (SOC) monitoring and alert investigation project. It demonstrates how security events can be detected, stored, enriched, reviewed, and managed through a web dashboard.

The project is designed to showcase practical skills relevant to entry-level SOC Analyst and Cybersecurity Analyst roles.

## Key Features

- **Security Dashboard:** Review alerts and severity statistics.
- **Detection Rules:** Detect repeated failed logins and potential brute-force activity from log files.
- **Alert Management:** Track alerts as New, Investigating, or Resolved.
- **Filtering and Search:** Filter by severity, source IP, and date range.
- **Alert Sorting:** Sort alert records by ID.
- **Alert Details:** Inspect detection information, timestamps, and available enrichment results.
- **IP Reputation Enrichment:** Classify IP addresses and optionally query VirusTotal for globally reachable IP addresses.
- **Duplicate Prevention:** Avoid saving duplicate alerts.
- **CSV Export:** Export alert records for reporting.
- **CSV Import:** Import sample alert records through the dashboard with validation.
- **REST API:** Retrieve alerts, filter results, update statuses, and check application health.
- **Automated Tests:** Validate detection logic, storage, API behavior, and IP reputation handling.

## Technology Stack

| Component | Technology |
|---|---|
| Backend | Python, Flask |
| Frontend | HTML5, CSS3, JavaScript |
| Database | SQLite |
| API | REST-style HTTP endpoints |
| Data exchange | JSON, CSV |
| IP intelligence | VirusTotal API (optional) |
| Testing | pytest |
| Development environment | Python virtual environment, PowerShell, Git |

## Project Structure

```text
SentinelSOC/
|-- app/
|   |-- main.py
|   |-- mitre.py
|   |-- database/
|   |   `-- alert_store.py
|   |-- enrichment/
|   |   `-- ip_reputation.py
|   |-- detection/
|   |   `-- ...
|   `-- services/
|       `-- alert_pipeline.py
|-- frontend/
|   |-- index.html
|   |-- script.js
|   `-- style.css
|-- sample_logs/
|-- tests/
|-- .github/workflows/tests.yml
|-- .env.example
|-- .gitignore
|-- Dockerfile
|-- main.py
|-- pyproject.toml
|-- requirements.txt
|-- sentinelsoc_sample_alerts.csv
`-- README.md
```

The structure above highlights the main components. Detection modules and additional files may vary as the project evolves.

## Requirements

- Python 3
- pip
- Git (for version control)
- A Windows, Linux, or macOS development environment

## Installation and Setup

### 1. Clone the repository

After publishing the project to GitHub, replace the placeholder URL with your repository URL.

```bash
git clone <YOUR-GITHUB-REPOSITORY-URL>
cd SentinelSOC
```

Alternatively, open your existing project directory without cloning.

### 2. Create and activate a virtual environment

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
python -m pip install -r requirements.txt
```

### 4. Configure optional VirusTotal enrichment

Copy `.env.example` to `.env` if you plan to configure an API key:

```powershell
Copy-Item .env.example .env
notepad .env
```

Set `VIRUSTOTAL_API_KEY` to your own VirusTotal API key if you have one.

**Security note:** Never commit `.env` or publish a real API key. VirusTotal integration is optional; the project supports operation without an API key.

### 5. Run automated tests

```powershell
python -m pytest -v
```

The project was last verified in the development environment with **24 tests passing**. Run the test suite again after making changes to confirm the current result.

### 6. Start the dashboard

```powershell
python -m flask --app app.main run --debug
```

Open the following URL in your browser:

http://127.0.0.1:5000/

The Flask development server is intended for local development, not direct production deployment.

## API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/` | Open the dashboard |
| GET | `/health` | Check application health |
| GET | `/api/alerts` | Retrieve and filter alerts |
| GET | `/api/alerts/export` | Export matching alerts as CSV |
| POST | `/api/alerts/import` | Import validated CSV alerts |
| PATCH | `/api/alerts/<id>/status` | Update an alert's investigation status |

### Example requests

Filter high-severity alerts:

```text
/api/alerts?severity=HIGH
```

Search by source IP:

```text
/api/alerts?source_ip=192.0.2.10
```

Filter by date:

```text
/api/alerts?start_date=2026-10-01&end_date=2026-10-16
```

These examples illustrate query parameters. Use the actual dates and IP addresses appropriate for your test data.

## Detection and Investigation Workflow

1. Read security events from sample log files.
2. Apply detection rules for repeated failed logins and brute-force activity.
3. Create alert records when detection conditions are met.
4. Store alerts in SQLite and prevent duplicate records.
5. Enrich IP information locally and optionally query VirusTotal.
6. Display alert details and severity statistics in the dashboard.
7. Filter and investigate alerts by severity, source IP, or date.
8. Update investigation status and export records for reporting.

## Testing

Automated tests cover areas including:

- Alert creation, retrieval, and duplicate prevention.
- API health, alert retrieval, and filtering.
- Repeated failed-login detection.
- Brute-force detection.
- Integrated detection pipeline behavior.
- Private, loopback, and public IP handling.
- VirusTotal success and failure scenarios.

Run the tests with:

```powershell
python -m pytest -v
```

## Security Considerations

- Use only authorized log data and systems.
- Keep API keys in environment variables rather than source code.
- Do not commit local databases, secrets, or sensitive logs.
- Treat reputation results as investigation signals, not definitive proof of malicious activity.
- Use authentication, access controls, HTTPS, and production server settings before exposing the application to a network.
- Validate imported CSV data and avoid treating simulated alerts as real incidents.

## Future Improvements

Potential enhancements include:

- Windows Event Log ingestion.
- Additional detection rules and MITRE ATT&CK mapping.
- Analyst authentication and role-based access control.
- Alert audit history and investigation notes.
- Real-time updates and expanded metrics.
- Production deployment and security hardening.

These items are planned improvements, not claims about existing functionality.

## Author

**Gangula Shivaram**

B.Tech, Computer Science and Engineering (Cyber Security), 2026

Career interests: SOC Analyst, Cybersecurity Analyst, Security Monitoring, and Incident Response.

---

*SentinelSOC is an educational cybersecurity project demonstrating defensive monitoring, detection, and alert investigation workflows.*
