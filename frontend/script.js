
const API_URL = "/api/alerts";
const EXPORT_URL = "/api/alerts/export";
const IMPORT_URL = "/api/alerts/import";

const connection = document.getElementById("connection");
const message = document.getElementById("message");
const alertsBody = document.getElementById("alerts-body");

const severityFilter = document.getElementById("severity-filter");
const ipSearch = document.getElementById("ip-search");
const startDateInput = document.getElementById("start-date");
const endDateInput = document.getElementById("end-date");
const applyDateButton = document.getElementById("apply-date-filter");
const clearDateButton = document.getElementById("clear-date-filter");
const sortFilter = document.getElementById("sort-filter");
const refreshButton = document.getElementById("refresh-btn");
const exportButton = document.getElementById("export-btn");

const importForm = document.getElementById("import-form");
const importFileInput = document.getElementById("import-file");
const importButton = document.getElementById("import-btn");
const importMessage = document.getElementById("import-message");

const totalAlerts = document.getElementById("total-alerts");
const highAlerts = document.getElementById("high-alerts");
const mediumAlerts = document.getElementById("medium-alerts");
const lowAlerts = document.getElementById("low-alerts");
const uniqueIPs = document.getElementById("unique-ips");

const detailsOverlay = document.getElementById("details-overlay");
const detailsContent = document.getElementById("details-content");
const closeDetailsButton = document.getElementById("close-details");

const ALLOWED_STATUSES = ["New", "Investigating", "Resolved"];
const SEVERITY_CONFIG = [
    { name: "HIGH", color: "#dc2626" },
    { name: "MEDIUM", color: "#d97706" },
    { name: "LOW", color: "#16a34a" },
];

let severityChartElements = null;

function getFilterParams() {
    const params = new URLSearchParams();
    const severity = severityFilter?.value ?? "";
    const sourceIP = ipSearch?.value.trim() ?? "";
    const startDate = startDateInput?.value ?? "";
    const endDate = endDateInput?.value ?? "";

    if (severity) params.set("severity", severity);
    if (sourceIP) params.set("source_ip", sourceIP);
    if (startDate) params.set("start_date", startDate);
    if (endDate) params.set("end_date", endDate);

    return params;
}

function validateDateRange() {
    const startDate = startDateInput?.value ?? "";
    const endDate = endDateInput?.value ?? "";

    if (startDate && endDate && startDate > endDate) {
        message.textContent =
            "Start date must not be after the end date.";
        startDateInput?.focus();
        return false;
    }

    return true;
}

function ensureSeverityChart() {
    if (severityChartElements) return severityChartElements;

    const summaryCards = document.querySelector(".summary-cards");
    if (!summaryCards) return null;

    const section = document.createElement("section");
    section.id = "severity-chart-section";
    section.setAttribute("aria-labelledby", "severity-chart-title");

    Object.assign(section.style, {
        background: "var(--card-bg, #ffffff)",
        border: "1px solid var(--border-color, #e2e8f0)",
        borderRadius: "12px",
        padding: "20px",
        margin: "24px 0",
        boxSizing: "border-box",
    });

    const heading = document.createElement("h2");
    heading.id = "severity-chart-title";
    heading.textContent = "Alert Severity Distribution";

    const description = document.createElement("p");
    description.textContent =
        "Overview of all stored alerts by severity.";
    description.style.color = "#64748b";

    const chart = document.createElement("div");
    chart.id = "severity-chart";

    Object.assign(chart.style, {
        display: "flex",
        flexDirection: "column",
        gap: "18px",
    });

    section.append(heading, description, chart);
    summaryCards.parentNode.insertBefore(section, summaryCards.nextSibling);

    const elements = {};

    for (const item of SEVERITY_CONFIG) {
        const row = document.createElement("div");
        Object.assign(row.style, {
            display: "grid",
            gridTemplateColumns: "75px minmax(60px, 1fr) 115px",
            alignItems: "center",
            gap: "12px",
        });

        const label = document.createElement("span");
        label.textContent = item.name;
        label.style.fontWeight = "700";

        const track = document.createElement("div");
        Object.assign(track.style, {
            height: "16px",
            background: "#e2e8f0",
            borderRadius: "999px",
            overflow: "hidden",
        });

        const bar = document.createElement("div");
        Object.assign(bar.style, {
            width: "0%",
            height: "100%",
            background: item.color,
            borderRadius: "999px",
            transition: "width 250ms ease",
        });
        track.appendChild(bar);

        const count = document.createElement("span");
        count.style.textAlign = "right";

        row.append(label, track, count);
        chart.appendChild(row);
        elements[item.name] = { bar, count };
    }

    severityChartElements = elements;
    return elements;
}

function updateSeverityChart(summary) {
    const elements = ensureSeverityChart();
    if (!elements) return;

    const counts = {
        HIGH: Number(summary.high_severity) || 0,
        MEDIUM: Number(summary.medium_severity) || 0,
        LOW: Number(summary.low_severity) || 0,
    };

    const largestCount = Math.max(...Object.values(counts), 0);

    for (const item of SEVERITY_CONFIG) {
        const count = counts[item.name];
        const percentage = largestCount > 0
            ? (count / largestCount) * 100
            : 0;

        elements[item.name].bar.style.width = `${percentage}%`;
        elements[item.name].count.textContent =
            `${count} alert${count === 1 ? "" : "s"}`;
    }
}

async function loadAlerts() {
    if (!validateDateRange()) return;

    connection.textContent = "Connecting...";
    message.textContent = "Loading alerts...";

    try {
        const params = getFilterParams();
        const queryString = params.toString();
        const url = queryString ? `${API_URL}?${queryString}` : API_URL;
        const response = await fetch(url);

        if (!response.ok) {
            let errorMessage = `API returned HTTP ${response.status}`;
            try {
                const errorData = await response.json();
                errorMessage = errorData.error ?? errorMessage;
            } catch {
                // Keep the HTTP error.
            }
            throw new Error(errorMessage);
        }

        const data = await response.json();

        if (!Array.isArray(data.alerts)) {
            throw new Error("Invalid API response: alerts must be an array.");
        }

        const alerts = [...data.alerts];
        const summary = data.summary ?? {};

        totalAlerts.textContent = summary.total_alerts ?? 0;
        highAlerts.textContent = summary.high_severity ?? 0;
        mediumAlerts.textContent = summary.medium_severity ?? 0;
        lowAlerts.textContent = summary.low_severity ?? 0;
        uniqueIPs.textContent = summary.unique_source_ips ?? 0;

        updateSeverityChart(summary);

        const sortOrder = sortFilter?.value ?? "newest";
        alerts.sort((a, b) => {
            const firstID = Number(a.id) || 0;
            const secondID = Number(b.id) || 0;
            return sortOrder === "oldest"
                ? firstID - secondID
                : secondID - firstID;
        });

        alertsBody.replaceChildren();

        for (const alertItem of alerts) {
            const row = document.createElement("tr");
            const values = [
                alertItem.id,
                alertItem.severity,
                alertItem.rule,
                alertItem.source_ip,
                alertItem.failed_attempts,
                alertItem.created_at
                    ? `${alertItem.created_at} UTC`
                    : "",
            ];

            values.forEach((value, index) => {
                const cell = document.createElement("td");
                cell.textContent = value ?? "";
                if (index === 1) {
                    cell.className = String(
                        alertItem.severity ?? ""
                    ).toLowerCase();
                }
                row.appendChild(cell);
            });

            const statusCell = document.createElement("td");
            const statusSelect = document.createElement("select");
            statusSelect.setAttribute(
                "aria-label",
                `Status for alert ${alertItem.id}`
            );

            for (const status of ALLOWED_STATUSES) {
                const option = document.createElement("option");
                option.value = status;
                option.textContent = status;
                statusSelect.appendChild(option);
            }

            statusSelect.value = ALLOWED_STATUSES.includes(alertItem.status)
                ? alertItem.status
                : "New";

            statusSelect.addEventListener("change", async () => {
                const previousStatus = alertItem.status ?? "New";
                const updated = await updateAlertStatus(
                    alertItem.id,
                    statusSelect,
                    previousStatus
                );
                if (updated) alertItem.status = statusSelect.value;
            });

            statusCell.appendChild(statusSelect);
            row.appendChild(statusCell);

            const detailsCell = document.createElement("td");
            const detailsButton = document.createElement("button");
            detailsButton.type = "button";
            detailsButton.textContent = "View Details";
            detailsButton.addEventListener("click", () => {
                showAlertDetails({
                    ...alertItem,
                    status: statusSelect.value,
                });
            });

            detailsCell.appendChild(detailsButton);
            row.appendChild(detailsCell);
            alertsBody.appendChild(row);
        }

        connection.textContent = "API Connected";
        message.textContent = alerts.length
            ? `${alerts.length} alert record(s) loaded.`
            : "No alerts found for the selected filters.";
    } catch (error) {
        connection.textContent = "API Disconnected";
        message.textContent = `Could not load alerts. ${error.message}`;
        alertsBody.replaceChildren();
        console.error("Failed to load alerts:", error);
    }
}

async function updateAlertStatus(alertId, statusSelect, previousStatus) {
    const newStatus = statusSelect.value;
    statusSelect.disabled = true;
    message.textContent = `Updating alert #${alertId}...`;

    try {
        const response = await fetch(`${API_URL}/${alertId}/status`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ status: newStatus }),
        });

        const result = await response.json();
        if (!response.ok) {
            throw new Error(result.error ?? `HTTP ${response.status}`);
        }

        statusSelect.value = result.status;
        message.textContent =
            `Alert #${alertId} status updated to ${result.status}.`;
        return true;
    } catch (error) {
        statusSelect.value = previousStatus;
        message.textContent =
            `Could not update alert #${alertId}. ${error.message}`;
        console.error("Failed to update alert status:", error);
        return false;
    } finally {
        statusSelect.disabled = false;
    }
}

function exportAlerts() {
    if (!validateDateRange()) return;

    const params = getFilterParams();
    const queryString = params.toString();
    const url = queryString
        ? `${EXPORT_URL}?${queryString}`
        : EXPORT_URL;

    window.location.assign(url);
}

function showAlertDetails(alertItem) {
    if (!detailsOverlay || !detailsContent) return;

    const fields = [
        ["Alert ID", alertItem.id],
        ["Severity", alertItem.severity],
        ["Detection Rule", alertItem.rule],
        ["Source IP", alertItem.source_ip],
        ["Failed Attempts", alertItem.failed_attempts],
        ["Status", alertItem.status ?? "New"],
        ["IP Classification", alertItem.ip_type ?? "Unknown"],
        ["IP Reputation", alertItem.reputation ?? "Unknown"],
        [
            "Globally Reachable",
            alertItem.is_global === true ? "Yes"
                : alertItem.is_global === false ? "No" : "Unknown",
        ],
        ["VirusTotal Malicious Detections", alertItem.malicious_detections ?? 0],
        ["VirusTotal Suspicious Detections", alertItem.suspicious_detections ?? 0],
        ["VirusTotal Harmless Detections", alertItem.harmless_detections ?? 0],
        [
            "Enrichment Notes",
            alertItem.enrichment_note ?? "No enrichment information available.",
        ],
        ["Message", alertItem.message],
        ["Detected At (UTC)", alertItem.created_at],
    ];

    detailsContent.replaceChildren();

    for (const [label, value] of fields) {
        const item = document.createElement("div");
        item.className = "detail-item";

        const labelElement = document.createElement("span");
        labelElement.className = "detail-label";
        labelElement.textContent = label;

        const valueElement = document.createElement("div");
        valueElement.className = "detail-value";
        valueElement.textContent = value ?? "N/A";

        item.append(labelElement, valueElement);
        detailsContent.appendChild(item);
    }

    detailsOverlay.hidden = false;
    closeDetailsButton?.focus();
}

function closeAlertDetails() {
    if (detailsOverlay) detailsOverlay.hidden = true;
}

async function importCSV(event) {
    event.preventDefault();

    const file = importFileInput.files?.[0];

    if (!file) {
        importMessage.textContent = "Choose a CSV file first.";
        return;
    }

    if (!file.name.toLowerCase().endsWith(".csv")) {
        importMessage.textContent = "Please select a .csv file.";
        return;
    }

    const formData = new FormData();
    formData.append("file", file);

    importButton.disabled = true;
    importMessage.textContent = "Validating and importing CSV...";

    try {
        const response = await fetch(IMPORT_URL, {
            method: "POST",
            body: formData,
        });

        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.error ?? `HTTP ${response.status}`);
        }

        importMessage.textContent =
            `Import complete: ${result.added} added, ` +
            `${result.duplicates_skipped} duplicate(s) skipped. ` +
            `Total alerts: ${result.total_alerts}.`;

        importForm.reset();
        await loadAlerts();
    } catch (error) {
        importMessage.textContent = `Import failed: ${error.message}`;
    } finally {
        importButton.disabled = false;
    }
}

applyDateButton?.addEventListener("click", loadAlerts);

clearDateButton?.addEventListener("click", () => {
    startDateInput.value = "";
    endDateInput.value = "";
    loadAlerts();
});

severityFilter?.addEventListener("change", loadAlerts);
ipSearch?.addEventListener("input", loadAlerts);
sortFilter?.addEventListener("change", loadAlerts);
refreshButton?.addEventListener("click", loadAlerts);
exportButton?.addEventListener("click", exportAlerts);
importForm?.addEventListener("submit", importCSV);
closeDetailsButton?.addEventListener("click", closeAlertDetails);

detailsOverlay?.addEventListener("click", (event) => {
    if (event.target === detailsOverlay) closeAlertDetails();
});

document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closeAlertDetails();
});

loadAlerts();
