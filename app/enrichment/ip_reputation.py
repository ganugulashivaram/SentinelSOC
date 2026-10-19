
import ipaddress
import json
import os
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"
REQUEST_TIMEOUT = 5


def lookup_virustotal(address, api_key):
    """Look up a globally reachable IP using VirusTotal."""

    request = Request(
        VIRUSTOTAL_API_URL.format(address),
        headers={
            "x-apikey": api_key,
            "Accept": "application/json",
        },
        method="GET",
    )

    try:
        with urlopen(request, timeout=REQUEST_TIMEOUT) as response:
            data = json.loads(response.read().decode("utf-8"))

        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)

        if malicious > 0:
            reputation = "Malicious"
        elif suspicious > 0:
            reputation = "Suspicious"
        elif harmless > 0:
            reputation = "No malicious detections reported"
        else:
            reputation = "Unknown"

        return {
            "reputation": reputation,
            "malicious_detections": malicious,
            "suspicious_detections": suspicious,
            "harmless_detections": harmless,
            "enrichment_note": (
                f"VirusTotal analysis counts: "
                f"{malicious} malicious, "
                f"{suspicious} suspicious, "
                f"{harmless} harmless."
            ),
        }

    except HTTPError as error:
        if error.code == 401:
            note = "VirusTotal API key was rejected."
        elif error.code == 403:
            note = "VirusTotal denied the request or API access."
        elif error.code == 429:
            note = "VirusTotal rate limit reached."
        else:
            note = f"VirusTotal returned HTTP {error.code}."

    except (URLError, TimeoutError, OSError):
        note = "VirusTotal lookup failed or timed out."

    except (ValueError, TypeError, AttributeError):
        note = "VirusTotal returned an invalid response."

    return {
        "reputation": "Unknown",
        "malicious_detections": 0,
        "suspicious_detections": 0,
        "harmless_detections": 0,
        "enrichment_note": note,
    }


def enrich_ip(source_ip):
    """
    Classify an IP locally and optionally check VirusTotal.

    A reputation of Unknown does not mean an IP is safe.
    """

    source_ip = str(source_ip).strip()

    try:
        address = ipaddress.ip_address(source_ip)
    except ValueError:
        return {
            "source_ip": source_ip,
            "ip_type": "Invalid",
            "reputation": "Unknown",
            "is_global": False,
            "malicious_detections": 0,
            "suspicious_detections": 0,
            "harmless_detections": 0,
            "enrichment_note": "The source IP address is invalid.",
        }

    if address.is_loopback:
        ip_type = "Loopback"
        note = "This address refers to the local host."

    elif address.is_link_local:
        ip_type = "Link-local"
        note = "This address is intended for a local network link."

    elif address.is_multicast:
        ip_type = "Multicast"
        note = "This address is used for multicast traffic."

    elif address.is_unspecified:
        ip_type = "Unspecified"
        note = "This address does not identify a specific host."

    elif address.is_reserved:
        ip_type = "Reserved"
        note = "This address belongs to a reserved address range."

    elif address.is_private:
        ip_type = "Private"
        note = (
            "Private address. External reputation lookup was skipped."
        )

    elif address.is_global:
        ip_type = "Public"
        note = (
            "Public IP address. No threat-intelligence "
            "lookup has been performed."
        )

    else:
        ip_type = "Special-purpose"
        note = "This address is not globally reachable."

    result = {
        "source_ip": str(address),
        "ip_type": ip_type,
        "reputation": "Unknown",
        "is_global": address.is_global,
        "malicious_detections": 0,
        "suspicious_detections": 0,
        "harmless_detections": 0,
        "enrichment_note": note,
    }

    # Only query VirusTotal when the address is global and
    # an API key is configured.
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()

    if address.is_global and api_key:
        result.update(lookup_virustotal(str(address), api_key))

    elif address.is_global:
        result["enrichment_note"] = (
            "No VirusTotal lookup performed. "
            "Configure VIRUSTOTAL_API_KEY to enable reputation checks."
        )

    return result
