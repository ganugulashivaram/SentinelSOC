
import json
from io import BytesIO

from app.enrichment import ip_reputation
from app.enrichment.ip_reputation import enrich_ip


def test_private_ip_skips_external_lookup(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")

    result = enrich_ip("192.168.1.50")

    assert result["ip_type"] == "Private"
    assert result["reputation"] == "Unknown"
    assert result["is_global"] is False


def test_public_ip_without_api_key(monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)

    result = enrich_ip("8.8.8.8")

    assert result["ip_type"] == "Public"
    assert result["reputation"] == "Unknown"
    assert result["is_global"] is True


def test_loopback_ip():
    result = enrich_ip("127.0.0.1")

    assert result["ip_type"] == "Loopback"
    assert result["is_global"] is False


def test_invalid_ip():
    result = enrich_ip("not-an-ip")

    assert result["ip_type"] == "Invalid"
    assert result["reputation"] == "Unknown"
    assert result["is_global"] is False


def test_ipv6_public_address_without_api_key(monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)

    result = enrich_ip("2001:4860:4860::8888")

    assert result["source_ip"] == "2001:4860:4860::8888"
    assert result["ip_type"] == "Public"
    assert result["is_global"] is True


def test_virustotal_malicious_result(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")

    payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 5,
                    "suspicious": 2,
                    "harmless": 40,
                    "undetected": 10,
                }
            }
        }
    }

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return json.dumps(payload).encode("utf-8")

    def fake_urlopen(request, timeout):
        assert request.get_header("X-apikey") == "test-key"
        assert timeout == 5
        return FakeResponse()

    monkeypatch.setattr(ip_reputation, "urlopen", fake_urlopen)

    result = enrich_ip("8.8.8.8")

    assert result["reputation"] == "Malicious"
    assert result["malicious_detections"] == 5
    assert result["suspicious_detections"] == 2
    assert result["harmless_detections"] == 40


def test_virustotal_failure_returns_unknown(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")

    def fake_urlopen(request, timeout):
        raise TimeoutError("Request timed out")

    monkeypatch.setattr(ip_reputation, "urlopen", fake_urlopen)

    result = enrich_ip("8.8.8.8")

    assert result["reputation"] == "Unknown"
    assert "failed or timed out" in result["enrichment_note"]
