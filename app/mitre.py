"""Map detection rule names to MITRE ATT&CK techniques."""

# Checked in order; first keyword match wins.
_RULES = [
    ("brute", {
        "id": "T1110",
        "technique": "Brute Force",
        "tactic": "Credential Access",
    }),
    ("failed", {
        "id": "T1110.001",
        "technique": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
    }),
]


def mitre_for_rule(rule_name):
    """Return the technique dict for a rule name, or None if unmapped."""
    name = str(rule_name or "").casefold()
    for keyword, technique in _RULES:
        if keyword in name:
            return technique
    return None


def add_mitre(alert):
    """Return a copy of the alert with MITRE fields added."""
    technique = mitre_for_rule(alert.get("rule"))
    enriched = dict(alert)
    enriched["mitre_id"] = technique["id"] if technique else ""
    enriched["mitre_technique"] = technique["technique"] if technique else ""
    enriched["mitre_tactic"] = technique["tactic"] if technique else ""
    return enriched