from app.mitre import add_mitre, mitre_for_rule


def test_brute_force_rule_maps_to_t1110():
    assert mitre_for_rule("Potential Brute Force Attack")["id"] == "T1110"


def test_failed_login_rule_maps_to_t1110_001():
    assert mitre_for_rule("Repeated Failed Logins")["id"] == "T1110.001"


def test_unknown_rule_returns_none():
    assert mitre_for_rule("Something Else") is None


def test_add_mitre_does_not_modify_original():
    original = {"rule": "Brute Force"}
    enriched = add_mitre(original)
    assert "mitre_id" not in original
    assert enriched["mitre_tactic"] == "Credential Access"