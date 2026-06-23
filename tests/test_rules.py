import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from engine.rules import get_rules, get_rules_by_type, get_rule_count

def test_rule_count():
    assert get_rule_count() >= 55, f"Expected >=55 rules, got {get_rule_count()}"
    print(f"[PASS] test_rule_count: {get_rule_count()} rules")

def test_rule_structure():
    for rule in get_rules():
        assert "id" in rule, f"Rule missing id: {rule.get('name')}"
        assert "name" in rule, f"Rule missing name: {rule.get('id')}"
        assert "category" in rule, f"{rule['id']} missing category"
        assert "ttps" in rule, f"{rule['id']} missing ttps"
        assert "kill_chain" in rule, f"{rule['id']} missing kill_chain"
        assert "base_score" in rule, f"{rule['id']} missing base_score"
        if rule.get("type", "regex") in ("regex", "geo_regex"):
            assert "patterns" in rule, f"{rule['id']} missing patterns"
            assert rule["patterns"], f"{rule['id']} has empty patterns"
        else:
            assert "config" in rule, f"{rule['id']} missing config"
    print("[PASS] test_rule_structure: all rules valid")

def test_ttp_format():
    for rule in get_rules():
        for ttp in rule["ttps"]:
            assert ttp.startswith("T"), f"{rule['id']} TTP {ttp} doesn't start with T"
    print("[PASS] test_ttp_format")

def test_categories():
    cats = set(r["category"] for r in get_rules())
    expected = {"web", "auth", "recon", "network", "malware", "exfiltration", "cloud", "ai", "behavioral", "geo"}
    assert cats == expected, f"Missing categories: {expected - cats}"
    print(f"[PASS] test_categories: {cats}")

if __name__ == "__main__":
    test_rule_count()
    test_rule_structure()
    test_ttp_format()
    test_categories()
    print("All rule tests passed")
