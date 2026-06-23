import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from engine.parsers import normalize_log, decode_all, extract_b64

def test_decode_url():
    raw = "%27+OR+%271%27%3D%271"
    variants = decode_all(raw)
    assert any("' OR '1'='1" in v.replace('+', ' ') for v in variants), f"URL decode failed: {variants}"
    print("[PASS] test_decode_url")

def test_decode_double():
    raw = "%252e%252e%252f"
    variants = decode_all(raw)
    assert any("../" in v for v in variants), f"Double decode failed: {variants}"
    print("[PASS] test_decode_double")

def test_b64_extract():
    raw = "exec atob('Y21kIC1pIC9yIC90bXAvZmlsZS50eHQ=')"
    decoded = extract_b64(raw)
    assert any("cmd" in d and "tmp" in d for d in decoded), f"Base64 decode failed: {decoded}"
    print("[PASS] test_b64_extract")

def test_normalize_log():
    log = {"url": "/test?id=1' OR '1'='1", "body": "", "status": "200"}
    norm = normalize_log(log)
    assert norm["fields"]["url"] == log["url"]
    assert isinstance(norm["decoded_variants"], list)
    print("[PASS] test_normalize_log")

if __name__ == "__main__":
    test_decode_url()
    test_decode_double()
    test_b64_extract()
    test_normalize_log()
    print("All parser tests passed")
