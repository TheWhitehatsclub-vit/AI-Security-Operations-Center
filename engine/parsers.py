import re
import base64
import urllib.parse
import html

DECODING_PIPELINE = [
    ("html_entity", lambda x: html.unescape(x)),
    ("url_decode", lambda x: urllib.parse.unquote(x)),
    ("double_url", lambda x: urllib.parse.unquote(urllib.parse.unquote(x))),
]

B64_PATTERN = re.compile(r'([A-Za-z0-9+/]{20,}={0,2})')

def decode_all(raw: str) -> list[str]:
    results = []
    current = raw
    for name, decoder in DECODING_PIPELINE:
        try:
            decoded = decoder(current)
            if decoded != current:
                results.append(decoded)
                current = decoded
        except Exception:
            break
    return results

def extract_b64(raw: str) -> list[str]:
    out = []
    for m in B64_PATTERN.findall(raw):
        try:
            out.append(base64.b64decode(m).decode(errors="replace"))
        except Exception:
            continue
    return out

def flatten_log(log: dict) -> dict:
    flat = {}
    for k, v in log.items():
        if isinstance(v, str):
            flat[k] = v
        elif isinstance(v, dict):
            for sk, sv in v.items():
                flat[f"{k}.{sk}"] = str(sv) if sv is not None else ""
        else:
            flat[k] = str(v) if v is not None else ""
    return flat

def extract_all_text(log: dict) -> str:
    parts = []
    for v in log.values():
        if isinstance(v, str):
            parts.append(v)
        elif isinstance(v, dict):
            for sv in v.values():
                if isinstance(sv, str):
                    parts.append(sv)
    return " | ".join(parts)

def normalize_log(raw: dict) -> dict:
    flat = flatten_log(raw)
    all_text = extract_all_text(raw)
    decoded = decode_all(all_text)
    b64_decoded = extract_b64(all_text)

    return {
        "flat": flat,
        "all_text": all_text,
        "decoded_variants": decoded,
        "b64_decoded": b64_decoded,
        "fields": {
            "url": flat.get("url", flat.get("path", "")),
            "body": flat.get("body", ""),
            "query": flat.get("query", ""),
            "user_agent": flat.get("user_agent", ""),
            "referer": flat.get("referer", ""),
            "headers": flat.get("headers", ""),
            "raw": flat.get("raw", ""),
            "status": flat.get("status", ""),
            "method": flat.get("method", ""),
            "message": flat.get("message", ""),
            # Network-specific fields
            "alert_type": flat.get("alert_type", ""),
            "tool": flat.get("tool", ""),
            "scan_type": flat.get("scan_type", ""),
            "src_ip": flat.get("src_ip", flat.get("source_ip", "")),
            "dst_ip": flat.get("dst_ip", ""),
            "dst_port": flat.get("dst_port", ""),
            "state": flat.get("state", ""),
            "port_count": flat.get("port_count", ""),
            "syn_count": flat.get("syn_count", ""),
            "est_count": flat.get("est_count", ""),
            "ratio": flat.get("ratio", ""),
            "detail": flat.get("detail", ""),
            "ip": flat.get("ip", ""),
            "mac": flat.get("mac", ""),
            "previous_mac": flat.get("previous_mac", ""),
            "current_mac": flat.get("current_mac", ""),
        },
    }
