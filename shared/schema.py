import uuid
from datetime import datetime
from typing import Optional

ALERT_STREAM = "neuralops:alerts"
INCIDENT_STREAM = "neuralops:incidents"

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

def make_alert(
    rule_name: str,
    category: str,
    severity: str,
    ttp: str,
    kill_chain: str,
    source_ip: str,
    matched_value: str,
    raw_log: dict,
    confidence: float = 0.0,
    description: str = "",
    incident_id: str = "",
) -> dict:
    return {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "rule_name": rule_name,
        "category": category,
        "severity": severity.upper(),
        "ttp": ttp,
        "kill_chain": kill_chain,
        "source_ip": source_ip,
        "matched_value": str(matched_value)[:1000],
        "confidence": round(confidence, 4),
        "description": description,
        "incident_id": incident_id,
        "raw_log": raw_log,
    }

def make_incident(
    alerts: list[dict],
    source_ip: str,
    category: str,
    severity: str,
    ttp: str,
) -> dict:
    return {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "alert_count": len(alerts),
        "alert_ids": [a["id"] for a in alerts],
        "rule_names": list({a["rule_name"] for a in alerts}),
        "category": category,
        "severity": severity,
        "ttp": ttp,
        "source_ip": source_ip,
        "confidence": max(a["confidence"] for a in alerts),
        "description": f"{severity} incident: {', '.join(set(category for a in alerts))} from {source_ip}",
    }
