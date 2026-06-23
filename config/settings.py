import os

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

STREAMS = {
    "logs": "neuralops:logs",
    "network": "neuralops:network",
    "system": "neuralops:system",
    "alerts": "neuralops:alerts",
    "incidents": "neuralops:incidents",
    "feedback": "neuralops:fp_feedback",
    "state": "neuralops:state:",
    "synthetic": "neuralops:synthetic",
}

BATCH_SIZE = int(os.getenv("BATCH_SIZE", "100"))
BLOCK_MS = int(os.getenv("BLOCK_MS", "3000"))
WINDOW_SIZE = int(os.getenv("WINDOW_SIZE", "1000"))
TRAIN_INTERVAL = int(os.getenv("TRAIN_INTERVAL", "120"))
CONTAMINATION = float(os.getenv("CONTAMINATION", "0.03"))

ALERT_MAXLEN = int(os.getenv("ALERT_MAXLEN", "20000"))
INCIDENT_TTL = int(os.getenv("INCIDENT_TTL", "3600"))
DEDUP_WINDOW = int(os.getenv("DEDUP_WINDOW", "300"))
PERSIST_INTERVAL = int(os.getenv("PERSIST_INTERVAL", "60"))

OUTPUT_FILE = os.getenv("OUTPUT_FILE", "/tmp/neuralops_alerts.log")
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK", "")

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_KEY", "")
GREYNOISE_KEY = os.getenv("GREYNOISE_KEY", "")

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

GEOIP_DB_PATH = os.getenv("GEOIP_DB_PATH", "data/GeoLite2-City.mmdb")
GEOIP_ASN_PATH = os.getenv("GEOIP_ASN_PATH", "data/GeoLite2-ASN.mmdb")
RULE_REFRESH_INTERVAL = int(os.getenv("RULE_REFRESH_INTERVAL", "30"))

ALERT_STREAMS = ["neuralops:logs", "neuralops:network", "neuralops:system"]
