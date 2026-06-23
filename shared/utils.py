import uuid
from datetime import datetime

def make_alert_id() -> str:
    return str(uuid.uuid4())

def timestamp_now() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

def short_id(length: int = 8) -> str:
    return str(uuid.uuid4()).replace("-", "")[:length]
