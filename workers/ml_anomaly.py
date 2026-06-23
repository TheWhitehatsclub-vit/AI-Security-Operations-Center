import asyncio
import time
import numpy as np
from collections import deque
from sklearn.ensemble import IsolationForest
from config.redis import get_redis
from config.settings import STREAMS, WINDOW_SIZE, TRAIN_INTERVAL, CONTAMINATION
from shared.schema import make_alert

feature_buffer = deque(maxlen=WINDOW_SIZE)
model = None
last_train = 0.0

def extract_features(log: dict) -> list:
    return [
        len(str(log.get("raw", ""))),
        len(str(log.get("url", ""))),
        len(str(log.get("body", ""))),
        int(str(log.get("status", "0"))),
        int(str(log.get("latency_ms", "0"))),
        int(str(log.get("length", "0"))),
        len(str(log.get("user_agent", ""))),
        int(str(log.get("method", "GET")) == "POST"),
        int(str(log.get("method", "GET")) == "PUT"),
        int(str(log.get("method", "GET")) == "DELETE"),
    ]

def train():
    global model, last_train
    if len(feature_buffer) < 100:
        return
    X = np.array(list(feature_buffer), dtype=np.float64)
    model = IsolationForest(contamination=CONTAMINATION, n_estimators=100, random_state=42, n_jobs=1)
    model.fit(X)
    last_train = time.time()

async def main():
    r = await get_redis()
    last_ids = {STREAMS["logs"]: "$", STREAMS["network"]: "$"}

    while True:
        try:
            result = await r.xread(last_ids, count=200, block=5000)
            for stream, entries in result:
                for eid, data in entries:
                    last_ids[stream] = eid
                    feats = extract_features(dict(data))
                    feature_buffer.append(feats)

                    if model:
                        X = np.array([feats], dtype=np.float64)
                        pred = model.predict(X)
                        if pred[0] == -1:
                            score = float(model.score_samples(X)[0])
                            sev = "HIGH" if score < -0.4 else "MEDIUM"
                            if score < -0.5:
                                sev = "CRITICAL"
                            alert = make_alert(
                                rule_name="MLAnomaly",
                                category="anomaly",
                                severity=sev,
                                ttp="T1078",
                                kill_chain="Actions on Objectives",
                                source_ip=str(data.get("source_ip", data.get("src_ip", "unknown"))),
                                matched_value=f"score={score:.3f}",
                                raw_log=dict(data),
                                confidence=min(1.0, abs(score)),
                            )
                            await r.xadd(STREAMS["alerts"], alert, maxlen=20000)

            if time.time() - last_train > TRAIN_INTERVAL:
                train()
        except Exception as e:
            await asyncio.sleep(2)

if __name__ == "__main__":
    asyncio.run(main())
