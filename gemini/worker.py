#!/usr/bin/env python3
"""
NeuralOps — Gemini Alert Analyzer Worker
Auto-consumes alerts from neuralops:alerts, sends to Gemini, pushes analysis to neuralops:gemini_analysis.

Usage:
  python3 gemini/worker.py              # Auto-consumer mode (watches Redis)
  python3 gemini/worker.py --api        # FastAPI server mode (UI triggers)
"""

import sys, os, json, asyncio, logging
from datetime import datetime
from typing import Any
from urllib.parse import unquote_plus

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import httpx
import redis.asyncio as aioredis
from config.settings import REDIS_URL, STREAMS, GEMINI_API_KEY

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")
logger = logging.getLogger("neuralops.gemini")

GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
GEMINI_TIMEOUT = 30

ANALYSIS_STREAM = "neuralops:gemini_analysis"

def build_prompt(alert: dict) -> str:
    raw = alert.get("raw_log", {})
    geo = alert.get("geo", {})

    decoded_query = unquote_plus(raw.get("query", "")) if raw.get("query") else ""
    matched_value = alert.get("matched_value", "")
    matched_pattern = alert.get("matched_pattern", "")

    pattern_mismatch = (
        "onmouseover" in matched_value or
        "onerror" in matched_value or
        "onclick" in matched_value
    ) and "<script" in matched_pattern.lower()

    return f"""
You are an expert AI SOC analyst working inside NeuralOps.
Analyze the following web attack alert and provide structured triage.

ALERT METADATA
Alert ID       : {alert.get("id","")}
Timestamp      : {alert.get("timestamp","")}
Rule           : {alert.get("rule_name","")}
Category       : {alert.get("category","")}
Severity       : {alert.get("severity","")}
Confidence     : {alert.get("confidence",0):.3f}
TTP            : {alert.get("ttp","")}
Kill Chain     : {alert.get("kill_chain","")}

DETECTION DETAILS
Matched Value  : {matched_value}
Matched Pattern: {matched_pattern}
Description    : {alert.get("description","")}

REQUEST CONTEXT
Source IP      : {raw.get("source_ip","")}
Method         : {raw.get("method","")}
Path           : {raw.get("path","")}
Decoded Query  : {decoded_query}
User-Agent     : {raw.get("user_agent","")}

GEO CONTEXT
Country        : {geo.get("country","Unknown")}
City           : {geo.get("city","Unknown")}
Private IP     : {geo.get("is_private",False)}

ANALYSIS TASKS
1. Summarize what this alert represents in 1-2 sentences.
2. Explain what the attack payload does technically.
3. Reassess true severity considering the context.
4. Estimate false positive likelihood (0-100%).
5. List 3-5 specific recommended actions for the SOC analyst.

Respond ONLY with valid JSON, no markdown:
{{
  "summary": "string",
  "true_severity": "LOW | MEDIUM | HIGH | CRITICAL",
  "attack_explanation": "string",
  "false_positive_likelihood": 0-100,
  "recommended_actions": ["string", "string", "string"],
  "analyst_notes": "string"
}}
"""

async def call_gemini(alert: dict) -> dict | None:
    if not GEMINI_API_KEY:
        logger.warning("GEMINI_API_KEY not set")
        return None

    prompt = build_prompt(alert)
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent?key={GEMINI_API_KEY}"

    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.2, "maxOutputTokens": 1024}
    }

    try:
        async with httpx.AsyncClient(timeout=GEMINI_TIMEOUT) as client:
            resp = await client.post(url, json=payload)
            if resp.status_code != 200:
                logger.error(f"Gemini API error {resp.status_code}")
                return None
            data = resp.json()
            raw_text = data["candidates"][0]["content"]["parts"][0]["text"].strip()
    except Exception as e:
        logger.error(f"Gemini call failed: {e}")
        return None

    clean = raw_text.strip()
    if clean.startswith("```"):
        clean = clean.split("```")[1]
        if clean.startswith("json"):
            clean = clean[4:]
    clean = clean.strip().rstrip("```").strip()

    try:
        result = json.loads(clean)
    except json.JSONDecodeError:
        logger.error(f"Failed to parse Gemini response: {raw_text[:200]}")
        return None

    return {
        "alert_id": alert.get("id"),
        "analyzed_at": datetime.utcnow().isoformat() + "Z",
        "model_used": GEMINI_MODEL,
        "analysis": result,
        "raw_gemini": raw_text
    }

async def get_connection():
    return aioredis.from_url(REDIS_URL, decode_responses=True, socket_connect_timeout=3)

async def consumer_loop():
    print("=" * 60)
    print("  NEURALOPS — Gemini Analyzer (auto-consumer)")
    print(f"  Watching {STREAMS['alerts']} ...")
    print("  Press Ctrl+C to stop")
    print("=" * 60)

    last_id = "0"
    r = None

    try:
        r = await get_connection()

        while True:
            try:
                result = await r.xread({STREAMS["alerts"]: last_id}, count=1, block=2000)
            except (ConnectionError, OSError, aioredis.TimeoutError) as e:
                logger.warning(f"Redis reconnecting: {e}")
                await asyncio.sleep(1)
                if r:
                    try: await r.aclose()
                    except: pass
                r = await get_connection()
                continue

            if not result:
                continue

            _, entries = result[0]
            for eid, data in entries:
                last_id = eid

                try:
                    try:
                        await r.xdel(STREAMS["alerts"], eid)
                    except:
                        pass
                except:
                    pass

                alert = dict(data)
                print(f"\n  ► New alert: {alert.get('rule_name','?')} — {alert.get('confidence',0)} [{alert.get('severity','?')}]", flush=True)

                analysis = await call_gemini(alert)
                if analysis:
                    try:
                        flat = {k: json.dumps(v) if isinstance(v, (dict, list)) else str(v) for k, v in analysis.items()}
                        await r.xadd(ANALYSIS_STREAM, flat, maxlen=20000)
                    except Exception:
                        pass

                    result = analysis.get("analysis", {})
                    print(f"    Gemini: {result.get('summary','')[:120]}", flush=True)
                    print(f"    Severity: {result.get('true_severity','?')}  FP: {result.get('false_positive_likelihood',0)}%", flush=True)
                    print(f"    Actions: {', '.join(result.get('recommended_actions',[])[:2])}", flush=True)
                else:
                    print(f"    (Gemini skipped — no key or error)", flush=True)

    except asyncio.CancelledError:
        pass
    finally:
        if r:
            try: await r.aclose()
            except: pass
        print("\n  Gemini analyzer stopped.", flush=True)

def start_api():
    """Run FastAPI server for manual/UI-triggered analysis."""
    from fastapi import FastAPI, HTTPException
    from fastapi.middleware.cors import CORSMiddleware
    import uvicorn

    app = FastAPI(title="NeuralOps — Gemini Analyzer API")

    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

    @app.get("/health")
    async def health():
        return {"status": "ok", "model": GEMINI_MODEL, "api_key_set": bool(GEMINI_API_KEY)}

    @app.post("/analyze")
    async def analyze_alert(alert: dict):
        analysis = await call_gemini(alert)
        if not analysis:
            raise HTTPException(502, "Gemini analysis failed")
        return analysis

    print(f"  Gemini API server on http://0.0.0.0:8001")
    uvicorn.run(app, host="0.0.0.0", port=8001)

if __name__ == "__main__":
    if "--api" in sys.argv:
        start_api()
    else:
        asyncio.run(consumer_loop())
