#!/usr/bin/env python3
"""
NeuralOps — Gemini Alert Analyzer Worker
Auto-consumes alerts from neuralops:alerts, sends to Gemini, pushes analysis to neuralops:gemini_analysis.

Usage:
  python3 gemini/worker.py              # Auto-consumer mode (watches Redis)
  python3 gemini/worker.py --api        # FastAPI server mode (UI triggers)
"""

import sys, os, json, asyncio, logging, time
from datetime import datetime, timezone
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
    import json
    raw_raw = alert.get("raw_log", {})
    raw = json.loads(raw_raw) if isinstance(raw_raw, str) else raw_raw
    geo_raw = alert.get("geo", {})
    geo = json.loads(geo_raw) if isinstance(geo_raw, str) else geo_raw
    source = alert.get("source", "web")

    decoded_query = unquote_plus(raw.get("query", "")) if raw and raw.get("query") else ""

    # Build context section based on source type
    if source == "network":
        context = f"""Source IP      : {raw.get("src_ip", raw.get("source_ip", ""))}
Destination IP : {raw.get("dst_ip", "")}
Destination Port : {raw.get("dst_port", "")}
State          : {raw.get("state", "")}
Alert Type     : {raw.get("alert_type", "")}
Tool           : {raw.get("tool", "")}
Scan Type      : {raw.get("scan_type", "")}
Port Count     : {raw.get("port_count", "")}
SYN Count      : {raw.get("syn_count", "")}
EST Count      : {raw.get("est_count", "")}
SYN/EST Ratio  : {raw.get("ratio", "")}
Detail         : {raw.get("detail", "")}
IP             : {raw.get("ip", "")}
MAC            : {raw.get("mac", "")}
Previous MAC   : {raw.get("previous_mac", "")}
Current MAC    : {raw.get("current_mac", "")}"""
    elif source == "system":
        context = f"""Message        : {raw.get("message", "")}
Unit           : {raw.get("unit", "")}
Hostname       : {raw.get("hostname", "")}
Source IP      : {raw.get("source_ip", raw.get("src_ip", ""))}"""
    else:
        context = f"""Source IP      : {raw.get("source_ip", "")}
Method         : {raw.get("method", "")}
Path           : {raw.get("path", "")}
Decoded Query  : {decoded_query}
User-Agent     : {raw.get("user_agent", "")}
Status         : {raw.get("status", "")}
Body           : {(raw.get("body") or "")[:300]}"""

    return f"""
You are an expert AI SOC analyst working inside NeuralOps.
Analyze the following {source} security alert and provide structured triage.

ALERT METADATA
Alert ID       : {alert.get("id","")}
Timestamp      : {alert.get("timestamp","")}
Rule           : {alert.get("rule_name","")}
Category       : {alert.get("category","")}
Severity       : {alert.get("severity","")}
    Confidence     : {float(alert.get("confidence",0)):.3f}
    Confidence Boost : {float(alert.get("confidence_boost",0)):.3f}
TTP            : {alert.get("ttp","")}
Kill Chain     : {alert.get("kill_chain","")}

DETECTION DETAILS
Matched Value  : {alert.get("matched_value","")}
Matched Pattern: {alert.get("matched_pattern","")}
Description    : {alert.get("description","")}

REQUEST CONTEXT
{context}

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
        "generationConfig": {"temperature": 0.2, "maxOutputTokens": 4096}
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
        clean = clean.split("\n", 1)[-1] if "\n" in clean else clean[3:]
        clean = clean.rsplit("```", 1)[0].strip()
        if clean.startswith("json"):
            clean = clean[4:].strip()
        elif clean.startswith("JSON"):
            clean = clean[4:].strip()
    clean = clean.strip()

    try:
        result = json.loads(clean)
    except json.JSONDecodeError:
        logger.error(f"Failed to parse Gemini response: {raw_text[:200]}")
        return None

    return {
        "alert_id": alert.get("id"),
        "analyzed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
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
    last_api_call = 0.0
    MIN_SECONDS_BETWEEN_CALLS = 120
    consecutive_429s = 0

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
                sev = alert.get("severity","LOW")
                print(f"\n  ► New alert: {alert.get('rule_name','?')} — {alert.get('confidence',0)} [{sev}]", flush=True)

                if sev == "LOW" and last_api_call > 0:
                    print(f"    Skipping LOW severity — saving quota for HIGH/CRITICAL", flush=True)
                    continue

                now = time.monotonic()
                wait = MIN_SECONDS_BETWEEN_CALLS - (now - last_api_call)
                if wait > 0:
                    print(f"    Rate limiting: waiting {wait:.1f}s before next API call", flush=True)
                    await asyncio.sleep(wait)

                last_api_call = time.monotonic()
                analysis = await call_gemini(alert)
                if analysis:
                    consecutive_429s = 0
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
                    consecutive_429s += 1
                    backoff = min(2 ** consecutive_429s * 30, 600)
                    logger.warning(f"Gemini call failed ({consecutive_429s}x) — backing off {backoff}s")
                    await asyncio.sleep(backoff)
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
