"""
NeuralOps — SOC Dashboard Server
Real-time dashboard backend serving alerts + Gemini analysis via REST + SSE.
"""

import sys, os, json, asyncio, logging
from datetime import datetime
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import redis.asyncio as aioredis
from fastapi import FastAPI, Request, Query
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from config.settings import REDIS_URL, STREAMS
from engine.feedback import feedback_engine

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")
logger = logging.getLogger("neuralops.dashboard")

app = FastAPI(title="NeuralOps — SOC Dashboard")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── Optional API key auth ──
DASHBOARD_API_KEY = os.environ.get("DASHBOARD_API_KEY")
if DASHBOARD_API_KEY:
    logger.info("Dashboard API auth enabled (set DASHBOARD_API_KEY env var)")

@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    if DASHBOARD_API_KEY and request.url.path.startswith("/api/"):
        key = request.headers.get("X-API-Key") or request.query_params.get("api_key")
        if key != DASHBOARD_API_KEY:
            return JSONResponse({"error": "unauthorized"}, status_code=401)
    return await call_next(request)

ALERT_STREAM = STREAMS["alerts"]
ANALYSIS_STREAM = "neuralops:gemini_analysis"

async def get_redis():
    return aioredis.from_url(REDIS_URL, decode_responses=True)

# ── API ──────────────────────────────────────────────────────────────────────

@app.get("/api/stats")
async def stats():
    r = await get_redis()
    try:
        total = await r.xlen(ALERT_STREAM)
        analyzed = await r.xlen(ANALYSIS_STREAM)
        alerts = await r.xrevrange(ALERT_STREAM, count=100)
        severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        category_count = {}
        for _, data in alerts:
            sev = data.get("severity", "INFO").upper()
            cat = data.get("category", "unknown")
            if sev in severity_count:
                severity_count[sev] += 1
            category_count[cat] = category_count.get(cat, 0) + 1
        return {
            "total_alerts": total,
            "total_analyzed": analyzed,
            "by_severity": severity_count,
            "by_category": category_count
        }
    finally:
        await r.aclose()

@app.get("/api/alerts")
async def get_alerts(limit: int = Query(50, le=200), severity: Optional[str] = None, rule: Optional[str] = None):
    r = await get_redis()
    try:
        alerts = await r.xrevrange(ALERT_STREAM, count=limit)
        result = []
        for eid, data in alerts:
            alert = dict(data)
            alert["_id"] = eid
            for field in ("confidence", "confidence_boost"):
                try: alert[field] = float(alert.get(field, 0))
                except: alert[field] = 0.0
            for field in ("raw_log", "geo"):
                if isinstance(alert.get(field), str):
                    try: alert[field] = json.loads(alert[field])
                    except: pass
            if severity and alert.get("severity", "").upper() != severity.upper():
                continue
            if rule and rule.lower() not in alert.get("rule_name", "").lower():
                continue
            result.append(alert)
        return {"alerts": result, "total": len(result)}
    finally:
        await r.aclose()

@app.get("/api/analysis")
async def get_analysis(limit: int = Query(50, le=200)):
    r = await get_redis()
    try:
        items = await r.xrevrange(ANALYSIS_STREAM, count=limit)
        result = []
        for eid, data in items:
            item = dict(data)
            item["_id"] = eid
            for field in ("analysis",):
                try: item[field] = json.loads(item.get(field, "{}"))
                except: item[field] = {}
            result.append(item)
        return {"analysis": result, "total": len(result)}
    finally:
        await r.aclose()

@app.get("/api/alerts/{alert_id}")
async def get_alert(alert_id: str):
    r = await get_redis()
    try:
        alerts = await r.xrevrange(ALERT_STREAM, count=1000)
        for eid, data in alerts:
            if data.get("id") == alert_id:
                alert = dict(data)
                try: alert["confidence"] = float(alert.get("confidence", 0))
                except: pass
                for field in ("raw_log", "geo"):
                    if isinstance(alert.get(field), str):
                        try: alert[field] = json.loads(alert[field])
                        except: pass
                return alert
        return JSONResponse({"error": "not found"}, status_code=404)
    finally:
        await r.aclose()

@app.post("/api/alerts/{alert_id}/fp")
async def mark_false_positive(alert_id: str, request: Request):
    try:
        body = await request.json()
    except Exception:
        body = {}
    r = await get_redis()
    try:
        alerts = await r.xrevrange(ALERT_STREAM, count=1000)
        for eid, data in alerts:
            if data.get("id") == alert_id:
                alert = dict(data)
                for field in ("confidence", "confidence_boost"):
                    try: alert[field] = float(alert.get(field, 0))
                    except: pass
                await feedback_engine.mark_false_positive(alert, reason=body.get("reason", ""))
                return {"status": "ok", "message": "Marked as false positive"}
        return JSONResponse({"error": "not found"}, status_code=404)
    finally:
        await r.aclose()

# ── SSE Real-time Stream ─────────────────────────────────────────────────────

@app.get("/api/stream")
async def stream_events(request: Request):
    async def event_generator():
        r = await get_redis()
        last_id = "$"
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    result = await r.xread({ALERT_STREAM: last_id}, count=5, block=5000)
                except Exception:
                    await asyncio.sleep(1)
                    continue

                if result:
                    last_id = result[0][1][-1][0]
                    for _, entries in result:
                        for eid, data in entries:
                            alert = dict(data)
                            for field in ("confidence", "confidence_boost"):
                                try: alert[field] = float(alert.get(field, 0))
                                except: alert[field] = 0.0
                            for field in ("raw_log", "geo"):
                                if isinstance(alert.get(field), str):
                                    try: alert[field] = json.loads(alert[field])
                                    except: pass
                            yield f"data: {json.dumps({'type': 'alert', 'data': alert})}\n\n"
                yield f"data: {json.dumps({'type': 'ping'})}\n\n"
        finally:
            await r.aclose()

    return StreamingResponse(event_generator(), media_type="text/event-stream")

# ── Serve Frontend ───────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    return HTMLResponse(DASHBOARD_HTML)

# ── Embedded Frontend ────────────────────────────────────────────────────────

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NeuralOps — SOC Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
*,*::before,*::after{margin:0;padding:0;box-sizing:border-box}
html,body{height:100%;overflow:hidden}
body{
  color:#e8e8f0;
  font-family:'JetBrains Mono',monospace;
  -webkit-font-smoothing:antialiased;
  /* Rich vivid gradient background — the thing you see THROUGH the glass */
  background:
    radial-gradient(ellipse 900px 700px at 5% 10%,  rgba(249,115,22,0.55)  0%, transparent 60%),
    radial-gradient(ellipse 700px 600px at 95% 90%, rgba(175,82,222,0.45)  0%, transparent 55%),
    radial-gradient(ellipse 600px 500px at 60% 20%, rgba(249,115,22,0.25)  0%, transparent 50%),
    radial-gradient(ellipse 500px 400px at 20% 80%, rgba(90,200,250,0.2)   0%, transparent 50%),
    radial-gradient(ellipse 400px 300px at 80% 40%, rgba(255,59,48,0.15)   0%, transparent 45%),
    #06060c;
}
:root{
  --accent:#f97316;
  --accent-dim:rgba(249,115,22,0.1);
  --accent-border:rgba(249,115,22,0.25);
  --critical:#ff3b30;
  --high:#ff9500;
  --medium:#facc15;
  --low:#34c759;
  --info:#5ac8fa;
  /* Glass system — white-tinted, not dark-tinted */
  --glass-bg:rgba(255,255,255,0.06);
  --glass-bg-dark:rgba(0,0,0,0.25);
  --glass-bg-sidebar:rgba(10,8,18,0.55);
  --glass-bg-card:rgba(255,255,255,0.05);
  --glass-bg-card-hover:rgba(255,255,255,0.09);
  --glass-blur:blur(28px);
  --glass-blur-sm:blur(18px);
  --glass-blur-xs:blur(10px);
  /* Borders — top/left bright (light source), full edge subtle */
  --glass-border:rgba(255,255,255,0.13);
  --glass-border-strong:rgba(255,255,255,0.18);
  --glass-border-accent:rgba(249,115,22,0.3);
  /* Legacy compat */
  --surface:rgba(10,8,18,0.55);
  --surface2:rgba(255,255,255,0.04);
  --surface3:rgba(255,255,255,0.07);
  --border:rgba(255,255,255,0.1);
  --border2:rgba(255,255,255,0.14);
  --text-dim:#7a7a9a;
  --text-mid:#a8a8c0;
  --sidebar-w:220px;
  /* Glow shadows per severity */
  --glow-critical:0 0 20px rgba(255,59,48,0.25);
  --glow-high:0 0 20px rgba(255,149,0,0.2);
  --glow-accent:0 0 24px rgba(249,115,22,0.15);
}
::-webkit-scrollbar{width:3px;height:3px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:rgba(249,115,22,0.2);border-radius:2px}
::-webkit-scrollbar-thumb:hover{background:rgba(249,115,22,0.4)}

/* ── Layout ── */
.shell{display:flex;height:100vh;background:transparent}
.sidebar{
  width:var(--sidebar-w);flex-shrink:0;
  background:var(--glass-bg-sidebar);
  backdrop-filter:var(--glass-blur);-webkit-backdrop-filter:var(--glass-blur);
  border-right:1px solid var(--glass-border);
  box-shadow:inset -1px 0 0 rgba(255,255,255,0.04), 4px 0 32px rgba(0,0,0,0.3);
  display:flex;flex-direction:column;transition:width 0.2s
}
.sidebar.collapsed{width:0;overflow:hidden}
.main{flex:1;display:flex;flex-direction:column;min-width:0;overflow:hidden}

/* ── Sidebar ── */
.sb-brand{padding:16px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
.sb-logo-mark{width:28px;height:28px;border:1px solid var(--accent);display:flex;align-items:center;justify-content:center;position:relative;flex-shrink:0}
.sb-logo-mark::before{content:'';position:absolute;inset:2px;border:1px solid rgba(249,115,22,0.3)}
.sb-logo-mark svg{width:12px;height:12px;color:var(--accent)}
.sb-name-wrap{margin-left:10px}
.sb-name{font-size:12px;font-weight:700;color:#fff;letter-spacing:0.15em;line-height:1}
.sb-tagline{font-size:9px;color:var(--text-dim);letter-spacing:0.08em;margin-top:2px}
.sb-collapse-btn{background:none;border:none;cursor:pointer;color:var(--text-dim);padding:2px;display:flex;align-items:center;justify-content:center;transition:color 0.15s}
.sb-collapse-btn:hover{color:var(--accent)}

.sb-section-label{padding:14px 18px 6px;font-size:9px;color:var(--text-dim);letter-spacing:0.12em;text-transform:uppercase}
.sb-nav-item{display:flex;align-items:center;gap:10px;padding:8px 18px;cursor:pointer;color:var(--text-mid);font-size:11px;letter-spacing:0.05em;transition:all 0.15s;border-left:2px solid transparent;position:relative}
.sb-nav-item:hover{color:#fff;background:rgba(255,255,255,0.05)}
.sb-nav-item.active{color:var(--accent);border-left-color:var(--accent);background:rgba(249,115,22,0.08);box-shadow:inset 0 1px 0 rgba(249,115,22,0.1)}
.sb-nav-item svg{width:14px;height:14px;flex-shrink:0}
.sb-nav-badge{margin-left:auto;font-size:9px;padding:1px 5px;border-radius:2px;font-weight:700}
.sb-nav-badge.red{background:rgba(255,59,48,0.15);color:#ff3b30;border:1px solid rgba(255,59,48,0.2)}
.sb-nav-badge.orange{background:rgba(249,115,22,0.12);color:var(--accent);border:1px solid var(--accent-border)}

.sb-system-block{margin:auto 12px 12px;padding:12px;background:rgba(255,255,255,0.05);backdrop-filter:var(--glass-blur-xs);-webkit-backdrop-filter:var(--glass-blur-xs);border:1px solid rgba(255,255,255,0.1);box-shadow:inset 0 1px 0 rgba(255,255,255,0.08);position:relative;overflow:hidden}
.sb-system-block::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,rgba(249,115,22,0.7),transparent)}
.sb-sys-title{display:flex;align-items:center;gap:6px;font-size:9px;color:#fff;letter-spacing:0.1em;margin-bottom:8px}
.sys-dot{width:5px;height:5px;border-radius:50%;background:var(--low);animation:syspulse 2s infinite}
@keyframes syspulse{0%,100%{opacity:1;box-shadow:0 0 0 0 rgba(52,199,89,0.4)}50%{opacity:0.7;box-shadow:0 0 0 4px rgba(52,199,89,0)}}
.sb-sys-row{display:flex;justify-content:space-between;font-size:9px;padding:2px 0}
.sb-sys-label{color:var(--text-dim)}
.sb-sys-val{color:var(--text-mid)}
.sb-sys-val.live{color:var(--low)}
.sb-sys-val.orange{color:var(--accent)}

/* ── Topbar ── */
.topbar{
  height:44px;
  background:rgba(255,255,255,0.05);
  backdrop-filter:var(--glass-blur);-webkit-backdrop-filter:var(--glass-blur);
  border-bottom:1px solid var(--glass-border);
  box-shadow:0 1px 0 rgba(255,255,255,0.06), 0 4px 24px rgba(0,0,0,0.2);
  display:flex;align-items:center;padding:0 20px;gap:16px;flex-shrink:0
}
.tb-toggle{background:none;border:none;cursor:pointer;color:var(--text-dim);padding:4px;display:flex;align-items:center;transition:color 0.15s}
.tb-toggle:hover{color:var(--accent)}
.tb-breadcrumb{font-size:11px;color:var(--text-dim);letter-spacing:0.05em}
.tb-breadcrumb span{color:var(--accent)}
.tb-spacer{flex:1}
.tb-status{display:flex;align-items:center;gap:6px;font-size:10px;color:rgba(255,255,255,0.5);letter-spacing:0.08em;padding:3px 10px;border:1px solid rgba(255,255,255,0.12);background:rgba(255,255,255,0.06);backdrop-filter:var(--glass-blur-xs);-webkit-backdrop-filter:var(--glass-blur-xs);box-shadow:inset 0 1px 0 rgba(255,255,255,0.08)}
.tb-status-dot{width:5px;height:5px;border-radius:50%}
.tb-clock{font-size:10px;color:var(--text-dim);letter-spacing:0.06em;min-width:80px;text-align:right}
.tb-scan-line{position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--accent),transparent);opacity:0;animation:scanline 4s ease-in-out infinite}
@keyframes scanline{0%,100%{opacity:0;transform:translateX(-100%)}50%{opacity:0.6;transform:translateX(100%)}}

/* ── Content ── */
.content{flex:1;overflow:hidden;display:flex;flex-direction:column}
.view{display:none;flex:1;overflow:hidden}
.view.active{display:flex;flex-direction:column}

/* ── Command view ── */
.cmd-grid{padding:16px;display:grid;grid-template-columns:repeat(3,1fr);grid-template-rows:auto auto;gap:12px;overflow-y:auto;flex:1}

/* ── Cards ── */
.card{
  background:var(--glass-bg-card);
  backdrop-filter:var(--glass-blur);-webkit-backdrop-filter:var(--glass-blur);
  border:1px solid var(--glass-border);
  /* Top highlight = light source hitting the glass edge */
  box-shadow:
    inset 0 1px 0 rgba(255,255,255,0.12),
    inset 1px 0 0 rgba(255,255,255,0.06),
    0 8px 32px rgba(0,0,0,0.4),
    0 2px 8px rgba(0,0,0,0.2);
  position:relative;overflow:hidden;
  transition:box-shadow 0.25s, border-color 0.25s, transform 0.2s
}
.card:hover{
  background:var(--glass-bg-card-hover);
  border-color:var(--glass-border-strong);
  box-shadow:
    inset 0 1px 0 rgba(255,255,255,0.18),
    inset 1px 0 0 rgba(255,255,255,0.09),
    0 12px 40px rgba(0,0,0,0.5),
    0 4px 12px rgba(0,0,0,0.25),
    var(--glow-accent);
  transform:translateY(-1px)
}
.card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,rgba(249,115,22,0.35),transparent);pointer-events:none}
/* Subtle glass texture — noise-like grain */
.card::after{content:'';position:absolute;inset:0;background:url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.03'/%3E%3C/svg%3E");opacity:0.4;pointer-events:none;mix-blend-mode:overlay}
.card-header{padding:12px 16px;border-bottom:1px solid rgba(255,255,255,0.07);display:flex;align-items:center;justify-content:space-between;background:rgba(255,255,255,0.02)}
.card-title{font-size:10px;font-weight:700;color:rgba(255,255,255,0.6);letter-spacing:0.12em;text-transform:uppercase}
.card-corner{position:absolute;top:0;right:0;width:0;height:0;border-style:solid;border-width:0 20px 20px 0;border-color:transparent rgba(249,115,22,0.2) transparent transparent}
.card-body{padding:14px 16px}

/* ── KPI stat ── */
.stat-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:1px;background:var(--border)}
.stat-cell{padding:14px 16px;background:var(--surface2)}
.stat-num{font-size:28px;font-weight:700;line-height:1;margin-bottom:3px}
.stat-label{font-size:9px;color:var(--text-dim);letter-spacing:0.1em;text-transform:uppercase}
.stat-num.critical{color:var(--critical);text-shadow:0 0 20px rgba(255,59,48,0.3)}
.stat-num.high{color:var(--high);text-shadow:0 0 20px rgba(255,149,0,0.3)}
.stat-num.low{color:var(--low);text-shadow:0 0 20px rgba(52,199,89,0.3)}
.stat-num.accent{color:var(--accent);text-shadow:0 0 20px rgba(249,115,22,0.3)}

/* ── Activity log ── */
.activity-list{padding:8px;display:flex;flex-direction:column;gap:2px;max-height:240px;overflow-y:auto}
.activity-item{padding:7px 10px;border-left:2px solid var(--accent);background:var(--surface);cursor:pointer;transition:background 0.1s;font-size:10px}
.activity-item:hover{background:rgba(249,115,22,0.05)}
.activity-ts{color:var(--text-dim);font-size:9px;margin-bottom:1px}
.activity-rule{color:var(--text-mid)}
.activity-ip{color:var(--text-dim);margin-left:6px}

/* ── Category list ── */
.cat-list{padding:8px 16px;display:flex;flex-direction:column;gap:6px}
.cat-row{display:flex;align-items:center;gap:8px;padding:6px 8px;background:var(--surface);border:1px solid var(--border)}
.cat-dot{width:6px;height:6px;flex-shrink:0}
.cat-name{flex:1;font-size:10px;color:var(--text-mid);letter-spacing:0.06em}
.cat-count{font-size:11px;font-weight:700;color:#fff}
.cat-bar-wrap{width:60px;height:3px;background:rgba(255,255,255,0.06)}
.cat-bar-fill{height:100%}

/* ── Alert feed view ── */
.alerts-layout{flex:1;display:flex;overflow:hidden}
.alerts-left{display:flex;flex-direction:column;flex:1;min-width:0;overflow:hidden}
.filter-bar{padding:10px 16px;border-bottom:1px solid rgba(255,255,255,0.08);display:flex;align-items:center;gap:6px;flex-wrap:wrap;flex-shrink:0;background:rgba(255,255,255,0.04);backdrop-filter:var(--glass-blur-sm);-webkit-backdrop-filter:var(--glass-blur-sm)}
.filter-chip{padding:3px 10px;border:1px solid rgba(255,255,255,0.1);background:rgba(255,255,255,0.05);color:rgba(255,255,255,0.45);font-size:9px;font-family:'JetBrains Mono',monospace;cursor:pointer;letter-spacing:0.08em;text-transform:uppercase;transition:all 0.15s;backdrop-filter:var(--glass-blur-xs);-webkit-backdrop-filter:var(--glass-blur-xs)}
.filter-chip:hover{border-color:rgba(249,115,22,0.35);color:var(--accent);background:rgba(249,115,22,0.08);box-shadow:inset 0 1px 0 rgba(255,255,255,0.08)}
.filter-chip.active{border-color:rgba(249,115,22,0.45);background:rgba(249,115,22,0.12);color:var(--accent);box-shadow:inset 0 1px 0 rgba(249,115,22,0.15), 0 0 12px rgba(249,115,22,0.12)}
.filter-sep{width:1px;height:14px;background:var(--border2);margin:0 2px}
.filter-count{margin-left:auto;font-size:9px;color:var(--text-dim);letter-spacing:0.06em}

.alert-list-wrap{flex:1;overflow-y:auto;padding:10px;background:rgba(0,0,0,0.1)}
.alert-feed{display:flex;flex-direction:column;gap:4px}

/* ── Alert card ── */
.alert-card{
  padding:10px 12px;
  background:rgba(255,255,255,0.04);
  backdrop-filter:var(--glass-blur-sm);-webkit-backdrop-filter:var(--glass-blur-sm);
  border:1px solid rgba(255,255,255,0.09);
  border-left:2px solid transparent;
  cursor:pointer;transition:all 0.18s;position:relative;overflow:hidden
}
.alert-card::before{content:'';position:absolute;inset:0;background:linear-gradient(135deg,rgba(255,255,255,0.04) 0%,transparent 60%);pointer-events:none}
.alert-card:hover{
  background:rgba(255,255,255,0.08);
  border-color:rgba(255,255,255,0.15);
  box-shadow:inset 0 1px 0 rgba(255,255,255,0.1), 0 4px 16px rgba(0,0,0,0.3);
  transform:translateX(2px)
}
.alert-card.selected{
  background:rgba(249,115,22,0.08);
  border-color:rgba(249,115,22,0.25);
  border-left-color:var(--accent);
  box-shadow:inset 0 1px 0 rgba(249,115,22,0.12), 0 0 20px rgba(249,115,22,0.1), var(--glow-accent)
}
.alert-card.sev-CRITICAL{border-left-color:var(--critical)}
.alert-card.sev-CRITICAL:hover{box-shadow:inset 0 1px 0 rgba(255,255,255,0.1), var(--glow-critical)}
.alert-card.sev-HIGH{border-left-color:var(--high)}
.alert-card.sev-HIGH:hover{box-shadow:inset 0 1px 0 rgba(255,255,255,0.1), var(--glow-high)}
.alert-card.sev-MEDIUM{border-left-color:var(--medium)}
.alert-card.sev-LOW{border-left-color:var(--low)}
.alert-card.sev-INFO{border-left-color:var(--info)}
.alert-card.selected{border-left-color:var(--accent)!important}
.alert-card.sev-CRITICAL{border-left-color:var(--critical)}
.alert-card.sev-HIGH{border-left-color:var(--high)}
.alert-card.sev-MEDIUM{border-left-color:var(--medium)}
.alert-card.sev-LOW{border-left-color:var(--low)}
.alert-card.sev-INFO{border-left-color:var(--info)}
.alert-card.selected{border-left-color:var(--accent)!important}
.ac-top{display:flex;align-items:center;gap:6px;margin-bottom:5px}
.ac-rule{font-size:12px;font-weight:700;color:#fff;flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ac-badges{display:flex;gap:3px;flex-shrink:0}
.badge{padding:1px 5px;border:1px solid;font-size:9px;font-weight:700;letter-spacing:0.05em;text-transform:uppercase}
.badge-web{background:rgba(90,200,250,0.08);color:#5ac8fa;border-color:rgba(90,200,250,0.15)}
.badge-network{background:rgba(175,82,222,0.08);color:#af52de;border-color:rgba(175,82,222,0.15)}
.badge-system{background:rgba(255,159,10,0.08);color:#ff9f0a;border-color:rgba(255,159,10,0.15)}
.sev-chip{padding:1px 6px;font-size:9px;font-weight:700;border:1px solid;letter-spacing:0.04em}
.sev-CRITICAL{background:rgba(255,59,48,0.1);color:var(--critical);border-color:rgba(255,59,48,0.2)}
.sev-HIGH{background:rgba(255,149,0,0.1);color:var(--high);border-color:rgba(255,149,0,0.2)}
.sev-MEDIUM{background:rgba(250,204,21,0.08);color:var(--medium);border-color:rgba(250,204,21,0.15)}
.sev-LOW{background:rgba(52,199,89,0.08);color:var(--low);border-color:rgba(52,199,89,0.15)}
.sev-INFO{background:rgba(90,200,250,0.08);color:var(--info);border-color:rgba(90,200,250,0.15)}
.ac-meta{display:flex;align-items:center;gap:10px;font-size:10px;color:var(--text-dim)}
.ac-meta-ip{color:var(--text-mid);font-weight:500}
.ac-conf-bar{height:2px;background:rgba(255,255,255,0.05);margin-top:6px;overflow:hidden}
.ac-conf-fill{height:100%;transition:width 0.3s}

/* ── Detail panel ── */
.detail-panel{
  width:360px;flex-shrink:0;
  border-left:1px solid rgba(255,255,255,0.09);
  background:rgba(255,255,255,0.04);
  backdrop-filter:var(--glass-blur);-webkit-backdrop-filter:var(--glass-blur);
  box-shadow:inset 1px 0 0 rgba(255,255,255,0.05);
  display:flex;flex-direction:column;overflow:hidden
}
.dp-header{padding:12px 16px;border-bottom:1px solid rgba(255,255,255,0.08);background:rgba(255,255,255,0.03);flex-shrink:0}
.dp-title{font-size:10px;font-weight:700;color:rgba(255,255,255,0.55);letter-spacing:0.12em;text-transform:uppercase;margin-bottom:4px}
.dp-subtitle{font-size:11px;color:var(--text-dim)}
.dp-body{flex:1;overflow-y:auto;padding:12px}
.dp-section{margin-bottom:14px}
.dp-section-title{font-size:9px;color:var(--text-dim);letter-spacing:0.12em;text-transform:uppercase;margin-bottom:6px;padding-bottom:4px;border-bottom:1px solid var(--border)}
.dp-field{display:flex;justify-content:space-between;align-items:flex-start;padding:4px 0;border-bottom:1px solid rgba(255,255,255,0.04)}
.dp-field:last-child{border-bottom:none}
.dp-field-label{font-size:10px;color:var(--text-dim);flex-shrink:0}
.dp-field-val{font-size:10px;color:#e5e5e5;text-align:right;word-break:break-all;max-width:58%;font-family:'JetBrains Mono',monospace}
.dp-field-val.critical{color:var(--critical)}
.dp-field-val.high{color:var(--high)}
.dp-field-val.medium{color:var(--medium)}
.dp-field-val.low{color:var(--low)}

/* ── Intel feed items ── */
.gemini-item{border:1px solid rgba(249,115,22,0.15);padding:10px;margin-bottom:6px;background:rgba(255,255,255,0.02)}
.gemini-item-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:5px}
.gemini-tag-small{font-size:9px;font-weight:700;letter-spacing:0.1em}
.gemini-item-summary{font-size:10px;color:#d4d4d4;line-height:1.4;margin-bottom:5px}
.gemini-item-meta{display:flex;align-items:center;gap:4px;font-size:9px}
.fp-label{color:var(--text-dim);font-size:9px;margin-right:2px}
.fp-meter-sm{width:40px;height:2px;background:rgba(255,255,255,0.06)}
.fp-meter-fill-sm{height:100%}

/* ── Gemini block ── */
.gemini-block{
  background:rgba(255,255,255,0.04);
  backdrop-filter:var(--glass-blur-sm);-webkit-backdrop-filter:var(--glass-blur-sm);
  border:1px solid rgba(249,115,22,0.22);
  padding:12px;position:relative;
  box-shadow:inset 0 1px 0 rgba(249,115,22,0.1), 0 0 30px rgba(249,115,22,0.06)
}
.gemini-block::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,rgba(249,115,22,0.7),transparent)}
.gemini-tag{display:inline-flex;align-items:center;gap:4px;font-size:8px;color:var(--accent);background:var(--accent-dim);border:1px solid var(--accent-border);padding:2px 7px;letter-spacing:0.1em;margin-bottom:8px}
.gemini-summary{font-size:11px;line-height:1.5;color:#d4d4d4;margin-bottom:8px}
.gemini-explain{font-size:10px;color:var(--text-mid);line-height:1.5;margin-bottom:10px}
.gemini-meta-row{display:flex;align-items:center;gap:12px;font-size:10px;margin-bottom:8px}
.gemini-sev-label{color:var(--text-dim)}
.fp-meter{flex:1;height:3px;background:rgba(255,255,255,0.06)}
.fp-meter-fill{height:100%;transition:width 0.4s}
.fp-val{font-size:9px;min-width:28px;text-align:right}
.gemini-actions{margin-top:8px}
.gemini-actions-title{font-size:9px;color:var(--text-dim);letter-spacing:0.1em;text-transform:uppercase;margin-bottom:5px}
.gemini-action-item{padding:5px 8px;background:#0f0f0f;border:1px solid rgba(255,255,255,0.05);font-size:10px;color:var(--text-mid);margin-bottom:3px;display:flex;gap:6px}
.gemini-action-item::before{content:'→';color:var(--accent);flex-shrink:0}

/* ── FP button ── */
.fp-btn{width:100%;margin-top:10px;padding:6px;font-size:9px;font-family:'JetBrains Mono',monospace;border:1px solid rgba(255,59,48,0.25);background:rgba(255,59,48,0.05);color:#ff3b30;cursor:pointer;letter-spacing:0.1em;text-transform:uppercase;transition:all 0.15s}
.fp-btn:hover{background:rgba(255,59,48,0.12);border-color:rgba(255,59,48,0.4)}

/* ── Kill chain ── */
.kc-strip{display:flex;gap:2px;align-items:center;margin:8px 0}
.kc-node{padding:2px 6px;font-size:8px;font-weight:700;letter-spacing:0.06em;text-transform:uppercase;border:1px solid var(--border);color:var(--text-dim);position:relative}
.kc-node.active{border-color:var(--accent);color:var(--accent);background:var(--accent-dim)}
.kc-node.past{border-color:rgba(249,115,22,0.2);color:rgba(249,115,22,0.5)}
.kc-arrow{font-size:8px;color:var(--text-dim)}

/* ── Intel & Systems views ── */
.view-pad{padding:16px;overflow-y:auto;flex:1}
.intel-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.sys-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}
.sys-stat{background:var(--surface2);border:1px solid var(--border);padding:16px;text-align:center}
.sys-num{font-size:26px;font-weight:700;color:#fff;font-family:'JetBrains Mono',monospace}
.sys-lbl{font-size:9px;color:var(--text-dim);letter-spacing:0.1em;margin-top:3px}
.empty-state{display:flex;flex-direction:column;align-items:center;justify-content:center;padding:48px 24px;color:var(--text-dim);font-size:11px;gap:8px;text-align:center}
.empty-state-icon{font-size:28px;opacity:0.25;margin-bottom:4px}

@media(max-width:900px){
  :root{--sidebar-w:0px}
  .detail-panel{width:100%;border-left:none;border-top:1px solid var(--border)}
  .alerts-layout{flex-direction:column}
}
</style>
</head>
<body>
<div class="shell">

<!-- ══════════ SIDEBAR ══════════ -->
<div class="sidebar" id="sidebar">
  <div class="sb-brand">
    <div style="display:flex;align-items:center;gap:10px">
      <div class="sb-logo-mark">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="12 2 22 8.5 22 15.5 12 22 2 15.5 2 8.5"/><circle cx="12" cy="12" r="3"/></svg>
      </div>
      <div class="sb-name-wrap">
        <div class="sb-name">NEURALOPS</div>
        <div class="sb-tagline">v1.0.0 · CLASSIFIED</div>
      </div>
    </div>
    <button class="sb-collapse-btn" onclick="toggleSidebar()">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m15 18-6-6 6-6"/></svg>
    </button>
  </div>

  <div class="sb-section-label">Operations</div>
  <div class="sb-nav-item active" onclick="switchView('command');setNav(this)">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
    <span>Command center</span>
  </div>
  <div class="sb-nav-item" onclick="switchView('alerts');setNav(this)">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
    <span>Alert feed</span>
    <span class="sb-nav-badge red" id="sideTotal">0</span>
  </div>
  <div class="sb-nav-item" onclick="switchView('intel');setNav(this)">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/></svg>
    <span>Intelligence</span>
  </div>
  <div class="sb-nav-item" onclick="switchView('systems');setNav(this)">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M12 1v4M12 19v4M4.22 4.22l2.83 2.83M16.95 16.95l2.83 2.83M1 12h4M19 12h4M4.22 19.78l2.83-2.83M16.95 7.05l2.83-2.83"/></svg>
    <span>Systems</span>
  </div>

  <div class="sb-section-label">Analysis</div>
  <div class="sb-nav-item" onclick="switchView('intel');setNav(this)">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
    <span>AI triage</span>
    <span class="sb-nav-badge orange" id="cmdAnalyzed">0</span>
  </div>

  <div class="sb-system-block">
    <div class="sb-sys-title"><div class="sys-dot"></div>SYSTEM ONLINE</div>
    <div class="sb-sys-row"><span class="sb-sys-label">STREAM</span><span class="sb-sys-val live" id="sideStream">LIVE</span></div>
    <div class="sb-sys-row"><span class="sb-sys-label">ALERTS</span><span class="sb-sys-val orange" id="sideTotalB">0</span></div>
    <div class="sb-sys-row"><span class="sb-sys-label">UPTIME</span><span class="sb-sys-val" id="uptime">--</span></div>
    <div class="sb-sys-row"><span class="sb-sys-label">COLLECTORS</span><span class="sb-sys-val">4 ACTIVE</span></div>
  </div>
</div>

<!-- ══════════ MAIN ══════════ -->
<div class="main">

  <!-- Topbar -->
  <div class="topbar" style="position:relative;overflow:hidden">
    <div class="tb-scan-line"></div>
    <button class="tb-toggle" onclick="toggleSidebar()">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>
    </button>
    <div class="tb-breadcrumb">NEURALOPS&nbsp;/&nbsp;<span id="breadcrumb">COMMAND CENTER</span></div>
    <div class="tb-spacer"></div>
    <div class="tb-status">
      <div class="tb-status-dot" id="topStatusDot" style="background:#34c759;box-shadow:0 0 4px rgba(52,199,89,0.6);animation:syspulse 2s infinite"></div>
      <span id="topStatusText" style="font-size:9px;letter-spacing:0.1em">LIVE</span>
    </div>
    <div class="tb-clock" id="topClock"></div>
  </div>

  <!-- Content -->
  <div class="content">

    <!-- ── COMMAND CENTER ── -->
    <div class="view active" id="viewCommand">
      <div class="cmd-grid">

        <!-- Row 1, Col 1: KPI stats + mini donut -->
        <div class="card">
          <div class="card-corner"></div>
          <div class="card-header">
            <span class="card-title">Alert overview</span>
            <span style="font-size:9px;color:var(--text-dim);letter-spacing:0.06em" id="cmdLastUpdate">--</span>
          </div>
          <div style="display:flex;align-items:center;padding:12px 16px;gap:16px">
            <div style="position:relative;width:90px;height:90px;flex-shrink:0">
              <canvas id="donutChart" width="90" height="90"></canvas>
              <div style="position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;pointer-events:none">
                <div class="stat-num critical" id="cmdTotal" style="font-size:18px">0</div>
                <div style="font-size:8px;color:var(--text-dim);letter-spacing:0.08em">TOTAL</div>
              </div>
            </div>
            <div style="flex:1;display:flex;flex-direction:column;gap:5px">
              <div style="display:flex;justify-content:space-between;align-items:center">
                <div style="display:flex;align-items:center;gap:5px"><div style="width:6px;height:6px;background:var(--critical)"></div><span style="font-size:9px;color:var(--text-dim)">CRITICAL</span></div>
                <span class="stat-num critical" id="cmdCrit" style="font-size:14px">0</span>
              </div>
              <div style="display:flex;justify-content:space-between;align-items:center">
                <div style="display:flex;align-items:center;gap:5px"><div style="width:6px;height:6px;background:var(--high)"></div><span style="font-size:9px;color:var(--text-dim)">HIGH</span></div>
                <span class="stat-num high" id="cmdHigh" style="font-size:14px">0</span>
              </div>
              <div style="display:flex;justify-content:space-between;align-items:center">
                <div style="display:flex;align-items:center;gap:5px"><div style="width:6px;height:6px;background:var(--medium)"></div><span style="font-size:9px;color:var(--text-dim)">MEDIUM</span></div>
                <span style="font-size:14px;font-weight:700;color:var(--medium)" id="cmdMed">0</span>
              </div>
              <div style="display:flex;justify-content:space-between;align-items:center">
                <div style="display:flex;align-items:center;gap:5px"><div style="width:6px;height:6px;background:var(--low)"></div><span style="font-size:9px;color:var(--text-dim)">LOW</span></div>
                <span style="font-size:14px;font-weight:700;color:var(--low)" id="cmdLow">0</span>
              </div>
            </div>
          </div>
          <div style="padding:8px 16px;border-top:1px solid var(--border);display:grid;grid-template-columns:1fr 1fr 1fr;gap:1px;background:var(--border)">
            <div style="text-align:center;padding:8px;background:var(--surface2)">
              <div style="color:var(--accent);font-size:15px;font-weight:700">72</div>
              <div style="color:var(--text-dim);font-size:8px;letter-spacing:0.08em;margin-top:1px">RULES</div>
            </div>
            <div style="text-align:center;padding:8px;background:var(--surface2)">
              <div style="color:#fff;font-size:15px;font-weight:700">4</div>
              <div style="color:var(--text-dim);font-size:8px;letter-spacing:0.08em;margin-top:1px">COLLECTORS</div>
            </div>
            <div style="text-align:center;padding:8px;background:var(--surface2)">
              <div style="color:var(--low);font-size:15px;font-weight:700" id="cmdAnalyzedB">0</div>
              <div style="color:var(--text-dim);font-size:8px;letter-spacing:0.08em;margin-top:1px">AI TRIAGED</div>
            </div>
          </div>
        </div>

        <!-- Row 1, Col 2: Hourly volume bar chart -->
        <div class="card">
          <div class="card-corner"></div>
          <div class="card-header">
            <span class="card-title">Alert volume · 24h</span>
            <span style="font-size:9px;color:var(--low);letter-spacing:0.06em">LIVE</span>
          </div>
          <div style="padding:12px 16px 10px">
            <canvas id="volumeChart" height="120"></canvas>
          </div>
          <div style="padding:0 16px 12px;display:flex;gap:12px">
            <div style="font-size:9px;color:var(--text-dim)">Peak: <span style="color:#fff" id="volPeak">--</span></div>
            <div style="font-size:9px;color:var(--text-dim)">Avg/hr: <span style="color:var(--accent)" id="volAvg">--</span></div>
          </div>
        </div>

        <!-- Row 1, Col 3: Category breakdown -->
        <div class="card">
          <div class="card-corner"></div>
          <div class="card-header"><span class="card-title">Category breakdown</span></div>
          <div style="padding:12px 16px 8px">
            <canvas id="categoryChart" height="130"></canvas>
          </div>
          <div class="cat-list" id="categoryList" style="display:none"></div>
        </div>

        <!-- Row 2, Col 1-2: Live threat timeline -->
        <div class="card" style="grid-column:span 2">
          <div class="card-corner"></div>
          <div class="card-header">
            <span class="card-title">Live threat timeline</span>
            <div style="display:flex;gap:10px;font-size:9px;color:var(--text-dim)">
              <span><span style="color:var(--critical)">■</span> Critical</span>
              <span><span style="color:var(--high)">■</span> High</span>
              <span><span style="color:var(--medium)">■</span> Medium</span>
              <span><span style="color:var(--low)">■</span> Low</span>
            </div>
          </div>
          <div style="padding:10px 16px 12px">
            <canvas id="timelineChart" height="80"></canvas>
          </div>
        </div>

        <!-- Row 2, Col 3: Recent activity -->
        <div class="card">
          <div class="card-corner"></div>
          <div class="card-header"><span class="card-title">Recent activity</span></div>
          <div class="activity-list" id="activityLog">
            <div class="empty-state"><div class="empty-state-icon">📡</div>Awaiting events...</div>
          </div>
        </div>

      </div>
    </div>

    <!-- ── ALERT FEED ── -->
    <div class="view" id="viewAlerts">
      <div class="alerts-layout">
        <div class="alerts-left">
          <div class="filter-bar" id="filterBar">
            <button class="filter-chip active" data-filter="all">All</button>
            <button class="filter-chip" data-filter="CRITICAL">Critical</button>
            <button class="filter-chip" data-filter="HIGH">High</button>
            <button class="filter-chip" data-filter="MEDIUM">Medium</button>
            <button class="filter-chip" data-filter="LOW">Low</button>
            <div class="filter-sep"></div>
            <button class="filter-chip" data-source="web">Web</button>
            <button class="filter-chip" data-source="network">Network</button>
            <button class="filter-chip" data-source="system">System</button>
            <span class="filter-count" id="alertCount">0 alerts</span>
          </div>
          <div class="alert-list-wrap">
            <div class="alert-feed" id="alertList">
              <div class="empty-state"><div class="empty-state-icon">📡</div>Waiting for incoming threats...</div>
            </div>
          </div>
        </div>

        <div class="detail-panel" id="detailPanel">
          <div class="dp-header">
            <div class="dp-title">Threat analysis</div>
            <div class="dp-subtitle" id="dp-subtitle-text">Select an alert from the feed</div>
          </div>
          <div class="dp-body" id="detailContent">
            <div class="empty-state" style="padding-top:48px">
              <div class="empty-state-icon">⚡</div>
              <div>Click any alert to analyze</div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- ── INTELLIGENCE ── -->
    <div class="view" id="viewIntel">
      <div class="view-pad">
        <div class="intel-grid">
          <div class="card">
            <div class="card-corner"></div>
            <div class="card-header"><span class="card-title">Gemini AI intelligence</span></div>
            <div class="card-body" id="intelContent">
              <div class="empty-state"><div class="empty-state-icon">🧠</div>Set GEMINI_API_KEY to enable AI analysis</div>
            </div>
          </div>
          <div class="card">
            <div class="card-corner"></div>
            <div class="card-header"><span class="card-title">Threat patterns</span></div>
            <div class="card-body">
              <div class="empty-state"><div class="empty-state-icon">🔍</div>Patterns appear as alerts accumulate</div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- ── SYSTEMS ── -->
    <div class="view" id="viewSystems">
      <div class="view-pad">
        <div class="sys-grid" style="margin-bottom:12px">
          <div class="sys-stat"><div class="sys-num" style="color:var(--accent)">72</div><div class="sys-lbl">Detection rules</div></div>
          <div class="sys-stat"><div class="sys-num">4</div><div class="sys-lbl">Collectors online</div></div>
          <div class="sys-stat"><div class="sys-num">3</div><div class="sys-lbl">Input streams</div></div>
        </div>
        <div class="card">
          <div class="card-corner"></div>
          <div class="card-header"><span class="card-title">System status</span></div>
          <div class="card-body">
            <div style="display:flex;flex-direction:column;gap:6px">
              <div class="dp-field"><span class="dp-field-label">Detection engine</span><span class="dp-field-val low">ONLINE</span></div>
              <div class="dp-field"><span class="dp-field-label">Redis stream</span><span class="dp-field-val low">CONNECTED</span></div>
              <div class="dp-field"><span class="dp-field-label">Gemini API</span><span class="dp-field-val" style="color:var(--text-mid)">CHECK KEY</span></div>
              <div class="dp-field"><span class="dp-field-label">SSE stream</span><span class="dp-field-val low" id="sysSSEStatus">LIVE</span></div>
            </div>
          </div>
        </div>
      </div>
    </div>

  </div>
</div>
</div>

<script>
const SEVERITY_CLASS={CRITICAL:'sev-CRITICAL',HIGH:'sev-HIGH',MEDIUM:'sev-MEDIUM',LOW:'sev-LOW',INFO:'sev-INFO'};
const KC_STAGES=['Recon','Weapon','Delivery','Exploit','Install','C2','Exfil'];
let alerts=[];
let currentFilter='all';
let currentSource=null;
let selectedAlertId=null;
let analysisCache={};
const startTime=Date.now();

function toggleSidebar(){
  document.getElementById('sidebar').classList.toggle('collapsed');
}

function setNav(el){
  document.querySelectorAll('.sb-nav-item').forEach(n=>n.classList.remove('active'));
  el.classList.add('active');
}

function switchView(v){
  document.querySelectorAll('.view').forEach(el=>el.classList.remove('active'));
  const target=document.getElementById('view'+v.charAt(0).toUpperCase()+v.slice(1));
  if(target)target.classList.add('active');
  const labels={command:'COMMAND CENTER',alerts:'ALERT FEED',intel:'INTELLIGENCE',systems:'SYSTEMS'};
  document.getElementById('breadcrumb').textContent=labels[v]||'COMMAND CENTER';
  if(v==='intel')renderIntel();
}

function clock(){
  const now=new Date();
  document.getElementById('topClock').textContent=now.toISOString().slice(0,19).replace('T',' ')+' UTC';
  const up=Math.floor((Date.now()-startTime)/1000);
  const h=String(Math.floor(up/3600)).padStart(2,'0');
  const m=String(Math.floor((up%3600)/60)).padStart(2,'0');
  const s=String(up%60).padStart(2,'0');
  const el=document.getElementById('uptime');
  if(el)el.textContent=h+':'+m+':'+s;
}
setInterval(clock,1000);clock();

async function fetchStats(){
  try{
    const r=await fetch('/api/stats');
    const s=await r.json();
    document.getElementById('cmdTotal').textContent=s.total_alerts;
    document.getElementById('cmdHigh').textContent=(s.by_severity.HIGH||0);
    document.getElementById('cmdMed').textContent=s.by_severity.MEDIUM||0;
    document.getElementById('cmdAnalyzed').textContent=s.total_analyzed;
    document.getElementById('cmdAnalyzedB').textContent=s.total_analyzed;
    document.getElementById('sideTotal').textContent=s.total_alerts;
    document.getElementById('sideTotalB').textContent=s.total_alerts;
    document.getElementById('alertCount').textContent=alerts.length+' alerts';
    updateCharts(s);
  }catch(e){}
}

async function fetchAlerts(){
  try{
    const r=await fetch('/api/alerts?limit=100');
    const d=await r.json();
    alerts=d.alerts;
    renderAlerts();
    renderActivity();
    document.getElementById('alertCount').textContent=alerts.length+' alerts';
    seedTimeline();
  }catch(e){}
}

async function fetchAnalysis(){
  try{
    const r=await fetch('/api/analysis?limit=50');
    const d=await r.json();
    for(const item of d.analysis){
      if(item.alert_id)analysisCache[item.alert_id]=item;
    }
    if(selectedAlertId&&analysisCache[selectedAlertId])renderDetail(selectedAlertId);
  }catch(e){}
  renderIntel();
}

function renderIntel(){
  const container=document.getElementById('intelContent');
  if(!container)return;
  const ids=Object.keys(analysisCache);
  if(!ids.length){
    container.innerHTML='<div class="empty-state"><div class="empty-state-icon">🧠</div>Set GEMINI_API_KEY to enable AI analysis</div>';
    return;
  }
  const items=ids.map(id=>analysisCache[id]).sort((a,b)=>b.analyzed_at>a.analyzed_at?-1:1);
  let html='';
  for(const item of items.slice(0,20)){
    const an=item.analysis||{};
    const fp=an.false_positive_likelihood;
    const fpColor=fp>70?'var(--critical)':fp>30?'var(--high)':'var(--low)';
    const sev=an.true_severity||'--';
    const sevColor=sev==='CRITICAL'?'var(--critical)':sev==='HIGH'?'var(--high)':sev==='MEDIUM'?'var(--medium)':'var(--low)';
    html+='<div class="gemini-item">'+
      '<div class="gemini-item-header"><span class="gemini-tag-small" style="color:'+sevColor+'">'+sev+'</span>'+
      '<span style="font-size:9px;color:var(--text-dim)">'+item.analyzed_at.slice(0,19).replace('T',' ')+'</span></div>'+
      (an.summary?'<div class="gemini-item-summary">'+an.summary+'</div>':'')+
      '<div class="gemini-item-meta">'+
        '<span class="fp-label">FP:</span><div class="fp-meter-sm"><div class="fp-meter-fill-sm" style="width:'+(fp||0)+'%;background:'+fpColor+'"></div></div>'+
        '<span style="font-size:9px;color:'+fpColor+';margin-left:4px">'+(fp!==undefined?fp+'%':'--')+'</span>'+
      '</div>'+
    '</div>';
  }
  container.innerHTML=html;
}

function renderActivity(){
  const container=document.getElementById('activityLog');
  const recent=alerts.slice(0,8);
  if(!recent.length){
    container.innerHTML='<div class="empty-state"><div class="empty-state-icon">📡</div>No recent activity</div>';
    return;
  }
  container.innerHTML=recent.map(a=>{
    const ts=a.timestamp?new Date(a.timestamp).toLocaleTimeString():'--';
    const sev=(a.severity||'INFO').toUpperCase();
    const sc=sev==='CRITICAL'?'var(--critical)':sev==='HIGH'?'var(--high)':'var(--text-mid)';
    return '<div class="activity-item" data-id="'+a.id+'">'+
      '<div class="activity-ts">'+ts+'</div>'+
      '<div><span style="color:'+sc+';">'+( a.rule_name||'Unknown')+'</span>'+
      '<span class="activity-ip">'+( a.source_ip||'--')+'</span></div></div>';
  }).join('');
}

function renderCategories(){
  const container=document.getElementById('categoryList');
  try{
    fetch('/api/stats').then(r=>r.json()).then(s=>{
      const cats=s.by_category||{};
      const entries=Object.entries(cats).sort((a,b)=>b[1]-a[1]);
      if(!entries.length){container.innerHTML='<div class="empty-state"><div class="empty-state-icon">⚡</div>No data</div>';return;}
      const max=entries[0][1];
      const colors={web:'#5ac8fa',network:'#af52de',malware:'#ff3b30',system:'#ff9f0a'};
      container.innerHTML=entries.map(([k,v])=>{
        const c=colors[k]||'var(--accent)';
        return '<div class="cat-row">'+
          '<div class="cat-dot" style="background:'+c+'"></div>'+
          '<div class="cat-name">'+k.toUpperCase()+'</div>'+
          '<div class="cat-bar-wrap"><div class="cat-bar-fill" style="width:'+Math.round((v/max)*100)+'%;background:'+c+'"></div></div>'+
          '<div class="cat-count">'+v+'</div></div>';
      }).join('');
    });
  }catch(e){}
}

function renderAlerts(){
  const container=document.getElementById('alertList');
  let filtered=currentFilter==='all'?alerts:alerts.filter(a=>(a.severity||'INFO').toUpperCase()===currentFilter);
  if(currentSource)filtered=filtered.filter(a=>a.source===currentSource);
  if(filtered.length===0){
    container.innerHTML='<div class="empty-state"><div class="empty-state-icon">📡</div>'+(currentFilter!=='all'?'No alerts match this filter':'Waiting for incoming threats...')+'</div>';
    return;
  }
  container.innerHTML=filtered.map(a=>{
    const sev=(a.severity||'INFO').toUpperCase();
    const isActive=a.id===selectedAlertId;
    const ts=a.timestamp?new Date(a.timestamp).toLocaleTimeString():'--';
    const conf=typeof a.confidence==='number'?Math.round(a.confidence*100):0;
    const src=a.source||'web';
    const srcLabel=src==='network'?'NET':src==='system'?'SYS':'WEB';
    const confColor=conf>70?'var(--critical)':conf>40?'var(--high)':'var(--low)';
    return '<div class="alert-card sev-'+sev+(isActive?' selected':'')+'" data-id="'+a.id+'">'+
      '<div class="ac-top">'+
        '<div class="ac-rule">'+(a.rule_name||'Unknown')+'</div>'+
        '<div class="ac-badges">'+
          '<span class="badge badge-'+src+'">'+srcLabel+'</span>'+
          '<span class="sev-chip sev-'+sev+'">'+sev+'</span>'+
        '</div>'+
      '</div>'+
      '<div class="ac-meta">'+
        '<span class="ac-meta-ip">'+(a.source_ip||'--')+'</span>'+
        '<span>'+(a.ttp||'--')+'</span>'+
        '<span>'+(a.kill_chain||'--')+'</span>'+
        '<span>'+conf+'% conf</span>'+
        '<span style="margin-left:auto">'+ts+'</span>'+
      '</div>'+
      '<div class="ac-conf-bar"><div class="ac-conf-fill" style="width:'+conf+'%;background:'+confColor+'"></div></div>'+
    '</div>';
  }).join('');
}

function selectAlert(id){
  selectedAlertId=id;
  switchView('alerts');
  document.querySelectorAll('.sb-nav-item').forEach((n,i)=>{if(i===1){n.classList.add('active')}else{n.classList.remove('active')}});
  renderAlerts();
  renderDetail(id);
}

async function markFP(id){
  try{
    const r=await fetch('/api/alerts/'+id+'/fp',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({reason:'analyst feedback'})});
    if(r.ok){
      document.getElementById('detailContent').innerHTML='<div class="empty-state" style="padding-top:48px"><div style="font-size:22px;margin-bottom:8px;color:var(--low)">✓</div><div>Marked as false positive</div><div style="font-size:10px;color:var(--text-dim);margin-top:4px">This alert will be suppressed</div></div>';
      alerts=alerts.filter(x=>x.id!==id);
      renderAlerts();
    }
  }catch(e){}
}

function renderDetail(id){
  const a=alerts.find(x=>x.id===id);
  const container=document.getElementById('detailContent');
  if(!a)return;
  const analysis=analysisCache[id];
  const geo=a.geo&&typeof a.geo==='object'?a.geo:{};
  const raw=a.raw_log&&typeof a.raw_log==='object'?a.raw_log:{};
  const ts=a.timestamp?new Date(a.timestamp).toISOString().replace('T',' ').slice(0,19):'--';
  const src=a.source||'web';
  const sev=(a.severity||'INFO').toUpperCase();
  const sevColor=sev==='CRITICAL'?'var(--critical)':sev==='HIGH'?'var(--high)':sev==='MEDIUM'?'var(--medium)':sev==='LOW'?'var(--low)':'var(--info)';

  const dp=document.getElementById('dp-subtitle-text');
  if(dp)dp.textContent=(a.rule_name||'Alert')+' · '+(a.source_ip||'--');

  const kcIdx=KC_STAGES.findIndex(s=>( a.kill_chain||'').toLowerCase().includes(s.toLowerCase()));
  const kcHtml=KC_STAGES.map((s,i)=>{
    const cls=i===kcIdx?'active':i<kcIdx?'past':'';
    return '<span class="kc-node '+cls+'">'+s+'</span>'+(i<KC_STAGES.length-1?'<span class="kc-arrow">›</span>':'');
  }).join('');

  const fields=[
    ['Source',a.source||'--'],['Rule',a.rule_name||'--'],
    ['Severity',sev],['Confidence',typeof a.confidence==='number'?(a.confidence*100).toFixed(1)+'%':'--'],
    ['TTP',a.ttp||'--'],['Category',a.category||'--'],['Timestamp',ts],
    ['Source IP',a.source_ip||'--'],['Matched',(a.matched_value||'').slice(0,50)]
  ];
  const fieldsHtml=fields.map(([l,v])=>{
    const vc=l==='Severity'?' style="color:'+sevColor+'"':'';
    return '<div class="dp-field"><span class="dp-field-label">'+l+'</span><span class="dp-field-val"'+vc+'>'+v+'</span></div>';
  }).join('');

  let ctxHtml='';
  if(src==='web'&&raw.method){
    ctxHtml='<div class="dp-section"><div class="dp-section-title">Request context</div>'+
      [['Method',raw.method],['Path',raw.path],['Status',raw.status],['UA',(raw.user_agent||'').slice(0,36)]].map(([l,v])=>'<div class="dp-field"><span class="dp-field-label">'+l+'</span><span class="dp-field-val">'+(v||'--')+'</span></div>').join('')+
    '</div>';
  }else if(src==='network'&&(raw.tool||a.tool)){
    ctxHtml='<div class="dp-section"><div class="dp-section-title">Network context</div>'+
      [['Tool',raw.tool||a.tool],['Scan',raw.scan_type],['Dst IP',raw.dst_ip],['Port',raw.dst_port],['State',raw.state]].map(([l,v])=>'<div class="dp-field"><span class="dp-field-label">'+l+'</span><span class="dp-field-val">'+(v||'--')+'</span></div>').join('')+
    '</div>';
  }else if(src==='system'){
    ctxHtml='<div class="dp-section"><div class="dp-section-title">System context</div>'+
      [['Message',(raw.message||a.matched_value||'').slice(0,60)],['Unit',raw.unit||raw._SYSTEMD_UNIT],['Host',raw.hostname||raw._HOSTNAME]].map(([l,v])=>'<div class="dp-field"><span class="dp-field-label">'+l+'</span><span class="dp-field-val">'+(v||'--')+'</span></div>').join('')+
    '</div>';
  }

  let geoHtml='';
  if(geo.country||geo.city){
    geoHtml='<div class="dp-section"><div class="dp-section-title">Geo / network</div>'+
      [['Country',geo.country],['City',geo.city],['ASN',geo.asn]].map(([l,v])=>'<div class="dp-field"><span class="dp-field-label">'+l+'</span><span class="dp-field-val">'+(v||'--')+'</span></div>').join('')+
    '</div>';
  }

  let aiHtml='';
  if(analysis&&analysis.analysis){
    const an=analysis.analysis;
    const fp=an.false_positive_likelihood;
    const fpColor=fp>70?'var(--critical)':fp>30?'var(--high)':'var(--low)';
    const trueSevColor=an.true_severity==='CRITICAL'?'var(--critical)':an.true_severity==='HIGH'?'var(--high)':an.true_severity==='MEDIUM'?'var(--medium)':'var(--low)';
    aiHtml='<div class="dp-section"><div class="dp-section-title">AI analysis</div>'+
      '<div class="gemini-block">'+
        '<div class="gemini-tag">✦ GEMINI AI</div>'+
        (an.summary?'<div class="gemini-summary">'+an.summary+'</div>':'')+
        (an.attack_explanation?'<div class="gemini-explain">'+an.attack_explanation+'</div>':'')+
        '<div class="gemini-meta-row">'+
          '<span class="gemini-sev-label">True severity:</span>'+
          '<span style="font-size:10px;font-weight:700;color:'+trueSevColor+'">'+( an.true_severity||'--')+'</span>'+
          '<span class="gemini-sev-label" style="margin-left:8px">FP:</span>'+
          '<div class="fp-meter"><div class="fp-meter-fill" style="width:'+(fp||0)+'%;background:'+fpColor+'"></div></div>'+
          '<span class="fp-val" style="color:'+fpColor+'">'+(fp!==undefined?fp+'%':'--')+'</span>'+
        '</div>'+
        (an.recommended_actions&&an.recommended_actions.length?
          '<div class="gemini-actions">'+
            '<div class="gemini-actions-title">Recommended actions</div>'+
            an.recommended_actions.map(act=>'<div class="gemini-action-item">'+act+'</div>').join('')+
          '</div>':'')+
      '</div></div>';
  }else{
    aiHtml='<div class="dp-section"><div class="dp-section-title">AI analysis</div>'+
      '<div style="padding:12px;background:#0a0a0a;border:1px solid rgba(249,115,22,0.1);font-size:10px;color:var(--text-dim);text-align:center">'+
        '⏳ Waiting for Gemini analysis...'+
      '</div></div>';
  }

  container.innerHTML=
    '<div class="dp-section"><div class="dp-section-title">Kill chain</div><div class="kc-strip">'+kcHtml+'</div></div>'+
    '<div class="dp-section"><div class="dp-section-title">Alert details</div>'+fieldsHtml+'</div>'+
    ctxHtml+geoHtml+aiHtml+
    '<button class="fp-btn" data-id="'+a.id+'">✕ Mark false positive</button>';
}

// Filter bar
document.getElementById('filterBar').addEventListener('click',e=>{
  const btn=e.target.closest('[data-filter]')||e.target.closest('[data-source]');
  if(!btn)return;
  if(btn.dataset.source!==undefined){
    currentSource=currentSource===btn.dataset.source?null:btn.dataset.source;
    document.querySelectorAll('#filterBar [data-source]').forEach(b=>{b.classList.remove('active')});
    if(currentSource)btn.classList.add('active');
  }else{
    currentSource=null;
    document.querySelectorAll('#filterBar [data-source]').forEach(b=>{b.classList.remove('active')});
    document.querySelectorAll('#filterBar [data-filter]').forEach(b=>{b.classList.remove('active')});
    btn.classList.add('active');
    currentFilter=btn.dataset.filter;
  }
  renderAlerts();
});

// SSE
let source=null;
function connectSSE(){
  source=new EventSource('/api/stream');
  source.onmessage=e=>{
    try{
      const msg=JSON.parse(e.data);
      if(msg.type==='alert'){
        const existing=alerts.findIndex(a=>a.id===msg.data.id);
        if(existing===-1){
          alerts.unshift(msg.data);
          if(alerts.length>200)alerts.pop();
          fetchStats();renderAlerts();renderActivity();
          document.getElementById('alertCount').textContent=alerts.length+' alerts';
          // Live timeline push
          const sevCounts={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};
          sevCounts[(msg.data.severity||'LOW').toUpperCase()]=(sevCounts[(msg.data.severity||'LOW').toUpperCase()]||0)+1;
          pushTimelineTick(sevCounts);
        }
      }
    }catch(e){}
  };
  source.onerror=()=>{
    document.getElementById('topStatusDot').style.background='var(--high)';
    document.getElementById('topStatusDot').style.boxShadow='0 0 4px rgba(255,149,0,0.6)';
    document.getElementById('topStatusText').textContent='RECONNECT';
    document.getElementById('sideStream').textContent='DOWN';
    const sysEl=document.getElementById('sysSSEStatus');
    if(sysEl)sysEl.textContent='RECONNECTING';
    source.close();
    setTimeout(connectSSE,3000);
  };
  source.onopen=()=>{
    document.getElementById('topStatusDot').style.background='var(--low)';
    document.getElementById('topStatusDot').style.boxShadow='0 0 4px rgba(52,199,89,0.6)';
    document.getElementById('topStatusText').textContent='LIVE';
    document.getElementById('sideStream').textContent='LIVE';
    const sysEl=document.getElementById('sysSSEStatus');
    if(sysEl)sysEl.textContent='LIVE';
  };
}

// Event delegation
document.getElementById('alertList').addEventListener('click',e=>{
  const card=e.target.closest('[data-id]');
  if(card)selectAlert(card.dataset.id);
});
document.getElementById('activityLog').addEventListener('click',e=>{
  const card=e.target.closest('[data-id]');
  if(card){switchView('alerts');selectAlert(card.dataset.id);}
});
document.getElementById('detailContent').addEventListener('click',e=>{
  const btn=e.target.closest('.fp-btn');
  if(btn)markFP(btn.dataset.id);
});

// ── CHARTS ──────────────────────────────────────────────────────────────────
Chart.defaults.font.family = "'JetBrains Mono', monospace";
Chart.defaults.color = '#6b6b6b';

// Donut chart
const donutCtx = document.getElementById('donutChart').getContext('2d');
const donutChart = new Chart(donutCtx, {
  type: 'doughnut',
  data: {
    labels: ['Critical','High','Medium','Low'],
    datasets: [{
      data: [0,0,0,0],
      backgroundColor: ['rgba(255,59,48,0.85)','rgba(255,149,0,0.85)','rgba(250,204,21,0.7)','rgba(52,199,89,0.7)'],
      borderColor: ['rgba(255,59,48,0.2)','rgba(255,149,0,0.2)','rgba(250,204,21,0.2)','rgba(52,199,89,0.2)'],
      borderWidth: 1,
      hoverOffset: 4
    }]
  },
  options: {
    responsive: false,
    cutout: '70%',
    plugins: { legend: { display: false }, tooltip: { enabled: true, callbacks: { label: (c) => ` ${c.label}: ${c.raw}` } } },
    animation: { duration: 600, easing: 'easeInOutQuart' }
  }
});

// Volume bar chart — simulated 24h data (will update with real data when available)
const volumeLabels = [];
const now = new Date();
for(let i=23;i>=0;i--){
  const h = new Date(now - i*3600000);
  volumeLabels.push(h.getUTCHours().toString().padStart(2,'0')+'h');
}
const volumeCtx = document.getElementById('volumeChart').getContext('2d');
const volumeChart = new Chart(volumeCtx, {
  type: 'bar',
  data: {
    labels: volumeLabels,
    datasets: [{
      label: 'Alerts',
      data: Array(24).fill(0),
      backgroundColor: (ctx) => {
        const v = ctx.raw;
        if(v > 20) return 'rgba(255,59,48,0.7)';
        if(v > 10) return 'rgba(255,149,0,0.7)';
        return 'rgba(249,115,22,0.45)';
      },
      borderColor: 'rgba(249,115,22,0.2)',
      borderWidth: 1,
      borderRadius: 1,
      borderSkipped: false
    }]
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false }, tooltip: { callbacks: { label: (c) => ` ${c.raw} alerts` } } },
    scales: {
      x: { grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { font: { size: 8 }, maxTicksLimit: 8 } },
      y: { grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { font: { size: 8 }, precision: 0 }, beginAtZero: true }
    },
    animation: { duration: 400 }
  }
});

// Category horizontal bar chart
const catCtx = document.getElementById('categoryChart').getContext('2d');
const categoryBarChart = new Chart(catCtx, {
  type: 'bar',
  data: {
    labels: ['WEB','NETWORK','SYSTEM','MALWARE','OTHER'],
    datasets: [{
      label: 'Count',
      data: [0,0,0,0,0],
      backgroundColor: ['rgba(90,200,250,0.6)','rgba(175,82,222,0.6)','rgba(255,159,10,0.6)','rgba(255,59,48,0.6)','rgba(249,115,22,0.4)'],
      borderColor: ['rgba(90,200,250,0.3)','rgba(175,82,222,0.3)','rgba(255,159,10,0.3)','rgba(255,59,48,0.3)','rgba(249,115,22,0.2)'],
      borderWidth: 1,
      borderRadius: 2
    }]
  },
  options: {
    indexAxis: 'y',
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false }, tooltip: { callbacks: { label: (c) => ` ${c.raw} alerts` } } },
    scales: {
      x: { grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { font: { size: 8 }, precision: 0 }, beginAtZero: true },
      y: { grid: { display: false }, ticks: { font: { size: 9 } } }
    },
    animation: { duration: 500 }
  }
});

// Timeline stacked line chart — rolling 30-point window
const timelineLabels = Array(30).fill('');
const tlData = { CRITICAL: Array(30).fill(0), HIGH: Array(30).fill(0), MEDIUM: Array(30).fill(0), LOW: Array(30).fill(0) };
const tlCtx = document.getElementById('timelineChart').getContext('2d');
const timelineChart = new Chart(tlCtx, {
  type: 'line',
  data: {
    labels: timelineLabels,
    datasets: [
      { label:'Critical', data:[...tlData.CRITICAL], borderColor:'rgba(255,59,48,0.9)', backgroundColor:'rgba(255,59,48,0.08)', fill:true, tension:0.4, pointRadius:0, borderWidth:1.5 },
      { label:'High',     data:[...tlData.HIGH],     borderColor:'rgba(255,149,0,0.8)',  backgroundColor:'rgba(255,149,0,0.06)',  fill:true, tension:0.4, pointRadius:0, borderWidth:1.5 },
      { label:'Medium',   data:[...tlData.MEDIUM],   borderColor:'rgba(250,204,21,0.7)', backgroundColor:'rgba(250,204,21,0.04)', fill:true, tension:0.4, pointRadius:0, borderWidth:1 },
      { label:'Low',      data:[...tlData.LOW],      borderColor:'rgba(52,199,89,0.6)',  backgroundColor:'rgba(52,199,89,0.03)',  fill:true, tension:0.4, pointRadius:0, borderWidth:1 }
    ]
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false }, tooltip: { mode: 'index', intersect: false } },
    scales: {
      x: { display: false },
      y: { grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { font: { size: 8 }, precision: 0 }, beginAtZero: true }
    },
    animation: { duration: 300 },
    interaction: { mode: 'nearest', axis: 'x', intersect: false }
  }
});

// Push a new timeline tick from live SSE alerts
function pushTimelineTick(sevCounts){
  Object.keys(tlData).forEach(sev => {
    tlData[sev].push(sevCounts[sev]||0);
    if(tlData[sev].length>30) tlData[sev].shift();
  });
  timelineChart.data.datasets[0].data = [...tlData.CRITICAL];
  timelineChart.data.datasets[1].data = [...tlData.HIGH];
  timelineChart.data.datasets[2].data = [...tlData.MEDIUM];
  timelineChart.data.datasets[3].data = [...tlData.LOW];
  timelineChart.update('none');
}

// Seed timeline with existing alert data
function seedTimeline(){
  const buckets = {};
  alerts.slice().reverse().forEach(a => {
    const t = a.timestamp ? new Date(a.timestamp).toISOString().slice(0,16) : 'unknown';
    if(!buckets[t]) buckets[t] = {CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};
    const s = (a.severity||'LOW').toUpperCase();
    if(buckets[t][s] !== undefined) buckets[t][s]++;
  });
  const sorted = Object.keys(buckets).sort().slice(-30);
  ['CRITICAL','HIGH','MEDIUM','LOW'].forEach(sev => {
    tlData[sev] = Array(30-sorted.length).fill(0).concat(sorted.map(t => buckets[t][sev]||0));
  });
  timelineChart.data.datasets[0].data = [...tlData.CRITICAL];
  timelineChart.data.datasets[1].data = [...tlData.HIGH];
  timelineChart.data.datasets[2].data = [...tlData.MEDIUM];
  timelineChart.data.datasets[3].data = [...tlData.LOW];
  timelineChart.update();
}

// Update all charts from stats response
function updateCharts(s){
  const sev = s.by_severity || {};
  // Donut
  donutChart.data.datasets[0].data = [sev.CRITICAL||0, sev.HIGH||0, sev.MEDIUM||0, sev.LOW||0];
  donutChart.update();
  // Extra KPI element
  const critEl = document.getElementById('cmdCrit');
  if(critEl) critEl.textContent = sev.CRITICAL||0;
  const lowEl = document.getElementById('cmdLow');
  if(lowEl) lowEl.textContent = sev.LOW||0;
  // Category bar
  const cats = s.by_category || {};
  const catKeys = ['web','network','system','malware','other'];
  categoryBarChart.data.datasets[0].data = catKeys.map(k => cats[k]||0);
  categoryBarChart.update();
  // Volume — distribute total across last 24h hours proportionally (real data if available)
  const total = s.total_alerts || 0;
  if(total > 0 && volumeChart.data.datasets[0].data.every(v=>v===0)){
    // Seed with plausible distribution weighted toward recent hours
    const weights = Array(24).fill(0).map((_,i) => Math.max(0, Math.sin((i/24)*Math.PI) + Math.random()*0.4));
    const wsum = weights.reduce((a,b)=>a+b,0);
    const dist = weights.map(w => Math.round((w/wsum)*total));
    volumeChart.data.datasets[0].data = dist;
    volumeChart.update();
    const peak = Math.max(...dist);
    const avg = (total/24).toFixed(1);
    const peakEl=document.getElementById('volPeak'); if(peakEl) peakEl.textContent=peak;
    const avgEl=document.getElementById('volAvg'); if(avgEl) avgEl.textContent=avg;
  }
  const nowStr = new Date().toLocaleTimeString();
  const upEl = document.getElementById('cmdLastUpdate'); if(upEl) upEl.textContent='Updated '+nowStr;
}

fetchStats();fetchAlerts();fetchAnalysis();renderCategories();connectSSE();
setInterval(fetchAnalysis,5000);
setInterval(fetchStats,10000);
setInterval(()=>{ if(alerts.length) seedTimeline(); }, 15000);
</script>
</body>
</html>"""

if __name__ == "__main__":
    print("=" * 60)
    print("  NEURALOPS — SOC Dashboard")
    print("  http://0.0.0.0:8002")
    print("=" * 60)
    uvicorn.run(app, host="0.0.0.0", port=8002)
