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

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")
logger = logging.getLogger("neuralops.dashboard")

app = FastAPI(title="NeuralOps — SOC Dashboard")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

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

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NeuralOps — SOC Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg-primary: #0a0a0f;
    --bg-secondary: #111118;
    --bg-card: #16161e;
    --bg-hover: #1e1e2a;
    --border: rgba(255,255,255,0.06);
    --border-light: rgba(255,255,255,0.1);
    --text-primary: #e8e8ed;
    --text-secondary: rgba(255,255,255,0.5);
    --text-tertiary: rgba(255,255,255,0.25);
    --accent: #00ff88;
    --accent-dim: rgba(0,255,136,0.1);
    --critical: #ff3b30;
    --high: #ff9500;
    --medium: #ffcc00;
    --low: #34c759;
    --info: #5ac8fa;
    font-family: 'Inter', -apple-system, sans-serif;
  }

  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { background: var(--bg-primary); color: var(--text-primary); overflow-x: hidden; }
  ::-webkit-scrollbar { width: 6px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.1); border-radius: 3px; }

  /* Top Bar */
  .topbar {
    display: flex; align-items: center; justify-content: space-between;
    padding: 12px 24px; background: var(--bg-secondary);
    border-bottom: 0.5px solid var(--border); position: sticky; top: 0; z-index: 100;
  }
  .logo { display: flex; align-items: center; gap: 12px; }
  .logo-icon { width: 32px; height: 32px; border-radius: 6px; background: var(--accent-dim); border: 0.5px solid rgba(0,255,136,0.2); display: flex; align-items: center; justify-content: center; font-size: 16px; color: var(--accent); }
  .logo-text { font-family: 'JetBrains Mono', monospace; font-size: 16px; font-weight: 700; letter-spacing: -0.02em; }
  .logo-text span { color: var(--accent); }
  .logo-sub { font-size: 10px; color: var(--text-tertiary); letter-spacing: 0.15em; text-transform: uppercase; margin-top: 1px; }

  .topbar-right { display: flex; align-items: center; gap: 20px; }
  .status-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--accent); animation: pulse 2s infinite; }
  @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
  .status-text { font-size: 11px; color: var(--text-secondary); font-family: 'JetBrains Mono', monospace; }
  .status-dot.warning { background: var(--high); }

  /* Stats Bar */
  .stats-bar {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 12px; padding: 16px 24px; background: var(--bg-secondary);
    border-bottom: 0.5px solid var(--border);
  }
  .stat-card {
    background: var(--bg-card); border: 0.5px solid var(--border);
    border-radius: 8px; padding: 12px 16px; position: relative; overflow: hidden;
  }
  .stat-card::before {
    content: ''; position: absolute; top: 0; left: 0; right: 0;
    height: 2px; border-radius: 2px 2px 0 0;
  }
  .stat-card.critical::before { background: var(--critical); }
  .stat-card.high::before { background: var(--high); }
  .stat-card.medium::before { background: var(--medium); }
  .stat-card.total::before { background: var(--accent); }
  .stat-label { font-size: 10px; color: var(--text-tertiary); text-transform: uppercase; letter-spacing: 0.1em; font-family: 'JetBrains Mono', monospace; }
  .stat-value { font-size: 24px; font-weight: 700; margin-top: 4px; letter-spacing: -0.02em; }
  .stat-value.critical { color: var(--critical); }
  .stat-value.high { color: var(--high); }
  .stat-value.medium { color: var(--medium); }
  .stat-value.low { color: var(--low); }
  .stat-value.total { color: var(--accent); }

  /* Main Layout */
  .main { display: flex; height: calc(100vh - 140px); }
  .alerts-panel { flex: 1; border-right: 0.5px solid var(--border); overflow-y: auto; min-width: 0; }
  .detail-panel { width: 420px; overflow-y: auto; flex-shrink: 0; }

  /* Panel Headers */
  .panel-header {
    padding: 12px 16px; background: var(--bg-secondary);
    border-bottom: 0.5px solid var(--border); position: sticky; top: 0; z-index: 10;
    display: flex; align-items: center; justify-content: space-between;
  }
  .panel-title { font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--text-secondary); letter-spacing: 0.08em; text-transform: uppercase; }
  .panel-title span { color: var(--accent); }
  .panel-count { font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--text-tertiary); background: var(--bg-card); padding: 2px 8px; border-radius: 4px; border: 0.5px solid var(--border); }

  /* Filter Bar */
  .filter-bar {
    display: flex; gap: 8px; padding: 8px 16px;
    background: var(--bg-primary); border-bottom: 0.5px solid var(--border);
    flex-wrap: wrap;
  }
  .filter-btn {
    font-family: 'JetBrains Mono', monospace; font-size: 10px; padding: 4px 12px;
    border: 0.5px solid var(--border); border-radius: 4px; background: var(--bg-card);
    color: var(--text-secondary); cursor: pointer; transition: all 0.15s; text-transform: uppercase;
    letter-spacing: 0.06em;
  }
  .filter-btn:hover { border-color: var(--accent); color: var(--accent); }
  .filter-btn.active { background: var(--accent-dim); border-color: var(--accent); color: var(--accent); }
  .filter-btn.critical:hover { border-color: var(--critical); color: var(--critical); }
  .filter-btn.high:hover { border-color: var(--high); color: var(--high); }
  .filter-btn.medium:hover { border-color: var(--medium); color: var(--medium); }
  .filter-btn.low:hover { border-color: var(--low); color: var(--low); }
  .filter-btn.web:hover { border-color: #5ac8fa; color: #5ac8fa; }
  .filter-btn.network:hover { border-color: #af52de; color: #af52de; }
  .filter-btn.system:hover { border-color: #ff9f0a; color: #ff9f0a; }

  /* Alert Card */
  .alert-card {
    padding: 12px 16px; border-bottom: 0.5px solid var(--border);
    cursor: pointer; transition: background 0.15s; position: relative;
  }
  .alert-card:hover { background: var(--bg-hover); }
  .alert-card.active { background: var(--bg-hover); border-left: 2px solid var(--accent); }
  .alert-card.critical { border-left: 2px solid var(--critical); }
  .alert-card.high { border-left: 2px solid var(--high); }
  .alert-card.medium { border-left: 2px solid var(--medium); }
  .alert-card.low { border-left: 2px solid var(--low); }
  .alert-card.info { border-left: 2px solid var(--info); }
  .source-badge { font-size: 9px; font-family: 'JetBrains Mono', monospace; padding: 2px 6px; border-radius: 3px; letter-spacing: 0.06em; text-transform: uppercase; white-space: nowrap; }
  .source-web { background: rgba(90,200,250,0.12); color: #5ac8fa; border: 0.5px solid rgba(90,200,250,0.2); }
  .source-network { background: rgba(175,82,222,0.12); color: #af52de; border: 0.5px solid rgba(175,82,222,0.2); }
  .source-system { background: rgba(255,159,10,0.12); color: #ff9f0a; border: 0.5px solid rgba(255,159,10,0.2); }

  .alert-header { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
  .alert-rule { font-weight: 600; font-size: 13px; }
  .alert-severity { font-size: 10px; font-family: 'JetBrains Mono', monospace; padding: 2px 8px; border-radius: 3px; white-space: nowrap; }
  .severity-critical { background: rgba(255,59,48,0.15); color: var(--critical); border: 0.5px solid rgba(255,59,48,0.2); }
  .severity-high { background: rgba(255,149,0,0.15); color: var(--high); border: 0.5px solid rgba(255,149,0,0.2); }
  .severity-medium { background: rgba(255,204,0,0.12); color: var(--medium); border: 0.5px solid rgba(255,204,0,0.2); }
  .severity-low { background: rgba(52,199,89,0.12); color: var(--low); border: 0.5px solid rgba(52,199,89,0.2); }

  .alert-body { margin-top: 6px; display: flex; flex-wrap: wrap; gap: 6px; }
  .alert-tag { font-size: 10px; color: var(--text-tertiary); font-family: 'JetBrains Mono', monospace; background: var(--bg-primary); padding: 1px 6px; border-radius: 3px; border: 0.5px solid var(--border); }
  .alert-time { font-size: 10px; color: var(--text-tertiary); font-family: 'JetBrains Mono', monospace; }
  .alert-ip { font-size: 11px; color: var(--text-secondary); font-family: 'JetBrains Mono', monospace; }
  .alert-desc { font-size: 12px; color: var(--text-secondary); margin-top: 6px; }
  .alert-conf { font-size: 10px; color: var(--text-tertiary); font-family: 'JetBrains Mono', monospace; }

  /* Empty State */
  .empty-state { display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 60px 20px; color: var(--text-tertiary); }
  .empty-icon { font-size: 40px; margin-bottom: 16px; opacity: 0.3; }
  .empty-text { font-size: 14px; }
  .empty-sub { font-size: 12px; margin-top: 8px; }

  /* Detail Panel */
  .detail-content { padding: 16px; }
  .detail-section { margin-bottom: 20px; }
  .detail-section-title { font-size: 10px; color: var(--text-tertiary); text-transform: uppercase; letter-spacing: 0.1em; font-family: 'JetBrains Mono', monospace; margin-bottom: 8px; padding-bottom: 4px; border-bottom: 0.5px solid var(--border); }
  .detail-field { display: flex; justify-content: space-between; padding: 4px 0; font-size: 12px; }
  .detail-label { color: var(--text-tertiary); }
  .detail-value { color: var(--text-primary); font-weight: 500; max-width: 60%; text-align: right; word-break: break-all; }
  .detail-value.mono { font-family: 'JetBrains Mono', monospace; font-size: 11px; }

  .analysis-card {
    background: var(--bg-card); border: 0.5px solid var(--border);
    border-radius: 8px; padding: 16px; margin-top: 12px;
  }
  .analysis-card .gemini-badge {
    display: inline-flex; align-items: center; gap: 6px;
    font-size: 10px; color: var(--accent); font-family: 'JetBrains Mono', monospace;
    background: var(--accent-dim); padding: 3px 8px; border-radius: 4px;
    border: 0.5px solid rgba(0,255,136,0.2); margin-bottom: 12px;
  }
  .analysis-summary { font-size: 13px; line-height: 1.5; color: var(--text-primary); margin-bottom: 12px; }
  .analysis-explanation { font-size: 12px; line-height: 1.5; color: var(--text-secondary); margin-bottom: 12px; }
  .analysis-severity { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; margin-bottom: 12px; }
  .analysis-fp { font-size: 12px; color: var(--text-secondary); margin-bottom: 12px; }
  .analysis-actions { list-style: none; padding: 0; }
  .analysis-actions li {
    padding: 6px 10px; margin-bottom: 4px; font-size: 12px; color: var(--text-secondary);
    background: var(--bg-primary); border-radius: 4px; border: 0.5px solid var(--border);
    position: relative; padding-left: 20px;
  }
  .analysis-actions li::before {
    content: '→'; position: absolute; left: 6px; color: var(--accent);
  }

  .nowrap { white-space: nowrap; }

  /* New alert animation */
  @keyframes slideIn {
    from { opacity: 0; transform: translateX(-10px); }
    to { opacity: 1; transform: translateX(0); }
  }
  .alert-card.new { animation: slideIn 0.3s ease-out; }

  @media (max-width: 900px) {
    .main { flex-direction: column; height: auto; }
    .detail-panel { width: 100%; border-top: 0.5px solid var(--border); max-height: 50vh; }
    .stats-bar { grid-template-columns: repeat(2, 1fr); }
  }
</style>
</head>
<body>

<div class="topbar">
  <div class="logo">
    <div class="logo-icon">⚡</div>
    <div>
      <div class="logo-text">Neural<span>Ops</span></div>
      <div class="logo-sub">AI-Powered SOC Platform</div>
    </div>
  </div>
  <div class="topbar-right">
    <div style="display:flex;align-items:center;gap:6px;">
      <div class="status-dot" id="statusDot"></div>
      <span class="status-text" id="statusText">LIVE</span>
    </div>
    <span class="status-text" id="clock"></span>
  </div>
</div>

<div class="stats-bar" id="statsBar">
  <div class="stat-card total">
    <div class="stat-label">Total Alerts</div>
    <div class="stat-value total" id="statTotal">0</div>
  </div>
  <div class="stat-card high">
    <div class="stat-label">High / Critical</div>
    <div class="stat-value high" id="statHigh">0</div>
  </div>
  <div class="stat-card medium">
    <div class="stat-label">Medium</div>
    <div class="stat-value medium" id="statMed">0</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Analyzed</div>
    <div class="stat-value total" id="statAnalyzed">0</div>
  </div>
</div>

<div class="main">
  <div class="alerts-panel">
    <div class="panel-header">
      <div class="panel-title"><span>▼</span> Alert Feed</div>
      <div class="panel-count" id="alertCount">0</div>
    </div>
    <div class="filter-bar" id="filterBar">
      <button class="filter-btn active" data-filter="all">All</button>
      <button class="filter-btn critical" data-filter="CRITICAL">Critical</button>
      <button class="filter-btn high" data-filter="HIGH">High</button>
      <button class="filter-btn medium" data-filter="MEDIUM">Medium</button>
      <button class="filter-btn low" data-filter="LOW">Low</button>
      <span style="width:1px;height:16px;background:var(--border);margin:0 4px;"></span>
      <button class="filter-btn web" data-source="web">🌐 Web</button>
      <button class="filter-btn network" data-source="network">🔌 Network</button>
      <button class="filter-btn system" data-source="system">⚙️ System</button>
    </div>
    <div id="alertList"></div>
  </div>
  <div class="detail-panel" id="detailPanel">
    <div class="panel-header">
      <div class="panel-title"><span>◆</span> Analysis</div>
    </div>
    <div class="detail-content" id="detailContent">
      <div class="empty-state">
        <div class="empty-icon">⚡</div>
        <div class="empty-text">Select an alert to analyze</div>
        <div class="empty-sub">Click any alert from the feed</div>
      </div>
    </div>
  </div>
</div>

<script>
const SEVERITY_CLASS = { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low', INFO: 'info' };
let alerts = [];
let currentFilter = 'all';
let currentSource = null;
let selectedAlertId = null;
let analysisCache = {};

function clock() {
  document.getElementById('clock').textContent = new Date().toLocaleTimeString();
}
setInterval(clock, 1000);
clock();

async function fetchStats() {
  try {
    const r = await fetch('/api/stats');
    const s = await r.json();
    document.getElementById('statTotal').textContent = s.total_alerts;
    document.getElementById('statHigh').textContent = (s.by_severity.CRITICAL||0) + (s.by_severity.HIGH||0);
    document.getElementById('statMed').textContent = s.by_severity.MEDIUM || 0;
    document.getElementById('statAnalyzed').textContent = s.total_analyzed;
  } catch(e) {}
}

async function fetchAlerts() {
  try {
    const r = await fetch('/api/alerts?limit=100');
    const d = await r.json();
    alerts = d.alerts;
    renderAlerts();
    document.getElementById('alertCount').textContent = alerts.length;
  } catch(e) {}
}

async function fetchAnalysis() {
  try {
    const r = await fetch('/api/analysis?limit=50');
    const d = await r.json();
    for (const item of d.analysis) {
      if (item.alert_id) {
        analysisCache[item.alert_id] = item;
      }
    }
    if (selectedAlertId && analysisCache[selectedAlertId]) {
      renderDetail(selectedAlertId);
    }
  } catch(e) {}
}

function renderAlerts() {
  const container = document.getElementById('alertList');
  let filtered = currentFilter === 'all'
    ? alerts
    : alerts.filter(a => (a.severity || 'INFO').toUpperCase() === currentFilter);
  if (currentSource) {
    filtered = filtered.filter(a => a.source === currentSource);
  }

  if (filtered.length === 0) {
    container.innerHTML = '<div class="empty-state"><div class="empty-icon">📡</div><div class="empty-text">No alerts</div><div class="empty-sub">Waiting for incoming threats...</div></div>';
    return;
  }

  container.innerHTML = filtered.map(a => {
    const sev = (a.severity || 'INFO').toUpperCase();
    const sevClass = SEVERITY_CLASS[sev] || 'info';
    const isActive = a.id === selectedAlertId;
    const ts = a.timestamp ? new Date(a.timestamp).toLocaleTimeString() : '--';
    const conf = typeof a.confidence === 'number' ? a.confidence.toFixed(3) : a.confidence || '--';
    const src = a.source || 'web';
    const srcClass = 'source-' + src;
    const srcLabel = src === 'network' ? '🔌 NET' : src === 'system' ? '⚙️ SYS' : '🌐 WEB';
    return `<div class="alert-card ${sevClass}${isActive ? ' active' : ''}" data-id="${a.id}" onclick="selectAlert('${a.id}')">
      <div class="alert-header">
        <div class="alert-rule">${a.rule_name || 'Unknown'}</div>
        <div style="display:flex;gap:4px;align-items:center;">
          <span class="source-badge ${srcClass}">${srcLabel}</span>
          <div class="alert-severity severity-${sevClass}">${sev}</div>
        </div>
      </div>
      <div class="alert-body">
        <span class="alert-ip">${a.source_ip || '--'}</span>
        <span class="alert-tag">${a.ttp || '--'}</span>
        <span class="alert-tag">${a.category || '--'}</span>
        <span class="alert-conf">conf: ${conf}</span>
        <span class="alert-time">${ts}</span>
      </div>
      <div class="alert-desc">${a.description || (a.rule_name ? a.rule_name + ' detected' : '')}</div>
    </div>`;
  }).join('');
}

function selectAlert(id) {
  selectedAlertId = id;
  renderAlerts();
  renderDetail(id);
}

function renderDetail(id) {
  const a = alerts.find(x => x.id === id);
  const container = document.getElementById('detailContent');
  if (!a) return;

  const analysis = analysisCache[id];
  const geo = a.geo && typeof a.geo === 'object' ? a.geo : {};
  const raw = a.raw_log && typeof a.raw_log === 'object' ? a.raw_log : {};
  const ts = a.timestamp ? new Date(a.timestamp).toISOString().replace('T', ' ').slice(0, 19) : '--';

  const src = a.source || 'web';
  const srcLabel = src === 'network' ? '🔌 Network' : src === 'system' ? '⚙️ System' : '🌐 Web';

  let html = `
    <div class="detail-section">
      <div class="detail-section-title">Alert Details</div>
      <div class="detail-field"><span class="detail-label">Source</span><span class="detail-value">${srcLabel}</span></div>
      <div class="detail-field"><span class="detail-label">Rule</span><span class="detail-value">${a.rule_name || '--'}</span></div>
      <div class="detail-field"><span class="detail-label">Severity</span><span class="detail-value">${(a.severity || '--').toUpperCase()}</span></div>
      <div class="detail-field"><span class="detail-label">Confidence</span><span class="detail-value mono">${typeof a.confidence === 'number' ? (a.confidence*100).toFixed(1) + '%' : '--'}</span></div>
      <div class="detail-field"><span class="detail-label">TTP</span><span class="detail-value mono">${a.ttp || '--'}</span></div>
      <div class="detail-field"><span class="detail-label">Kill Chain</span><span class="detail-value mono">${a.kill_chain || '--'}</span></div>
      <div class="detail-field"><span class="detail-label">Category</span><span class="detail-value">${a.category || '--'}</span></div>
      <div class="detail-field"><span class="detail-label">Timestamp</span><span class="detail-value mono">${ts}</span></div>
      <div class="detail-field"><span class="detail-label">Source IP</span><span class="detail-value mono">${a.source_ip || '--'}</span></div>
      <div class="detail-field"><span class="detail-label">Matched</span><span class="detail-value mono" style="font-size:10px;">${(a.matched_value || '').slice(0,60)}</span></div>
    </div>

    <div class="detail-section">
      <div class="detail-section-title">Request Context</div>
      <div class="detail-field"><span class="detail-label">Method</span><span class="detail-value mono">${raw.method || '--'}</span></div>
      <div class="detail-field"><span class="detail-label">Path</span><span class="detail-value mono">${raw.path || '--'}</span></div>
      <div class="detail-field"><span class="detail-label">Status</span><span class="detail-value mono">${raw.status || '--'}</span></div>
      <div class="detail-field"><span class="detail-label">User Agent</span><span class="detail-value mono" style="font-size:10px;">${(raw.user_agent || '--').slice(0,40)}</span></div>
    </div>

    ${geo.country || geo.city ? `
    <div class="detail-section">
      <div class="detail-section-title">Geo</div>
      <div class="detail-field"><span class="detail-label">Country</span><span class="detail-value">${geo.country || '--'}</span></div>
      <div class="detail-field"><span class="detail-label">City</span><span class="detail-value">${geo.city || '--'}</span></div>
      <div class="detail-field"><span class="detail-label">ASN</span><span class="detail-value mono">${geo.asn || '--'}</span></div>
    </div>` : ''}
  `;

  if (analysis && analysis.analysis) {
    const an = analysis.analysis;
    const fp = an.false_positive_likelihood;
    let fpColor = '#34c759';
    if (fp > 70) fpColor = '#ff3b30';
    else if (fp > 30) fpColor = '#ff9500';

    html += `
    <div class="analysis-card">
      <div class="gemini-badge">✦ Gemini AI Analysis</div>
      <div class="analysis-summary">${an.summary || ''}</div>
      ${an.attack_explanation ? `<div class="analysis-explanation">${an.attack_explanation}</div>` : ''}
      <div class="analysis-severity">
        <span style="font-size:10px;color:var(--text-tertiary);font-family:'JetBrains Mono',monospace;">True Severity:</span>
        <span style="font-weight:600;color:${an.true_severity === 'CRITICAL' ? 'var(--critical)' : an.true_severity === 'HIGH' ? 'var(--high)' : an.true_severity === 'MEDIUM' ? 'var(--medium)' : 'var(--low)'}">${an.true_severity || '--'}</span>
      </div>
      <div class="analysis-fp">False Positive Likelihood: <span style="color:${fpColor};font-weight:600;">${fp !== undefined ? fp + '%' : '--'}</span></div>
      ${an.recommended_actions && an.recommended_actions.length ? `
      <div style="font-size:10px;color:var(--text-tertiary);text-transform:uppercase;letter-spacing:0.1em;font-family:'JetBrains Mono',monospace;margin-bottom:6px;">Recommended Actions</div>
      <ul class="analysis-actions">
        ${an.recommended_actions.map(act => `<li>${act}</li>`).join('')}
      </ul>` : ''}
      ${an.analyst_notes ? `<div style="margin-top:12px;padding:10px;background:var(--bg-primary);border-radius:4px;border:0.5px solid var(--border);font-size:11px;color:var(--text-secondary);line-height:1.4;"><span style="color:var(--accent);font-family:'JetBrains Mono',monospace;font-size:10px;">// analyst notes</span><br>${an.analyst_notes}</div>` : ''}
    </div>`;
  } else {
    html += `<div style="margin-top:16px;padding:12px;background:var(--bg-card);border-radius:6px;border:0.5px solid var(--border);text-align:center;">
      <div style="font-size:11px;color:var(--text-tertiary);">⏳ Waiting for Gemini analysis...</div>
    </div>`;
  }

  container.innerHTML = html;
}

// Filter buttons
document.getElementById('filterBar').addEventListener('click', e => {
  const btn = e.target.closest('.filter-btn');
  if (!btn) return;

  if (btn.dataset.source) {
    currentSource = currentSource === btn.dataset.source ? null : btn.dataset.source;
    document.querySelectorAll('.filter-btn[data-source]').forEach(b => b.classList.remove('active'));
    if (currentSource) btn.classList.add('active');
  } else {
    currentSource = null;
    document.querySelectorAll('.filter-btn[data-source]').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    currentFilter = btn.dataset.filter;
  }
  renderAlerts();
});

// SSE Real-time
let source = null;
function connectSSE() {
  source = new EventSource('/api/stream');
  source.onmessage = e => {
    try {
      const msg = JSON.parse(e.data);
      if (msg.type === 'alert') {
        const existing = alerts.findIndex(a => a.id === msg.data.id);
        if (existing === -1) {
          alerts.unshift(msg.data);
          if (alerts.length > 200) alerts.pop();
          fetchStats();
          renderAlerts();
          document.getElementById('alertCount').textContent = alerts.length;
        }
      }
    } catch(e) {}
  };
  source.onerror = () => {
    document.getElementById('statusDot').className = 'status-dot warning';
    document.getElementById('statusText').textContent = 'RECONNECT';
    source.close();
    setTimeout(connectSSE, 3000);
  };
  source.onopen = () => {
    document.getElementById('statusDot').className = 'status-dot';
    document.getElementById('statusText').textContent = 'LIVE';
  };
}

// Init
fetchStats();
fetchAlerts();
fetchAnalysis();
connectSSE();
setInterval(fetchAnalysis, 5000);
setInterval(fetchStats, 10000);
</script>
</body>
</html>"""

if __name__ == "__main__":
    print("=" * 60)
    print("  NEURALOPS — SOC Dashboard")
    print("  http://0.0.0.0:8002")
    print("=" * 60)
    uvicorn.run(app, host="0.0.0.0", port=8002)
