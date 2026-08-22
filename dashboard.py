#!/usr/bin/env python3
"""
nomad dashboard — Minimal web UI for agent drift detection.
"""

import json
import time
import threading
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, render_template_string, request

from nomad import NomadEngine
from config import SCAN_INTERVAL

app = Flask(__name__)
engine = NomadEngine(dry_run=True)
_last_result = {"drifters": [], "migrations": [], "timestamp": 0}
_last_security = {"available": False, "posture_score": 0, "sections": [], "critical_issues": [], "warnings": []}
_lock = threading.Lock()

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>nomad — drift detector</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Inter', 'Segoe UI', sans-serif;
    background: radial-gradient(1100px 520px at 18% -10%, #1c1016 0%, #08080e 45%), #08080e;
    color: #e0e0e8;
    padding: 24px;
    min-height: 100vh;
  }
  h1, .brand-name { font-family: 'Cinzel', 'Georgia', serif; }

  /* ---- Top bar ---- */
  .topbar { display: flex; align-items: center; justify-content: space-between; gap: 16px; flex-wrap: wrap; margin-bottom: 26px; }
  .brand { display: flex; align-items: center; gap: 14px; }
  .brand-logo {
    width: 46px; height: 46px; border-radius: 13px;
    background: linear-gradient(135deg, #1a0a0a, #2a1010);
    border: 1px solid rgba(200, 60, 60, .3);
    display: flex; align-items: center; justify-content: center; font-size: 1.25rem;
    box-shadow: 0 4px 18px rgba(255, 60, 60, .12);
  }
  .brand-name {
    font-size: 1.55rem; font-weight: 900; letter-spacing: 5px; text-transform: uppercase;
    background: linear-gradient(135deg, #ff6b6b, #c8a87c);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;
  }
  .brand-sub { color: #777; font-size: .8rem; margin-top: 3px; }
  .health {
    display: flex; align-items: center; gap: 9px;
    background: #111118; border: 1px solid #222; border-radius: 10px;
    padding: 9px 15px; font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: .78rem;
  }
  .dot { width: 10px; height: 10px; border-radius: 50%; }
  .dot.ok { background: #6bff6b; box-shadow: 0 0 9px #6bff6b; }
  .dot.stale { background: #ffdd6b; box-shadow: 0 0 9px #ffdd6b; }
  .dot.dead { background: #ff6b6b; box-shadow: 0 0 9px #ff6b6b; }
  .health-label { color: #aaa; }
  .health .age { color: #555; }

  /* ---- Stat grid ---- */
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 12px; margin-bottom: 24px; }
  .stat {
    background: linear-gradient(160deg, #14141e, #0d0d15);
    border: 1px solid #20202c; border-radius: 12px;
    padding: 18px; text-align: center; position: relative; overflow: hidden;
    transition: transform .15s ease;
  }
  .stat:hover { transform: translateY(-2px); }
  .stat::before { content: ''; position: absolute; top: 0; left: 0; bottom: 0; width: 3px; }
  .stat.blue::before { background: #6b9bff; }
  .stat.purple::before { background: #b06bff; }
  .stat.cyan::before { background: #6bd8ff; }
  .stat.red::before { background: #ff6b6b; }
  .stat .num { font-family: 'JetBrains Mono', monospace; font-size: 2.2em; font-weight: 700; }
  .stat.blue .num { color: #6b9bff; }
  .stat.purple .num { color: #b06bff; }
  .stat.cyan .num { color: #6bd8ff; }
  .stat.red .num { color: #ff6b6b; }
  .stat .label { font-size: .72em; color: #888; margin-top: 5px; letter-spacing: 1.5px; text-transform: uppercase; }
  .stat.hot { border-color: #ff6b6b; animation: pulse 2s ease-in-out infinite; }
  @keyframes pulse { 0%, 100% { box-shadow: 0 0 0 rgba(255, 107, 107, 0); } 50% { box-shadow: 0 0 20px rgba(255, 107, 107, .4); } }

  /* ---- Panels ---- */
  .panel { background: #0d0d15; border: 1px solid #1e1e2a; border-radius: 12px; padding: 18px; margin-bottom: 20px; }
  .panel-title { font-size: 1.02em; font-weight: 700; letter-spacing: 1px; margin-bottom: 13px; display: flex; align-items: center; gap: 9px; }
  .panel-title .bar { width: 4px; height: 16px; border-radius: 2px; }
  .p-red .bar { background: #ff6b6b; } .p-red .panel-title { color: #ff8b8b; }
  .p-blue .bar { background: #6b9bff; } .p-blue .panel-title { color: #8fb0ff; }
  .p-amber .bar { background: #ffbb6b; } .p-amber .panel-title { color: #ffd08b; }
  .p-pink .bar { background: #ff6bb8; } .p-pink .panel-title { color: #ff8fc8; }
  .p-green .bar { background: #6bff9b; } .p-green .panel-title { color: #8bffb0; }

  .empty { color: #444; text-align: center; padding: 30px; font-style: italic; }

  /* Drifters */
  .drifter {
    background: #1a0c0c; border: 1px solid #3a1515; border-left: 3px solid #ff6b6b;
    border-radius: 10px; padding: 15px 17px; margin-bottom: 12px;
  }
  .drifter.safe { background: #0d1610; border-color: #163a21; border-left-color: #6bff9b; }
  .drifter-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
  .drifter-name { font-weight: 700; font-size: 1.05em; color: #f0f0f8; }
  .drifter-score { padding: 3px 10px; border-radius: 6px; font-size: .85em; font-weight: 700; font-family: 'JetBrains Mono', monospace; }
  .score-high { background: #3a1515; color: #ff6b6b; }
  .score-med { background: #3a3a15; color: #ffdd6b; }
  .score-low { background: #153a15; color: #6bff6b; }
  .drifter-kind { color: #999; font-size: .8em; }
  .drifter-reason { color: #bbb; font-size: .85em; margin-top: 4px; }
  .drifter-evidence { color: #666; font-size: .78em; margin-top: 4px; font-family: 'JetBrains Mono', monospace; }

  /* Migrations */
  .migration {
    background: #0c0f1a; border: 1px solid #15203a; border-left: 3px solid #6b9bff;
    border-radius: 10px; padding: 12px 16px; margin-bottom: 8px;
    display: flex; align-items: center; gap: 12px; font-size: .88em;
  }
  .migration-arrow { color: #6b9bff; font-size: 1.2em; }

  /* Credentials / Network */
  .cred-item, .net-item {
    background: #0f0d14; border: 1px solid #201b2a; border-radius: 10px;
    padding: 12px 16px; margin-bottom: 8px; font-size: .85em;
  }
  .cred-item.critical { border-color: #ff6b6b; background: #1a0a0a; }
  .cred-item.high { border-color: #ffaa6b; background: #1a150a; }
  .cred-item.medium { border-color: #ffdd6b; background: #1a180a; }
  .net-item.high { border-color: #ff6bb8; background: #1a0a14; }
  .net-item.medium { border-color: #ffbb6b; background: #1a140a; }
  .cred-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px; }
  .cred-risk { padding: 2px 8px; border-radius: 5px; font-size: .75em; font-weight: 700; text-transform: uppercase; letter-spacing: .5px; }
  .risk-critical { background: #3a1515; color: #ff6b6b; }
  .risk-high { background: #3a2a15; color: #ffaa6b; }
  .risk-medium { background: #3a3a15; color: #ffdd6b; }
  .risk-low { background: #153a15; color: #6bff6b; }

  /* Security panel */
  .sec-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
  .sec-score { font-size: 2.6em; font-weight: 800; font-family: 'JetBrains Mono', monospace; }
  .sec-score.good { color: #6bff9b; text-shadow: 0 0 18px rgba(107, 255, 155, .35); }
  .sec-score.warn { color: #ffdd6b; text-shadow: 0 0 18px rgba(255, 221, 107, .3); }
  .sec-score.bad { color: #ff6b6b; text-shadow: 0 0 18px rgba(255, 107, 107, .35); }
  .sec-label { color: #888; font-size: .82em; }
  .sec-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 8px; }
  .sec-item { font-size: .83em; padding: 7px 11px; border-radius: 6px; }
  .sec-item.ok { background: #0d1610; color: #6bff9b; }
  .sec-item.warn { background: #1a180a; color: #ffdd6b; }
  .sec-item.critical { background: #1a0a0a; color: #ff6b6b; }
  .sec-unavail { color: #777; font-size: .85em; font-style: italic; }
  .sec-unavail a { color: #c8a87c; }

  .refresh { color: #555; font-size: .72em; text-align: right; font-family: 'JetBrains Mono', monospace; margin-top: 4px; }
</style>
</head>
<body>
<div class="topbar">
  <div class="brand">
    <div class="brand-logo">🛰️</div>
    <div>
      <div class="brand-name">nomad</div>
      <div class="brand-sub">catch autonomous agents that spawn ephemeral infrastructure</div>
    </div>
  </div>
  <div class="health">
    <span class="dot dead" id="health-dot"></span>
    <span class="health-label" id="health-label">connecting…</span>
    <span class="age" id="health-age"></span>
  </div>
</div>

<div class="grid">
  <div class="stat blue"><div class="num" id="s-containers">0</div><div class="label">Containers</div></div>
  <div class="stat purple"><div class="num" id="s-services">0</div><div class="label">Services</div></div>
  <div class="stat cyan"><div class="num" id="s-processes">0</div><div class="label">Processes</div></div>
  <div class="stat red" id="stat-drifters"><div class="num" id="s-drifters">0</div><div class="label">Drifters</div></div>
</div>

<div class="panel p-red">
  <div class="panel-title"><span class="bar"></span>Drifters</div>
  <div id="drifters"><div class="empty">No drifters detected</div></div>
</div>

<div class="panel p-blue">
  <div class="panel-title"><span class="bar"></span>Migrations</div>
  <div id="migrations"><div class="empty">No migrations detected</div></div>
</div>

<div class="panel p-amber">
  <div class="panel-title"><span class="bar"></span>Credential Access</div>
  <div id="credentials"><div class="empty">No credential access detected</div></div>
</div>

<div class="panel p-pink">
  <div class="panel-title"><span class="bar"></span>Network Anomalies</div>
  <div id="network"><div class="empty">No network anomalies detected</div></div>
</div>

<div class="panel p-green">
  <div class="panel-title"><span class="bar"></span>System Security</div>
  <div class="sec-header">
    <div>
      <div class="sec-score" id="sec-score">--</div>
      <div class="sec-label">Posture Score</div>
    </div>
    <div style="text-align:right">
      <div class="sec-label" id="sec-verify"></div>
      <div class="sec-label" id="sec-time"></div>
    </div>
  </div>
  <div class="sec-grid" id="sec-items"></div>
</div>

<div class="refresh" id="refresh-time"></div>
<script>
function health() {
  fetch('/api/health').then(r => r.json()).then(h => {
    const dot = document.getElementById('health-dot');
    const lbl = document.getElementById('health-label');
    const age = document.getElementById('health-age');
    dot.className = 'dot ' + h.status;
    lbl.textContent = h.status === 'ok' ? 'online' : h.status === 'stale' ? 'stale' : 'offline';
    const sec = h.last_scan_age_sec;
    age.textContent = sec !== null && sec !== undefined ? (sec < 120 ? 'fresh' : sec < 600 ? Math.round(sec) + 's ago' : '>10min') : '';
  }).catch(() => {
    document.getElementById('health-dot').className = 'dot dead';
    document.getElementById('health-label').textContent = 'offline';
  });
}
function update() {
  fetch('/api/last').then(r => r.json()).then(d => {
    document.getElementById('s-containers').textContent = d.containers || 0;
    document.getElementById('s-services').textContent = d.services || 0;
    document.getElementById('s-processes').textContent = d.processes || 0;
    const nd = (d.drifters || []).length;
    document.getElementById('s-drifters').textContent = nd;
    document.getElementById('stat-drifters').classList.toggle('hot', nd > 0);

    const dc = document.getElementById('drifters');
    if (d.drifters && d.drifters.length) {
      dc.innerHTML = d.drifters.map(dr => {
        const cls = dr.score > 0.8 ? '' : ' safe';
        const scls = dr.score > 0.8 ? 'score-high' : dr.score > 0.5 ? 'score-med' : 'score-low';
        return `<div class="drifter${cls}">
          <div class="drifter-header">
            <span class="drifter-name">${dr.name}</span>
            <span class="drifter-score ${scls}">${dr.score.toFixed(2)}</span>
          </div>
          <div class="drifter-kind">${dr.kind} — ${dr.alive ? 'alive' : 'dead'}</div>
          <div class="drifter-reason">${dr.reason}</div>
          <div class="drifter-evidence">${dr.evidence.join(' | ')}</div>
        </div>`;
      }).join('');
    } else {
      dc.innerHTML = '<div class="empty">No drifters detected</div>';
    }

    const mc = document.getElementById('migrations');
    if (d.migrations && d.migrations.length) {
      mc.innerHTML = d.migrations.map(m =>
        `<div class="migration">
          <span>${m.source}</span>
          <span class="migration-arrow">→</span>
          <span>${m.target}</span>
          <span style="color:#666">(${m.kind}, sim=${m.similarity.toFixed(2)})</span>
        </div>`
      ).join('');
    } else {
      mc.innerHTML = '<div class="empty">No migrations detected</div>';
    }

    const cc = document.getElementById('credentials');
    if (d.credential_findings && d.credential_findings.length) {
      cc.innerHTML = d.credential_findings.map(c => {
        const rcls = 'risk-' + c.risk_level;
        return `<div class="cred-item ${c.risk_level}">
          <div class="cred-header">
            <span>${c.process_name} (PID ${c.pid})</span>
            <span class="cred-risk ${rcls}">${c.risk_level}</span>
          </div>
          <div style="color:#888;font-size:0.9em">${c.file_path}</div>
          <div style="color:#666;font-size:0.8em;margin-top:4px">${c.evidence.join(' | ')}</div>
        </div>`;
      }).join('');
    } else {
      cc.innerHTML = '<div class="empty">No credential access detected</div>';
    }

    const nc = document.getElementById('network');
    if (d.network_anomalies && d.network_anomalies.length) {
      nc.innerHTML = d.network_anomalies.map(n => {
        const rcls = 'risk-' + n.risk_level;
        return `<div class="net-item ${n.risk_level}">
          <div class="cred-header">
            <span>${n.process_name} (PID ${n.pid})</span>
            <span class="cred-risk ${rcls}">${n.risk_level}</span>
          </div>
          <div style="color:#888;font-size:0.9em">${n.anomaly_type} → ${n.remote_addr || 'N/A'}</div>
          <div style="color:#666;font-size:0.8em;margin-top:4px">${n.evidence.join(' | ')}</div>
        </div>`;
      }).join('');
    } else {
      nc.innerHTML = '<div class="empty">No network anomalies detected</div>';
    }

    document.getElementById('refresh-time').textContent =
      'last scan: ' + new Date(d.timestamp * 1000).toLocaleTimeString();
  });

  fetch('/api/security').then(r => r.json()).then(s => {
    const el = document.getElementById('sec-score');
    const items = document.getElementById('sec-items');
    const verify = document.getElementById('sec-verify');
    const time = document.getElementById('sec-time');

    if (!s.available) {
      el.textContent = '--';
      el.className = 'sec-score';
      items.innerHTML = '<div class="sec-unavail">sec-toolkit.sh not installed — <a href="#setup">install it</a></div>';
      verify.textContent = '';
      time.textContent = '';
      return;
    }

    const score = s.posture_score || 0;
    el.textContent = score + '%';
    el.className = 'sec-score ' + (score >= 70 ? 'good' : score >= 40 ? 'warn' : 'bad');

    verify.textContent = s.verify_passed + '/' + s.verify_total + ' checks passed';
    time.textContent = s.timestamp ? new Date(s.timestamp).toLocaleTimeString() : '';

    let html = '';
    (s.critical_issues || []).forEach(i => {
      html += '<div class="sec-item critical">🔴 ' + i + '</div>';
    });
    (s.warnings || []).forEach(w => {
      html += '<div class="sec-item warn">⚠️ ' + w + '</div>';
    });
    if (!s.critical_issues?.length && !s.warnings?.length) {
      html = '<div class="sec-item ok">✅ All checks passed</div>';
    }
    items.innerHTML = html;
  });
}
health();
update();
setInterval(update, 10000);
</script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML)


@app.route("/api/last")
def api_last():
    with _lock:
        return jsonify(_last_result)


@app.route("/api/alerts")
def api_alerts():
    limit = request.args.get("limit", 50, type=int)
    return jsonify(engine.get_alerts(limit=limit))


@app.route("/api/scan", methods=["POST"])
def api_scan():
    result = engine.run_once()
    with _lock:
        global _last_result
        _last_result = result
    return jsonify(result)


@app.route("/api/security")
def api_security():
    with _lock:
        return jsonify(_last_security)


@app.route("/api/health")
def api_health():
    with _lock:
        last_ts = _last_result.get("timestamp", 0)
    age = time.time() - last_ts if last_ts else 999
    status = "ok" if age < 120 else "stale" if age < 600 else "dead"
    return jsonify({
        "status": status,
        "last_scan_age_sec": round(age, 1),
        "last_scan": datetime.fromtimestamp(last_ts, tz=timezone.utc).isoformat() if last_ts else None,
        "service": "nomad",
    })


def _background_scan():
    scan_count = 0
    while True:
        try:
            result = engine.run_once()
            with _lock:
                global _last_result
                _last_result = result

            if scan_count % 10 == 0:
                try:
                    from security import get_security_summary
                    sec = get_security_summary()
                    with _lock:
                        global _last_security
                        _last_security = sec
                except Exception:
                    pass

            scan_count += 1
        except Exception:
            pass
        time.sleep(SCAN_INTERVAL)


def run_dashboard(host="0.0.0.0", port=5010, debug=False):
    t = threading.Thread(target=_background_scan, daemon=True)
    t.start()
    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=5010)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    run_dashboard(host=args.host, port=args.port, debug=args.debug)
