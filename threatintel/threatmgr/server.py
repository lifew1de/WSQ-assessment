"""SIEM-style web dashboard + JSON API, built on http.server (stdlib only).

Endpoints:
  GET  /                      dashboard HTML
  GET  /api/stats             summary counts
  GET  /api/iocs?q=&type=&severity=&source=&limit=
  GET  /api/feeds             feed run metadata
  GET  /api/alerts?open=1
  GET  /api/lookup?value=     check a single observable against the store
  POST /api/scan              body: {"lines": ["log line", ...]} -> alerts
  POST /api/ack               body: {"id": <alert_id>}
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from .store import Store
from .matcher import Matcher

DASHBOARD = """<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ThreatMgr SOC Console</title>
<style>
:root{--bg:#0b0f17;--panel:#131a26;--line:#223049;--fg:#e6edf6;--muted:#8aa0bd;
--crit:#ff4d5e;--high:#ff9f43;--med:#ffd666;--low:#6ee7b7;--accent:#4aa8ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
header{padding:16px 22px;border-bottom:1px solid var(--line);display:flex;
align-items:center;gap:14px;background:var(--panel)}
header h1{font-size:17px;margin:0;letter-spacing:.5px}
.dot{width:9px;height:9px;border-radius:50%;background:var(--low);box-shadow:0 0 8px var(--low)}
.wrap{padding:22px;max-width:1200px;margin:0 auto}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:22px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px}
.card .n{font-size:28px;font-weight:700}.card .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.6px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:18px}
.panel h2{font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:.8px;margin:0 0 12px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:7px 9px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;position:sticky;top:0;background:var(--panel)}
.scroll{max-height:360px;overflow:auto}
.badge{padding:2px 8px;border-radius:20px;font-size:11px;font-weight:700}
.critical{background:rgba(255,77,94,.15);color:var(--crit)}
.high{background:rgba(255,159,67,.15);color:var(--high)}
.medium{background:rgba(255,214,102,.15);color:var(--med)}
.low{background:rgba(110,231,183,.15);color:var(--low)}
input,select,button,textarea{background:#0e1521;color:var(--fg);border:1px solid var(--line);
border-radius:7px;padding:8px 10px;font:inherit}
button{cursor:pointer;background:var(--accent);color:#04101f;border:none;font-weight:700}
.row{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px}
textarea{width:100%;min-height:90px;resize:vertical}
.mono{color:var(--muted)}a{color:var(--accent)}
.hit{color:var(--crit);font-weight:700}.clean{color:var(--low)}
</style></head><body>
<header><span class="dot"></span><h1>ThreatMgr · SOC Threat-Intel Console</h1>
<span class="mono" id="clock"></span></header>
<div class="wrap">
  <div class="cards" id="cards"></div>

  <div class="panel"><h2>Proactive log scan</h2>
    <p class="mono">Paste firewall / proxy / DNS / auth log lines. Any contact with a known IOC raises an alert.</p>
    <textarea id="scanin" placeholder="2026-10-31 12:00:01 src=10.0.0.5 dst=185.220.101.1 ...&#10;GET http://malicious.example/payload.exe"></textarea>
    <div class="row" style="margin-top:10px"><button onclick="runScan()">Scan</button>
      <span id="scanres" class="mono"></span></div>
    <div id="scanout"></div>
  </div>

  <div class="panel"><h2>IOC search</h2>
    <div class="row">
      <input id="q" placeholder="search value / threat" style="flex:1;min-width:180px">
      <select id="type"><option value="">any type</option>
        <option>ip</option><option>cidr</option><option>domain</option>
        <option>url</option><option>md5</option><option>sha256</option><option>cve</option></select>
      <select id="sev"><option value="">any severity</option>
        <option>critical</option><option>high</option><option>medium</option><option>low</option></select>
      <button onclick="loadIocs()">Search</button>
    </div>
    <div class="scroll"><table><thead><tr><th>Value</th><th>Type</th><th>Threat</th>
      <th>Severity</th><th>Source</th><th>Conf</th></tr></thead><tbody id="iocs"></tbody></table></div>
  </div>

  <div class="panel"><h2>Open alerts</h2>
    <div class="scroll"><table><thead><tr><th>Time</th><th>Observable</th><th>Threat</th>
      <th>Severity</th><th>Source</th><th></th></tr></thead><tbody id="alerts"></tbody></table></div>
  </div>

  <div class="panel"><h2>Feed status</h2>
    <div class="scroll"><table><thead><tr><th>Feed</th><th>Status</th><th>IOCs</th>
      <th>Last run</th></tr></thead><tbody id="feeds"></tbody></table></div>
  </div>
</div>
<script>
const $=s=>document.querySelector(s), E=document.createElement.bind(document);
const fmt=t=>t?new Date(t*1000).toLocaleString():'never';
const badge=s=>`<span class="badge ${s}">${s||'?'}</span>`;
function esc(x){return (x==null?'':''+x).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}

async function j(u,o){const r=await fetch(u,o);return r.json();}

async function loadStats(){const s=await j('/api/stats');
  const c=$('#cards');c.innerHTML='';
  const items=[['Total IOCs',s.total_iocs],['Open alerts',s.open_alerts],
    ['Critical',(s.by_severity||{}).critical||0],['High',(s.by_severity||{}).high||0],
    ['IP/CIDR',((s.by_type||{}).ip||0)+((s.by_type||{}).cidr||0)],
    ['Domains',(s.by_type||{}).domain||0],['URLs',(s.by_type||{}).url||0],
    ['CVEs',(s.by_type||{}).cve||0]];
  items.forEach(([l,n])=>{const d=E('div');d.className='card';
    d.innerHTML=`<div class="n">${n}</div><div class="l">${l}</div>`;c.appendChild(d);});}

async function loadIocs(){const q=$('#q').value,t=$('#type').value,sv=$('#sev').value;
  const rows=await j(`/api/iocs?q=${encodeURIComponent(q)}&type=${t}&severity=${sv}&limit=300`);
  $('#iocs').innerHTML=rows.map(r=>`<tr><td>${esc(r.value)}</td><td>${r.ioc_type}</td>
    <td>${esc(r.threat)}</td><td>${badge(r.severity)}</td><td>${r.source}</td>
    <td>${r.confidence}</td></tr>`).join('')||'<tr><td colspan=6 class=mono>no matches</td></tr>';}

async function loadAlerts(){const rows=await j('/api/alerts?open=1');
  $('#alerts').innerHTML=rows.map(r=>`<tr><td class=mono>${fmt(r.ts)}</td>
    <td class=hit>${esc(r.observable)}</td><td>${esc(r.threat)}</td>
    <td>${badge(r.severity)}</td><td>${r.source}</td>
    <td><button onclick="ack(${r.id})">ack</button></td></tr>`).join('')
    ||'<tr><td colspan=6 class=clean>no open alerts</td></tr>';}

async function loadFeeds(){const rows=await j('/api/feeds');
  $('#feeds').innerHTML=rows.map(r=>{const ok=(r.last_status||'').startsWith('ok');
    return `<tr><td>${esc(r.name||r.id)}</td>
      <td class="${ok?'clean':'hit'}">${esc(r.last_status)}</td>
      <td>${r.last_count}</td><td class=mono>${fmt(r.last_run)}</td></tr>`;}).join('')
    ||'<tr><td colspan=4 class=mono>no feed runs yet — run the collector</td></tr>';}

async function runScan(){const lines=$('#scanin').value.split('\\n').filter(x=>x.trim());
  if(!lines.length)return;
  const res=await j('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({lines})});
  $('#scanres').textContent=`${res.lines_scanned} lines scanned · ${res.alert_count} alert(s)`;
  $('#scanout').innerHTML=res.alerts.length?('<table><thead><tr><th>Observable</th>
    <th>Threat</th><th>Severity</th><th>Source</th></tr></thead><tbody>'+
    res.alerts.map(a=>`<tr><td class=hit>${esc(a.observable)}</td><td>${esc(a.ioc.threat)}</td>
    <td>${badge(a.ioc.severity)}</td><td>${a.ioc.source}</td></tr>`).join('')+'</tbody></table>')
    :'<p class=clean>No matches against known threat intel.</p>';
  loadStats();loadAlerts();}

async function ack(id){await j('/api/ack',{method:'POST',headers:{'Content-Type':'application/json'},
  body:JSON.stringify({id})});loadAlerts();loadStats();}

function tick(){$('#clock').textContent=new Date().toLocaleString();}
function refresh(){loadStats();loadIocs();loadAlerts();loadFeeds();}
tick();setInterval(tick,1000);refresh();setInterval(refresh,30000);
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    store: Store = None  # set by factory

    def log_message(self, fmt, *args):  # quieter logging
        pass

    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _qs(self):
        return parse_qs(urlparse(self.path).query)

    def do_GET(self):
        path = urlparse(self.path).path
        q = self._qs()
        try:
            if path == "/":
                return self._send(200, DASHBOARD, "text/html; charset=utf-8")
            if path == "/api/stats":
                return self._send(200, self.store.stats())
            if path == "/api/iocs":
                return self._send(200, self.store.search(
                    q=q.get("q", [None])[0], ioc_type=q.get("type", [None])[0] or None,
                    severity=q.get("severity", [None])[0] or None,
                    source=q.get("source", [None])[0] or None,
                    limit=int(q.get("limit", [200])[0])))
            if path == "/api/feeds":
                return self._send(200, self.store.feeds())
            if path == "/api/alerts":
                return self._send(200, self.store.alerts(
                    only_open=q.get("open", ["0"])[0] == "1"))
            if path == "/api/lookup":
                val = q.get("value", [""])[0]
                return self._send(200, {"value": val,
                                        "hits": Matcher(self.store).check(val)})
            return self._send(404, {"error": "not found"})
        except Exception as e:
            return self._send(500, {"error": str(e)})

    def do_POST(self):
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length", 0))
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return self._send(400, {"error": "invalid json"})
        try:
            if path == "/api/scan":
                m = Matcher(self.store)
                return self._send(200, m.scan_lines(
                    payload.get("lines", []), source_label="console"))
            if path == "/api/ack":
                self.store.acknowledge(int(payload.get("id")))
                return self._send(200, {"ok": True})
            return self._send(404, {"error": "not found"})
        except Exception as e:
            return self._send(500, {"error": str(e)})


def serve(store: Store, host: str = "127.0.0.1", port: int = 8787):
    handler = type("BoundHandler", (Handler,), {"store": store})
    httpd = ThreadingHTTPServer((host, port), handler)
    print(f"[server] ThreatMgr console on http://{host}:{port}  (Ctrl-C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[server] stopped")
        httpd.server_close()
