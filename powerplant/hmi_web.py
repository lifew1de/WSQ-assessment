"""
Operator HMI for the turbine PLC -- a browser SCADA screen.

This process is a pure Modbus *client*: it owns no process state. It connects
to the PLC over Modbus TCP, polls the input registers / discrete inputs for
telemetry, and writes the holding registers when the operator presses a
button. The browser talks only to this server's small JSON API; the JSON API
talks only Modbus to the PLC -- the same separation you would find between a
real HMI panel and its controller.

Run the PLC first, then:  python -m powerplant.hmi_web
and open http://127.0.0.1:8080
"""

import argparse
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from pymodbus.client import ModbusTcpClient

from . import registers as R

# Which holding registers the HMI is allowed to write, and their safe range.
WRITABLE = {
    "master_run": (R.HR_MASTER_RUN, 0, 1),
    "throttle": (R.HR_THROTTLE, 0, 100),
    "breaker_close": (R.HR_BREAKER_CLOSE, 0, 1),
    "reset_trip": (R.HR_RESET_TRIP, 0, 1),
    "cooling_pump": (R.HR_COOLING_PUMP, 0, 1),
}


class PlcLink:
    """Thread-safe wrapper around a single Modbus client to the PLC."""

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self._lock = threading.Lock()
        self._client = ModbusTcpClient(host, port=port, timeout=1.0)

    def _ensure(self) -> bool:
        if not self._client.connected:
            return self._client.connect()
        return True

    def read_state(self) -> dict:
        with self._lock:
            if not self._ensure():
                return {"online": False}
            ir = self._client.read_input_registers(
                0, count=R.IR_COUNT, slave=R.UNIT_ID)
            di = self._client.read_discrete_inputs(
                0, count=R.DI_COUNT, slave=R.UNIT_ID)
            hr = self._client.read_holding_registers(
                0, count=R.HR_COUNT, slave=R.UNIT_ID)
            if ir.isError() or di.isError() or hr.isError():
                return {"online": False}
            b = di.bits
            return {
                "online": True,
                "rpm": ir.registers[R.IR_RPM],
                "temp_c": R.from_reg_x10(ir.registers[R.IR_TEMP]),
                "power_mw": R.from_reg_x10(ir.registers[R.IR_POWER]),
                "city_supplied": bool(ir.registers[R.IR_CITY_SUPPLIED]),
                "breaker_closed": bool(ir.registers[R.IR_BREAKER_STATE]),
                "turbine_state": ir.registers[R.IR_TURBINE_STATE],
                "freq_hz": R.from_reg_x10(ir.registers[R.IR_GRID_FREQ]),
                "steam_bar": R.from_reg_x10(ir.registers[R.IR_STEAM_PRESSURE]),
                "trip_active": bool(b[R.DI_TRIP_ACTIVE]),
                "alarm_overspeed": bool(b[R.DI_ALARM_OVERSPEED]),
                "alarm_overtemp": bool(b[R.DI_ALARM_OVERTEMP]),
                "warn_high_rpm": bool(b[R.DI_WARN_HIGH_RPM]),
                "warn_high_temp": bool(b[R.DI_WARN_HIGH_TEMP]),
                # echo back current commands so the UI reflects real setpoints
                "cmd_master_run": hr.registers[R.HR_MASTER_RUN],
                "cmd_throttle": hr.registers[R.HR_THROTTLE],
                "cmd_breaker": hr.registers[R.HR_BREAKER_CLOSE],
                "cmd_cooling": hr.registers[R.HR_COOLING_PUMP],
                # thresholds so the gauges can draw their danger zones
                "limits": {
                    "overspeed": 3300, "high_rpm": 3150, "sync": 2950,
                    "overtemp": 540, "high_temp": 500,
                },
            }

    def write_cmd(self, name: str, value: int) -> dict:
        if name not in WRITABLE:
            return {"ok": False, "error": f"unknown command '{name}'"}
        addr, lo, hi = WRITABLE[name]
        value = max(lo, min(hi, int(value)))
        with self._lock:
            if not self._ensure():
                return {"ok": False, "error": "PLC offline"}
            rr = self._client.write_register(addr, value, slave=R.UNIT_ID)
            if rr.isError():
                return {"ok": False, "error": "modbus write failed"}
        return {"ok": True, "name": name, "value": value}


def make_handler(link: PlcLink):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):  # keep the console quiet
            pass

        def _send(self, code, body, ctype="application/json"):
            data = body if isinstance(body, bytes) else body.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                self._send(200, INDEX_HTML, "text/html; charset=utf-8")
            elif self.path == "/api/state":
                self._send(200, json.dumps(link.read_state()))
            else:
                self._send(404, json.dumps({"error": "not found"}))

        def do_POST(self):
            if self.path != "/api/cmd":
                self._send(404, json.dumps({"error": "not found"}))
                return
            length = int(self.headers.get("Content-Length", 0))
            try:
                payload = json.loads(self.rfile.read(length) or b"{}")
                result = link.write_cmd(payload["name"], payload["value"])
            except (ValueError, KeyError) as exc:
                self._send(400, json.dumps({"ok": False, "error": str(exc)}))
                return
            self._send(200, json.dumps(result))

    return Handler


# --------------------------------------------------------------------------
# The HMI page: one self-contained HTML/CSS/JS document, served inline.
# --------------------------------------------------------------------------
INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Turbine HMI</title>
<style>
  :root{
    --bg:#0b1220; --panel:#131d31; --panel2:#0f1830; --line:#26344f;
    --txt:#e7eefc; --dim:#8aa0c6; --green:#2fd27a; --amber:#f5b942;
    --red:#ff5d5d; --blue:#49b6ff; --accent:#49b6ff;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--txt);
    font-family:"Segoe UI",system-ui,sans-serif;padding:16px}
  h1{font-size:18px;margin:0 0 2px;letter-spacing:.5px}
  .sub{color:var(--dim);font-size:12px;margin-bottom:14px}
  .grid{display:grid;gap:14px;grid-template-columns:repeat(12,1fr)}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:12px;
    padding:14px}
  .card h2{font-size:11px;text-transform:uppercase;letter-spacing:1px;
    color:var(--dim);margin:0 0 10px;font-weight:600}
  .span3{grid-column:span 3}.span4{grid-column:span 4}
  .span5{grid-column:span 5}.span6{grid-column:span 6}
  .span7{grid-column:span 7}.span12{grid-column:span 12}
  @media(max-width:860px){.grid>*{grid-column:span 12 !important}}
  .gauge{position:relative;width:100%;aspect-ratio:1/1;max-width:220px;margin:auto}
  .readout{font-variant-numeric:tabular-nums;font-weight:700}
  .stat{display:flex;justify-content:space-between;align-items:baseline;
    padding:7px 0;border-bottom:1px dashed var(--line)}
  .stat:last-child{border-bottom:none}
  .stat .v{font-size:20px;font-weight:700;font-variant-numeric:tabular-nums}
  .stat .u{color:var(--dim);font-size:11px;margin-left:4px}
  .lamp{display:inline-flex;align-items:center;gap:8px;font-size:13px;
    padding:8px 10px;border-radius:8px;background:var(--panel2);
    border:1px solid var(--line);width:100%}
  .dot{width:12px;height:12px;border-radius:50%;background:#394a6b;flex:0 0 auto}
  .dot.on-g{background:var(--green);box-shadow:0 0 10px var(--green)}
  .dot.on-a{background:var(--amber);box-shadow:0 0 10px var(--amber)}
  .dot.on-r{background:var(--red);box-shadow:0 0 12px var(--red)}
  .lamps{display:grid;gap:8px}
  button{font:inherit;color:var(--txt);background:var(--panel2);cursor:pointer;
    border:1px solid var(--line);border-radius:9px;padding:11px 12px;width:100%}
  button:hover{border-color:var(--accent)}
  button.active{background:var(--green);color:#05240f;border-color:var(--green);
    font-weight:700}
  button.danger{background:var(--red);color:#2a0000;border-color:var(--red);
    font-weight:700}
  button.on{background:var(--blue);color:#001b2e;border-color:var(--blue);
    font-weight:700}
  .row2{display:grid;grid-template-columns:1fr 1fr;gap:8px}
  label.fld{display:block;color:var(--dim);font-size:12px;margin:12px 0 6px}
  input[type=range]{width:100%;accent-color:var(--accent)}
  .thr{display:flex;align-items:baseline;gap:6px}
  .thr b{font-size:26px}
  .banner{grid-column:span 12;border-radius:12px;padding:12px 16px;font-weight:700;
    display:none;align-items:center;gap:10px;letter-spacing:.5px}
  .banner.trip{display:flex;background:#3a0d0d;border:1px solid var(--red);
    color:#ffd4d4;animation:pulse 1s infinite}
  .banner.warn{display:flex;background:#3a2e07;border:1px solid var(--amber);
    color:#ffe9b0}
  @keyframes pulse{50%{opacity:.55}}
  /* city skyline */
  .city{display:flex;align-items:flex-end;gap:6px;height:120px;padding:10px;
    background:linear-gradient(#0a1428,#0e1c38);border-radius:10px;overflow:hidden}
  .bldg{flex:1;border-radius:3px 3px 0 0;position:relative;
    background:#17233d;transition:background .4s}
  .bldg .win{position:absolute;inset:6px;display:grid;gap:3px;
    grid-template-columns:repeat(3,1fr);grid-auto-rows:6px}
  .bldg .win i{background:#223150;border-radius:1px;transition:background .3s}
  .city.live .bldg .win i{background:var(--amber);box-shadow:0 0 4px var(--amber)}
  .offline{color:var(--red);font-size:12px}
  svg text{fill:var(--txt)}
</style>
</head>
<body>
  <h1>CITY POWER STATION &mdash; TURBINE HMI</h1>
  <div class="sub">Modbus/TCP operator station &middot; <span id="conn" class="offline">connecting&hellip;</span></div>

  <div class="grid">
    <div id="banner" class="banner"></div>

    <!-- Turbine speed gauge -->
    <div class="card span4">
      <h2>Turbine Speed</h2>
      <div class="gauge"><svg id="rpmgauge" viewBox="0 0 200 200"></svg></div>
    </div>

    <!-- Temperature gauge -->
    <div class="card span4">
      <h2>Metal Temperature</h2>
      <div class="gauge"><svg id="tempgauge" viewBox="0 0 200 200"></svg></div>
    </div>

    <!-- Live stats -->
    <div class="card span4">
      <h2>Generation</h2>
      <div class="stat"><span>Power to grid</span><span><span id="power" class="v">0.0</span><span class="u">MW</span></span></div>
      <div class="stat"><span>Grid frequency</span><span><span id="freq" class="v">0.0</span><span class="u">Hz</span></span></div>
      <div class="stat"><span>Steam pressure</span><span><span id="steam" class="v">0.0</span><span class="u">bar</span></span></div>
      <div class="stat"><span>Turbine state</span><span id="tstate" class="v">&mdash;</span></div>
    </div>

    <!-- Cityscape -->
    <div class="card span7">
      <h2>Cityscape &mdash; <span id="cityword">OFFLINE</span></h2>
      <div id="city" class="city"></div>
    </div>

    <!-- Alarm lamps -->
    <div class="card span5">
      <h2>Alarms &amp; Interlocks</h2>
      <div class="lamps">
        <span class="lamp"><span id="l-trip" class="dot"></span>Emergency Trip</span>
        <span class="lamp"><span id="l-osp" class="dot"></span>Overspeed Trip</span>
        <span class="lamp"><span id="l-otemp" class="dot"></span>Over-temperature Trip</span>
        <span class="lamp"><span id="l-wrpm" class="dot"></span>High-speed Warning</span>
        <span class="lamp"><span id="l-wtemp" class="dot"></span>High-temperature Warning</span>
      </div>
    </div>

    <!-- Controls -->
    <div class="card span12">
      <h2>Operator Controls</h2>
      <div class="grid">
        <div class="span4">
          <div class="row2">
            <button id="btn-run" onclick="toggle('master_run')">START</button>
            <button id="btn-stop" onclick="cmd('master_run',0)">STOP</button>
          </div>
          <label class="fld">Steam throttle demand</label>
          <div class="thr"><b id="thrval">0</b><span class="u">%</span></div>
          <input id="throttle" type="range" min="0" max="100" value="0"
                 oninput="thrval.textContent=this.value"
                 onchange="cmd('throttle',+this.value)">
        </div>
        <div class="span4">
          <label class="fld">Generator breaker (connect to city)</label>
          <button id="btn-brk" onclick="toggle('breaker_close')">CLOSE BREAKER</button>
          <label class="fld">Condenser cooling pump</label>
          <button id="btn-cool" onclick="toggle('cooling_pump')">COOLING PUMP</button>
        </div>
        <div class="span4">
          <label class="fld">Emergency</label>
          <button class="danger" onclick="cmd('reset_trip',1)">ACKNOWLEDGE &amp; RESET TRIP</button>
          <p class="sub" style="margin-top:12px">A trip latches: steam is cut and
          the breaker opened automatically. Reset only clears once the plant has
          coasted back into a safe envelope.</p>
        </div>
      </div>
    </div>
  </div>

<script>
const $ = id => document.getElementById(id);
let cur = {};   // latest state

async function cmd(name, value){
  await fetch('/api/cmd',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({name,value})});
  poll();
}
function toggle(name){
  const map={master_run:'cmd_master_run',breaker_close:'cmd_breaker',cooling_pump:'cmd_cooling'};
  const now = cur[map[name]] ? 1 : 0;
  cmd(name, now ? 0 : 1);
}

// Build a 270-degree arc gauge with a danger band and a needle.
function gauge(svgId, value, min, max, bands, label, unit){
  const svg=$(svgId); const cx=100,cy=105,r=78;
  const a0=135, a1=135+270;               // start/end angles (deg)
  const pol=(ang)=>{const t=(ang-90)*Math.PI/180;return[cx+r*Math.cos(t),cy+r*Math.sin(t)];};
  const arc=(s,e,col,w)=>{const[x0,y0]=pol(s),[x1,y1]=pol(e);
    const big=(e-s)>180?1:0;
    return `<path d="M${x0} ${y0} A${r} ${r} 0 ${big} 1 ${x1} ${y1}"
      fill="none" stroke="${col}" stroke-width="${w}" stroke-linecap="round"/>`;};
  const val2a=v=>a0+(Math.max(min,Math.min(max,v))-min)/(max-min)*(a1-a0);
  let s=`<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="#1d2a44" stroke-width="12"/>`;
  // colour bands: [frac_start,frac_end,colour]
  bands.forEach(b=>{s+=arc(a0+b[0]*(a1-a0), a0+b[1]*(a1-a0), b[2], 12);});
  // needle
  const na=val2a(value); const[nx,ny]=((ang)=>{const t=(ang-90)*Math.PI/180;
    return[cx+(r-14)*Math.cos(t),cy+(r-14)*Math.sin(t)];})(na);
  s+=`<line x1="${cx}" y1="${cy}" x2="${nx}" y2="${ny}" stroke="#fff" stroke-width="3"/>`;
  s+=`<circle cx="${cx}" cy="${cy}" r="5" fill="#fff"/>`;
  s+=`<text x="${cx}" y="150" text-anchor="middle" font-size="30" font-weight="700"
      class="readout">${Math.round(value)}</text>`;
  s+=`<text x="${cx}" y="170" text-anchor="middle" font-size="11" fill="#8aa0c6">${label} (${unit})</text>`;
  svg.innerHTML=s;
}

function setLamp(id, on, cls){ const d=$(id); d.className='dot'+(on?(' '+cls):''); }

function buildCity(){
  const c=$('city'); if(c.children.length) return;
  const hs=[70,95,55,110,80,60,100,75,90,65];
  c.innerHTML=hs.map(h=>`<div class="bldg" style="height:${h}px">
    <div class="win">${'<i></i>'.repeat(Math.floor(h/12)*3)}</div></div>`).join('');
}

function render(d){
  if(!d.online){ $('conn').textContent='PLC OFFLINE — start plc_server';
    $('conn').className='offline'; return; }
  cur=d;
  $('conn').textContent='online'; $('conn').className='';
  $('conn').style.color='var(--green)';

  const L=d.limits;
  gauge('rpmgauge', d.rpm, 0, 3600,
    [[0, L.sync/3600, '#2fd27a'],
     [L.sync/3600, L.high_rpm/3600, '#49b6ff'],
     [L.high_rpm/3600, L.overspeed/3600, '#f5b942'],
     [L.overspeed/3600, 1, '#ff5d5d']], 'RPM', 'rev/min');
  gauge('tempgauge', d.temp_c, 0, 600,
    [[0, L.high_temp/600, '#2fd27a'],
     [L.high_temp/600, L.overtemp/600, '#f5b942'],
     [L.overtemp/600, 1, '#ff5d5d']], 'TEMP', '°C');

  $('power').textContent=d.power_mw.toFixed(1);
  $('freq').textContent=d.freq_hz.toFixed(1);
  $('steam').textContent=d.steam_bar.toFixed(1);
  $('tstate').textContent=['STOPPED','RUNNING','TRIPPED'][d.turbine_state]||'—';
  $('tstate').style.color=d.turbine_state==2?'var(--red)':
    (d.turbine_state==1?'var(--green)':'var(--dim)');

  setLamp('l-trip', d.trip_active, 'on-r');
  setLamp('l-osp', d.alarm_overspeed, 'on-r');
  setLamp('l-otemp', d.alarm_overtemp, 'on-r');
  setLamp('l-wrpm', d.warn_high_rpm, 'on-a');
  setLamp('l-wtemp', d.warn_high_temp, 'on-a');

  // city skyline
  const city=$('city');
  city.className='city'+(d.city_supplied?' live':'');
  $('cityword').textContent=d.city_supplied?'ENERGISED':'DARK';

  // banner
  const b=$('banner');
  if(d.trip_active){ b.className='banner trip';
    b.innerHTML='⛔ EMERGENCY TRIP — '+
      (d.alarm_overspeed?'OVERSPEED':d.alarm_overtemp?'OVER-TEMPERATURE':'SAFETY')+
      ' — steam cut, breaker open. Acknowledge to reset.';
  } else if(d.warn_high_rpm||d.warn_high_temp){ b.className='banner warn';
    b.innerHTML='⚠ WARNING — '+[d.warn_high_rpm?'high speed':'',
      d.warn_high_temp?'high temperature':''].filter(Boolean).join(' & ')+
      ' approaching trip limit.';
  } else { b.className='banner'; }

  // reflect command state on buttons
  $('btn-run').classList.toggle('active', !!d.cmd_master_run);
  $('btn-brk').classList.toggle('on', !!d.cmd_breaker);
  $('btn-brk').textContent=d.cmd_breaker?'OPEN BREAKER':'CLOSE BREAKER';
  $('btn-cool').classList.toggle('on', !!d.cmd_cooling);
  const t=$('throttle');
  if(document.activeElement!==t){ t.value=d.cmd_throttle; $('thrval').textContent=d.cmd_throttle; }
}

async function poll(){
  try{ const r=await fetch('/api/state'); render(await r.json()); }
  catch(e){ $('conn').textContent='HMI link error'; $('conn').className='offline'; }
}
buildCity();
setInterval(poll, 500); poll();
</script>
</body>
</html>"""


def main() -> None:
    ap = argparse.ArgumentParser(description="Turbine HMI (web SCADA + Modbus client)")
    ap.add_argument("--plc-host", default=R.PLC_HOST)
    ap.add_argument("--plc-port", type=int, default=R.PLC_PORT)
    ap.add_argument("--http-host", default="127.0.0.1")
    ap.add_argument("--http-port", type=int, default=8080)
    args = ap.parse_args()

    link = PlcLink(args.plc_host, args.plc_port)
    httpd = ThreadingHTTPServer((args.http_host, args.http_port),
                                make_handler(link))
    print(f"HMI serving at http://{args.http_host}:{args.http_port}  "
          f"(PLC {args.plc_host}:{args.plc_port})")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nHMI stopped")


if __name__ == "__main__":
    main()
