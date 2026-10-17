"""
PayWatch server — receives bKash/Nagad/Rocket SMS from the SIM phone,
parses TrxID + amount + sender, and serves a mobile dashboard so the
user can check from any other device whether a payment arrived.
"""
import os
import re
import hmac
import sqlite3
import html as html_lib
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

BASE = Path(__file__).parent

# Load server/.env (local run). On Cloud Run, real env vars win.
_env_file = BASE / ".env"
if _env_file.exists():
    for line in _env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())

DB_PATH = os.environ.get("DB_PATH", str(BASE / "payments.db"))

DEVICE_SECRET = os.environ.get("DEVICE_SECRET", "")
DASHBOARD_USER = os.environ.get("DASHBOARD_USER", "admin")
DASHBOARD_PASS = os.environ.get("DASHBOARD_PASS", "")

# Only these SMS senders are trusted (official bKash / Nagad / Rocket IDs).
ALLOWED_SENDERS = {"bkash", "16247", "nagad", "rocket", "16216"}

TRX_RE = re.compile(r"TrxID\s*[:\-]?\s*([A-Za-z0-9]{6,})", re.I)
AMT_RE = re.compile(r"Tk\.?\s*([\d,]+(?:\.\d{1,2})?)", re.I)
FROM_RE = re.compile(r"from\s*(01\d{9})", re.I)

app = FastAPI(title="PayWatch")
security = HTTPBasic()


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """CREATE TABLE IF NOT EXISTS payments (
               trxid TEXT PRIMARY KEY,
               amount REAL,
               sender_number TEXT,
               sender_name TEXT,
               sms_body TEXT,
               received_at TEXT,
               created_at TEXT DEFAULT (datetime('now'))
           )"""
    )
    return conn


def norm_sender(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def parse_sms(sender: str, body: str):
    trx = TRX_RE.search(body or "")
    amt = AMT_RE.search(body or "")
    frm = FROM_RE.search(body or "")
    return {
        "trxid": trx.group(1).upper() if trx else None,
        "amount": float(amt.group(1).replace(",", "")) if amt else None,
        "sender_number": frm.group(1) if frm else None,
        "sender_name": sender,
    }


def check_dashboard(creds: HTTPBasicCredentials = Depends(security)):
    ok_user = hmac.compare_digest(creds.username, DASHBOARD_USER)
    ok_pass = hmac.compare_digest(creds.password, DASHBOARD_PASS)
    if not (ok_user and ok_pass):
        raise HTTPException(status_code=401, detail="Login dorkar",
                            headers={"WWW-Authenticate": "Basic"})
    return creds.username


@app.post("/api/ingest")
async def ingest(req: Request):
    """Called by the Android app on the SIM phone for each transaction SMS."""
    data = await req.json()
    secret = data.get("secret", "")
    if not DEVICE_SECRET or not hmac.compare_digest(str(secret), DEVICE_SECRET):
        raise HTTPException(status_code=403, detail="wrong secret")

    sender = norm_sender(data.get("sender", ""))
    if sender not in ALLOWED_SENDERS:
        return {"ok": False, "reason": "sender not trusted"}

    parsed = parse_sms(data.get("sender", ""), data.get("body", ""))
    if not parsed["trxid"]:
        return {"ok": False, "reason": "no trxid found"}

    conn = db()
    conn.execute(
        """INSERT OR IGNORE INTO payments
           (trxid, amount, sender_number, sender_name, sms_body, received_at)
           VALUES (?,?,?,?,?,?)""",
        (parsed["trxid"], parsed["amount"], parsed["sender_number"],
         parsed["sender_name"], data.get("body", "")[:2000],
         data.get("received_at") or datetime.now().isoformat()),
    )
    conn.commit()
    conn.close()
    return {"ok": True, "trxid": parsed["trxid"], "amount": parsed["amount"]}


@app.get("/api/verify")
def verify(trxid: str, user: str = Depends(check_dashboard)):
    """Check from any device: has this TrxID's payment arrived?"""
    conn = db()
    row = conn.execute("SELECT * FROM payments WHERE trxid = ?",
                       (trxid.strip().upper(),)).fetchone()
    conn.close()
    if not row:
        return {"found": False, "trxid": trxid.strip().upper()}
    return {"found": True, "trxid": row["trxid"], "amount": row["amount"],
            "sender_number": row["sender_number"],
            "received_at": row["received_at"]}


@app.get("/api/search_number")
def search_number(number: str, user: str = Depends(check_dashboard)):
    """Sender number diye khujo — full number ba sesh koyek digit."""
    digits = re.sub(r"\D", "", number or "")
    if len(digits) < 3:
        raise HTTPException(status_code=400, detail="kom kore 3 digit dao")
    conn = db()
    rows = conn.execute(
        "SELECT trxid, amount, sender_number, sender_name, received_at "
        "FROM payments WHERE sender_number LIKE ? "
        "ORDER BY created_at DESC LIMIT 50",
        (f"%{digits}%",)).fetchall()
    conn.close()
    return {"payments": [dict(r) for r in rows]}


@app.get("/api/latest")
def latest(limit: int = 50, user: str = Depends(check_dashboard)):
    conn = db()
    rows = conn.execute(
        "SELECT trxid, amount, sender_number, sender_name, received_at "
        "FROM payments ORDER BY created_at DESC LIMIT ?",
        (max(1, min(limit, 200)),)).fetchall()
    conn.close()
    return {"payments": [dict(r) for r in rows]}


DASH_HTML = """<!DOCTYPE html><html lang="bn"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PayWatch — Payment Check</title>
<style>
body{font-family:system-ui,sans-serif;margin:0;padding:12px;background:#f4f4f4}
h2{margin:6px 0}.box{background:#fff;border-radius:10px;padding:12px;margin:10px 0}
input{width:100%;padding:12px;font-size:17px;border:1px solid #ccc;border-radius:8px;box-sizing:border-box}
button{width:100%;padding:12px;font-size:17px;margin-top:8px;border:0;border-radius:8px;background:#d12053;color:#fff}
table{width:100%;border-collapse:collapse;font-size:14px}
td,th{border-bottom:1px solid #eee;padding:8px 4px;text-align:left}
.ok{color:green;font-weight:bold}.no{color:#d12053;font-weight:bold}
.small{font-size:12px;color:#666}
</style></head><body>
<h2>&#128176; PayWatch</h2>
<div class="box">
<input id="q" placeholder="TrxID likho (jemon: 9HXK2LMN4P)" autocomplete="off">
<button onclick="check()">Check koro</button>
<div id="res" style="margin-top:10px;font-size:18px"></div>
</div>
<div class="box">
<b>Number diye khujo</b>
<input id="n" placeholder="Full number ba sesh koyek digit (jemon: 45678)" inputmode="numeric" autocomplete="off">
<button onclick="searchNum()">Number diye khujo</button>
<div id="nres" style="margin-top:10px"></div>
</div>
<div class="box"><b>Sesh payment gula</b> <span class="small">(auto refresh)</span>
<table><thead><tr><th>TrxID</th><th>Tk</th><th>Number</th><th>Time</th></tr></thead>
<tbody id="rows"></tbody></table></div>
<script>
async function check(){
  const t=document.getElementById('q').value.trim();
  if(!t) return;
  const r=await fetch('/api/verify?trxid='+encodeURIComponent(t));
  const j=await r.json();
  document.getElementById('res').innerHTML = j.found
    ? '<span class="ok">&#10003; TK DHUKSE</span> — '+j.trxid+' : '+j.amount+' Tk<br><span class="small">'+(j.sender_number||'')+' | '+j.received_at+'</span>'
    : '<span class="no">&#10007; PAYMENT PAI NAI</span> — '+j.trxid;
}
async function searchNum(){
  const t=document.getElementById('n').value.replace(/\D/g,'');
  const box=document.getElementById('nres');
  if(t.length<3){box.innerHTML='<span class="no">Kom kore 3 digit dao</span>';return;}
  box.innerHTML='<span class="small">Khujtese...</span>';
  const r=await fetch('/api/search_number?number='+encodeURIComponent(t));
  const j=await r.json();
  if(!j.payments.length){box.innerHTML='<span class="no">&#10007; EI NUMBER THEKE PAYMENT PAI NAI</span>';return;}
  box.innerHTML='<span class="ok">&#10003; '+j.payments.length+' ta payment paise</span><table>'+
    j.payments.map(p=>'<tr><td>'+p.trxid+'</td><td>'+(p.amount??'')+' Tk</td><td>'+(p.sender_number||'')+'</td><td class="small">'+(p.received_at||'').slice(5,16)+'</td></tr>').join('')+'</table>';
}
async function load(){
  const r=await fetch('/api/latest?limit=30'); const j=await r.json();
  document.getElementById('rows').innerHTML=j.payments.map(p=>
    '<tr><td>'+p.trxid+'</td><td>'+(p.amount??'')+'</td><td>'+(p.sender_number||'')+'</td><td class="small">'+(p.received_at||'').slice(5,16)+'</td></tr>').join('');
}
load(); setInterval(load,15000);
</script></body></html>"""


@app.get("/", response_class=HTMLResponse)
def dashboard(user: str = Depends(check_dashboard)):
    return DASH_HTML


@app.get("/api/health")
def health():
    return {"ok": True}
