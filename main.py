"""
PayWatch server — receives bKash/Nagad/Rocket SMS from the SIM phone,
parses TrxID + amount + sender, and serves a mobile dashboard so the
user can check from any other device whether a payment arrived.

Storage: Postgres (Supabase free tier) — records survive redeploys.
Retention: 2 months — purono data auto delete hoye jay.
"""
import os
import re
import hmac
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg
from psycopg.rows import dict_row
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBasic, HTTPBasicCredentials

BASE = Path(__file__).parent

# Load server/.env (local run). On Render, real env vars win.
_env_file = BASE / ".env"
if _env_file.exists():
    for line in _env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())

DATABASE_URL = os.environ.get("DATABASE_URL", "")

DEVICE_SECRET = os.environ.get("DEVICE_SECRET", "")
DASHBOARD_USER = os.environ.get("DASHBOARD_USER", "admin")
DASHBOARD_PASS = os.environ.get("DASHBOARD_PASS", "")

# Only these SMS senders are trusted (official bKash / Nagad / Rocket IDs).
ALLOWED_SENDERS = {"bkash", "16247", "nagad", "rocket", "16216"}

# 2 masher purono data auto delete
RETENTION_DAYS = 60

TRX_RE = re.compile(r"TrxID\s*[:\-]?\s*([A-Za-z0-9]{6,})", re.I)
AMT_RE = re.compile(r"Tk\.?\s*([\d,]+(?:\.\d{1,2})?)", re.I)
FROM_RE = re.compile(r"from\s*(01\d{9})", re.I)


def db():
    if not DATABASE_URL:
        raise HTTPException(status_code=500, detail="DATABASE_URL set koro")
    conn = psycopg.connect(DATABASE_URL, row_factory=dict_row)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS payments (
               trxid TEXT PRIMARY KEY,
               amount DOUBLE PRECISION,
               sender_number TEXT,
               sender_name TEXT,
               sms_body TEXT,
               received_at TEXT,
               created_at TIMESTAMPTZ DEFAULT now()
           )"""
    )
    return conn


def cleanup_old(conn):
    """2 masher purono record delete."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)
    with conn.cursor() as cur:
        cur.execute("DELETE FROM payments WHERE created_at < %s", (cutoff,))


@asynccontextmanager
async def lifespan(app):
    if DATABASE_URL:
        try:
            conn = db()
            cleanup_old(conn)
            conn.commit()
            conn.close()
        except Exception:
            pass
    yield


app = FastAPI(title="PayWatch", lifespan=lifespan)
(BASE / "static").mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
security = HTTPBasic()


def norm_sender(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


DHAKA = timezone(timedelta(hours=6))


def norm_time(raw):
    """Millis / ISO / purono string -> 'DD/MM/YYYY HH:MM' (Dhaka)."""
    if not raw:
        return datetime.now(DHAKA).strftime("%d/%m/%Y %H:%M")
    s = str(raw).strip()
    try:
        if re.fullmatch(r"\d{10,13}", s):
            ms = int(s)
            if len(s) == 10:
                ms *= 1000
            dt = datetime.fromtimestamp(ms / 1000, tz=timezone.utc).astimezone(DHAKA)
        else:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=DHAKA)
            else:
                dt = dt.astimezone(DHAKA)
        return dt.strftime("%d/%m/%Y %H:%M")
    except Exception:
        return s[:16]


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
    try:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO payments
                   (trxid, amount, sender_number, sender_name, sms_body, received_at)
                   VALUES (%s,%s,%s,%s,%s,%s)
                   ON CONFLICT (trxid) DO NOTHING""",
                (parsed["trxid"], parsed["amount"], parsed["sender_number"],
                 parsed["sender_name"], data.get("body", "")[:2000],
                 norm_time(data.get("received_at") or datetime.now().isoformat())),
            )
            cleanup_old(conn)
        conn.commit()
    finally:
        conn.close()
    return {"ok": True, "trxid": parsed["trxid"], "amount": parsed["amount"]}


@app.get("/api/verify")
def verify(trxid: str, user: str = Depends(check_dashboard)):
    """Check from any device: has this TrxID's payment arrived?"""
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM payments WHERE trxid = %s",
                        (trxid.strip().upper(),))
            row = cur.fetchone()
    finally:
        conn.close()
    if not row:
        return {"found": False, "trxid": trxid.strip().upper()}
    return {"found": True, "trxid": row["trxid"], "amount": row["amount"],
            "sender_number": row["sender_number"],
            "received_at": norm_time(row["received_at"])}


@app.get("/api/search_number")
def search_number(number: str, user: str = Depends(check_dashboard)):
    """Sender number diye khujo — full number ba sesh koyek digit."""
    digits = re.sub(r"\D", "", number or "")
    if len(digits) < 3:
        raise HTTPException(status_code=400, detail="kom kore 3 digit dao")
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT trxid, amount, sender_number, sender_name, received_at "
                "FROM payments WHERE sender_number LIKE %s "
                "ORDER BY created_at DESC LIMIT 50",
                (f"%{digits}%",))
            rows = cur.fetchall()
    finally:
        conn.close()
    for r in rows:
        r["received_at"] = norm_time(r.get("received_at"))
    return {"payments": rows}


@app.get("/api/latest")
def latest(limit: int = 50, user: str = Depends(check_dashboard)):
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT trxid, amount, sender_number, sender_name, received_at "
                "FROM payments ORDER BY created_at DESC LIMIT %s",
                (max(1, min(limit, 200)),))
            rows = cur.fetchall()
    finally:
        conn.close()
    for r in rows:
        r["received_at"] = norm_time(r.get("received_at"))
    return {"payments": rows}


@app.get("/api/stats")
def stats(user: str = Depends(check_dashboard)):
    """Ajker + mot hisab (Dhaka time)."""
    today = datetime.now(DHAKA).date().isoformat()
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) AS c, COALESCE(SUM(amount),0) AS s FROM payments "
                "WHERE (created_at AT TIME ZONE 'Asia/Dhaka')::date = %s::date",
                (today,))
            t = cur.fetchone()
            cur.execute("SELECT COUNT(*) AS c, COALESCE(SUM(amount),0) AS s FROM payments")
            tot = cur.fetchone()
    finally:
        conn.close()
    return {"today_count": t["c"], "today_amount": float(t["s"]),
            "total_count": tot["c"], "total_amount": float(tot["s"])}


@app.get("/api/daily")
def daily(user: str = Depends(check_dashboard)):
    """Kon date e koto payment / koto taka (Dhaka time)."""
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT (created_at AT TIME ZONE 'Asia/Dhaka')::date AS d, "
                "COUNT(*) AS c, COALESCE(SUM(amount),0) AS s FROM payments "
                "GROUP BY d ORDER BY d DESC LIMIT 60")
            rows = cur.fetchall()
    finally:
        conn.close()
    return {"days": [{"date": str(r["d"]), "count": r["c"], "amount": float(r["s"])}
                     for r in rows]}


@app.get("/api/monthly")
def monthly(month: str, user: str = Depends(check_dashboard)):
    """Month select kore oi masher hisab: month=YYYY-MM."""
    if not re.fullmatch(r"\d{4}-\d{2}", month or ""):
        raise HTTPException(status_code=400, detail="month YYYY-MM format e dao")
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) AS c, COALESCE(SUM(amount),0) AS s FROM payments "
                "WHERE to_char(created_at AT TIME ZONE 'Asia/Dhaka', 'YYYY-MM') = %s",
                (month,))
            t = cur.fetchone()
            cur.execute(
                "SELECT (created_at AT TIME ZONE 'Asia/Dhaka')::date AS d, "
                "COUNT(*) AS c, COALESCE(SUM(amount),0) AS s FROM payments "
                "WHERE to_char(created_at AT TIME ZONE 'Asia/Dhaka', 'YYYY-MM') = %s "
                "GROUP BY d ORDER BY d",
                (month,))
            rows = cur.fetchall()
    finally:
        conn.close()
    return {"month": month, "count": t["c"], "amount": float(t["s"]),
            "days": [{"date": str(r["d"]), "count": r["c"], "amount": float(r["s"])}
                     for r in rows]}



DASH_HTML = """<!DOCTYPE html>
<html lang="bn">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PayWatch — Dashboard</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--pink:#D12053;--bg:#F3F4F6;--card:#fff;--ink:#16181D;--mut:#8B8E98;--green:#1E9E57;--line:#ECECF0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Hind Siliguri",sans-serif;background:var(--bg);color:var(--ink);min-height:100vh}
.app{display:flex;min-height:100vh}
.side{width:230px;background:var(--card);border-right:1px solid var(--line);padding:26px 16px;display:flex;flex-direction:column;gap:4px;position:sticky;top:0;height:100vh}
.brand{display:flex;align-items:center;gap:12px;padding:2px 10px 22px}
.brand .mark{width:42px;height:42px;border-radius:13px;background:linear-gradient(135deg,var(--pink),#7E1236);display:flex;align-items:center;justify-content:center;color:#fff;font-size:24px;font-weight:800;box-shadow:0 6px 14px rgba(209,32,83,.35)}
.brand b{font-size:20px}
.brand small{display:block;font-size:11px;color:var(--mut);font-weight:400}
.nav{display:flex;flex-direction:column;gap:4px}
.nav a{display:flex;align-items:center;gap:12px;padding:12px 14px;border-radius:12px;color:#5A5E6A;text-decoration:none;font-size:15px;font-weight:500}
.nav a.on{background:#FDEAF0;color:var(--pink);font-weight:700}
.nav .ico{width:20px;text-align:center}
.side .foot{margin-top:auto;padding:12px;border-top:1px solid var(--line);font-size:13px;color:var(--mut);display:flex;align-items:center;gap:10px}
.avatar{width:34px;height:34px;border-radius:50%;background:linear-gradient(135deg,#D12053,#7E1236);color:#fff;display:flex;align-items:center;justify-content:center;font-weight:700;flex-shrink:0}
.main{flex:1;padding:30px 32px;max-width:1080px;width:100%}
.top{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:24px;flex-wrap:wrap;gap:10px}
.top h1{font-size:26px;font-weight:800}
.top p{color:var(--mut);font-size:14px;margin-top:4px}
.snd{border:1.5px solid var(--line);background:#fff;border-radius:999px;padding:9px 16px;font-size:13px;font-weight:700;cursor:pointer;color:var(--mut)}
.snd.on{border-color:var(--pink);color:var(--pink)}
.live{display:inline-flex;align-items:center;gap:8px;background:#fff;border:1px solid var(--line);border-radius:999px;padding:9px 16px;font-size:13px;font-weight:600}
.dot{width:9px;height:9px;border-radius:50%;background:var(--green);animation:pulse 1.6s infinite;display:inline-block}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(30,158,87,.5)}70%{box-shadow:0 0 0 8px rgba(30,158,87,0)}100%{box-shadow:0 0 0 0 rgba(30,158,87,0)}}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:22px}
.stat{background:var(--card);border-radius:18px;padding:20px;box-shadow:0 2px 10px rgba(20,20,40,.05);display:flex;gap:14px;align-items:center}
.stat .ic{width:48px;height:48px;border-radius:14px;display:flex;align-items:center;justify-content:center;font-size:22px;flex-shrink:0}
.stat small{color:var(--mut);font-size:13px}
.stat b{font-size:24px;display:block;margin-top:2px}
.stat .sub{font-size:12px;color:var(--mut)}
.card{background:var(--card);border-radius:18px;padding:22px;box-shadow:0 2px 10px rgba(20,20,40,.05);margin-bottom:22px}
.card h3{font-size:17px;margin-bottom:4px}
.card .hint{font-size:13px;color:var(--mut);margin-bottom:14px}
.tabs{display:flex;gap:8px;margin-bottom:14px}
.tabs button{border:0;background:#F0F1F4;color:#5A5E6A;padding:10px 18px;border-radius:999px;font-size:14px;font-weight:600;cursor:pointer}
.tabs button.on{background:var(--pink);color:#fff}
.searchrow{display:flex;gap:10px}
.searchrow input{flex:1;border:1.5px solid var(--line);border-radius:12px;padding:13px 15px;font-size:16px;outline:none;min-width:0}
.searchrow input:focus{border-color:var(--pink)}
.searchrow button{border:0;background:var(--pink);color:#fff;border-radius:12px;padding:0 26px;font-size:15px;font-weight:700;cursor:pointer}
.result{margin-top:16px}
.found{background:#EAF9F0;border:1px solid #BDE8CC;border-radius:14px;padding:16px;display:flex;gap:14px;align-items:center}
.found .tick{width:44px;height:44px;border-radius:50%;background:var(--green);color:#fff;display:flex;align-items:center;justify-content:center;font-size:22px;flex-shrink:0}
.notfound{background:#FDEEF2;border:1px solid #F6C9D6;border-radius:14px;padding:16px;display:flex;gap:14px;align-items:center}
.notfound .cross{width:44px;height:44px;border-radius:50%;background:var(--pink);color:#fff;display:flex;align-items:center;justify-content:center;font-size:20px;flex-shrink:0}
.result .amt{font-size:22px;font-weight:800}
.result .meta{font-size:13px;color:var(--mut);margin-top:4px;line-height:1.9}
table{width:100%;border-collapse:collapse;font-size:14px}
th{text-align:left;color:var(--mut);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.4px;padding:10px 8px;border-bottom:1px solid var(--line);white-space:nowrap}
td{padding:13px 8px;border-bottom:1px solid var(--line)}
tr:last-child td{border-bottom:0}
.pill{display:inline-block;background:#F0F1F4;border-radius:8px;padding:4px 10px;font-family:ui-monospace,monospace;font-size:13px;white-space:nowrap}
.amtcell{font-weight:700;white-space:nowrap}
.empty{color:var(--mut);text-align:center;padding:26px;font-size:14px}
.sec-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:6px}
.sec-head .tag{font-size:12px;color:var(--mut);display:flex;align-items:center;gap:6px}
@media(max-width:860px){
  .side{display:none}
  .main{padding:18px 14px}
  .stats{grid-template-columns:1fr 1fr}
  .searchrow{flex-direction:column}
  .searchrow button{padding:13px}
}
@media(max-width:520px){.stats{grid-template-columns:1fr 1fr}}
</style>
</head>
<body>
<div class="app">
  <aside class="side">
    <div class="brand"><div class="mark">৳</div><div><b>PayWatch</b><small>Payment tracker</small></div></div>
    <nav class="nav">
      <a href="#" class="on"><span class="ico">📊</span>Dashboard</a>
      <a href="#search"><span class="ico">🔍</span>Search</a>
      <a href="#recent"><span class="ico">🕘</span>Recent</a>
      <a href="#daily"><span class="ico">📅</span>Daily</a>
      <a href="#monthly"><span class="ico">🗓️</span>Monthly</a>
    </nav>
    <div class="foot"><div class="avatar">A</div><div>admin<br><small style="color:var(--green)">● online</small></div></div>
  </aside>
  <main class="main">
    <div class="top">
      <div><h1>Payment Dashboard</h1><p id="dateLine">—</p></div>
      <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
        <button id="soundBtn" class="snd on" onclick="toggleSound()">🔔 Sound ON</button>
        <div class="live"><span class="dot"></span> LIVE</div>
      </div>
    </div>

    <div class="stats">
      <div class="stat"><div class="ic" style="background:#EAF9F0">💰</div><div><small>Ajker Payment</small><b id="stToday">–</b><div class="sub">ta</div></div></div>
      <div class="stat"><div class="ic" style="background:#FDEAF0">৳</div><div><small>Ajker Amount</small><b id="stAmt">–</b><div class="sub">taka</div></div></div>
      <div class="stat"><div class="ic" style="background:#EEF2FF">📦</div><div><small>Mot Payment</small><b id="stTotal">–</b><div class="sub">ta</div></div></div>
      <div class="stat"><div class="ic" style="background:#FFF7E6">💵</div><div><small>Mot Amount</small><b id="stTotAmt">–</b><div class="sub">taka</div></div></div>
    </div>

    <div class="card" id="search">
      <h3>Payment khujo</h3>
      <div class="hint">TrxID ba sender number diye check koro</div>
      <div class="tabs">
        <button id="tabT" class="on" onclick="setTab('t')">TrxID</button>
        <button id="tabN" onclick="setTab('n')">Number</button>
      </div>
      <div class="searchrow">
        <input id="q" placeholder="TrxID likho — jemon 9HXK2LMN4P" autocomplete="off">
        <button onclick="doSearch()">Check</button>
      </div>
      <div class="result" id="res"></div>
    </div>

    <div class="card" id="daily">
      <div class="sec-head"><h3>Din onujayi hisab</h3><span class="tag">kon date e koto</span></div>
      <div style="overflow-x:auto"><table>
        <thead><tr><th>Date</th><th>Payment</th><th>Amount</th></tr></thead>
        <tbody id="dayRows"></tbody>
      </table></div>
      <div class="empty" id="dayEmpty" style="display:none">Ekhono kono hisab nai</div>
    </div>

    <div class="card" id="monthly">
      <h3>Masher hisab</h3>
      <div class="hint">Month select kore dekho oi mashe koto dhuklo</div>
      <div class="searchrow">
        <input type="month" id="mPick">
        <button onclick="loadMonthly()">Dekho</button>
      </div>
      <div class="result" id="mRes"></div>
    </div>

    <div class="card" id="recent">
      <div class="sec-head"><h3>Sesh payment gula</h3><span class="tag"><span class="dot"></span>auto refresh</span></div>
      <div style="overflow-x:auto"><table>
        <thead><tr><th>TrxID</th><th>Amount</th><th>Number</th><th>Time</th></tr></thead>
        <tbody id="rows"></tbody>
      </table></div>
      <div class="empty" id="emptyRow" style="display:none">Ekhono kono payment ashe nai</div>
    </div>
  </main>
</div>
<script>
let tab='t';
function setTab(x){
  tab=x;
  document.getElementById('tabT').className = x=='t'?'on':'';
  document.getElementById('tabN').className = x=='n'?'on':'';
  const q=document.getElementById('q');
  q.value='';
  q.placeholder = x=='t' ? 'TrxID likho — jemon 9HXK2LMN4P' : 'Full number ba sesh digit — jemon 45678';
  q.inputMode = x=='n' ? 'numeric' : 'text';
  document.getElementById('res').innerHTML='';
  q.focus();
}
function esc(s){return String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
async function doSearch(){
  const box=document.getElementById('res');
  if(tab=='t'){
    const t=document.getElementById('q').value.trim();
    if(!t) return;
    box.innerHTML='<div class="hint">Khujtese...</div>';
    const j=await (await fetch('/api/verify?trxid='+encodeURIComponent(t))).json();
    box.innerHTML = j.found ? foundCard(j) : notFound('“'+esc(j.trxid)+'” — payment pai nai');
  } else {
    const t=document.getElementById('q').value.replace(/\D/g,'');
    if(t.length<3){box.innerHTML=notFound('Kom kore 3 digit dao');return;}
    box.innerHTML='<div class="hint">Khujtese...</div>';
    const j=await (await fetch('/api/search_number?number='+encodeURIComponent(t))).json();
    if(!j.payments.length){box.innerHTML=notFound('Ei number theke payment pai nai');return;}
    box.innerHTML='<div class="found"><div class="tick">✓</div><div><div class="amt">'+j.payments.length+' ta payment paise</div><div class="meta">'+j.payments.slice(0,5).map(p=>'<span class="pill">'+esc(p.trxid)+'</span> '+fmtAmt(p.amount)+' Tk').join('<br>')+'</div></div></div>';
  }
}
function foundCard(j){
  return '<div class="found"><div class="tick">✓</div><div><div class="amt">'+fmtAmt(j.amount)+' Tk dhukse ✓</div><div class="meta"><span class="pill">'+esc(j.trxid)+'</span> &nbsp;'+esc(j.sender_number||'')+'<br>'+esc(j.received_at||'')+'</div></div></div>';
}
function notFound(msg){
  return '<div class="notfound"><div class="cross">✕</div><div><b>Payment pai nai</b><div class="meta">'+msg+'</div></div></div>';
}
function fmtAmt(a){return (a==null||a==='')?'–':Number(a).toLocaleString('en-US')}
function fmtDate(iso){const m=/^(\\d{4})-(\\d{2})-(\\d{2})$/.exec(iso||'');if(!m)return esc(iso);const M=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];return m[3]+' '+M[+m[2]-1]+' '+m[1];}
async function loadStats(){
  try{
    const j=await (await fetch('/api/stats')).json();
    document.getElementById('stToday').textContent=j.today_count;
    document.getElementById('stAmt').textContent=fmtAmt(j.today_amount);
    document.getElementById('stTotal').textContent=j.total_count;
    document.getElementById('stTotAmt').textContent=fmtAmt(j.total_amount);
  }catch(e){}
}
async function load(){
  try{
    const j=await (await fetch('/api/latest?limit=30')).json();
    const tb=document.getElementById('rows');
    document.getElementById('emptyRow').style.display=j.payments.length?'none':'block';
    tb.innerHTML=j.payments.map(p=>'<tr><td><span class="pill">'+esc(p.trxid)+'</span></td><td class="amtcell">'+fmtAmt(p.amount)+' Tk</td><td>'+esc(p.sender_number||'–')+'</td><td style="color:var(--mut)">'+esc(p.received_at)+'</td></tr>').join('');
    const top = j.payments.length ? j.payments[0].trxid : null;
    if(lastTopTrx !== null && top && top !== lastTopTrx){
      const np = j.payments.find(function(p){return p.trxid===top});
      if(np) notifyPayment(np);
    }
    lastTopTrx = top;
  }catch(e){}
}
document.getElementById('q').addEventListener('keydown',e=>{if(e.key==='Enter')doSearch()});
document.getElementById('dateLine').textContent=new Date().toLocaleDateString('en-GB',{weekday:'long',day:'numeric',month:'long',year:'numeric'});
async function loadDaily(){
  try{
    const j=await (await fetch('/api/daily')).json();
    const tb=document.getElementById('dayRows');
    document.getElementById('dayEmpty').style.display=j.days.length?'none':'block';
    tb.innerHTML=j.days.map(d=>'<tr><td>'+fmtDate(d.date)+'</td><td>'+d.count+' ta</td><td class="amtcell">'+fmtAmt(d.amount)+' Tk</td></tr>').join('');
  }catch(e){}
}
let soundOn = localStorage.getItem('pw_sound') !== 'off';
let lastTopTrx = null;
let audioEl = null;
function ensureAudio(){
  if(!audioEl){ audioEl = new Audio('/static/notify.mp3'); audioEl.preload='auto'; }
}
document.addEventListener('pointerdown', ensureAudio, {once:true});
function paintSoundBtn(){
  const b=document.getElementById('soundBtn');
  b.textContent = soundOn ? '🔔 Sound ON' : '🔕 Sound OFF';
  b.className = 'snd' + (soundOn ? ' on' : '');
}
function toggleSound(){
  soundOn = !soundOn;
  localStorage.setItem('pw_sound', soundOn ? 'on' : 'off');
  paintSoundBtn();
  if(soundOn){ ensureAudio(); audioEl.play().catch(function(){}); speak('Sound on'); }
}
function speak(t){
  try{
    if(!('speechSynthesis' in window)) return;
    speechSynthesis.cancel();
    const u = new SpeechSynthesisUtterance(t);
    u.lang='bn-BD'; u.rate=1;
    speechSynthesis.speak(u);
  }catch(e){}
}
function notifyPayment(p){
  if(!soundOn) return;
  ensureAudio();
  try{ audioEl.currentTime=0; audioEl.play().catch(function(){}); }catch(e){}
  speak('Payment eseche. ' + fmtAmt(p.amount) + ' taka.');
}
paintSoundBtn();
async function loadMonthly(){
  const m=document.getElementById('mPick').value;
  const box=document.getElementById('mRes');
  if(!m){box.innerHTML=notFound('Month select koro');return;}
  box.innerHTML='<div class="hint">Khujtese...</div>';
  const j=await (await fetch('/api/monthly?month='+encodeURIComponent(m))).json();
  const MN=['January','February','March','April','May','June','July','August','September','October','November','December'];
  const parts=m.split('-');
  let h='<div class="found"><div class="tick">\u09F3</div><div><div class="amt">'+fmtAmt(j.amount)+' Tk</div><div class="meta">'+MN[+parts[1]-1]+' '+parts[0]+' — '+j.count+' ta payment</div></div></div>';
  if(j.days.length){
    h+='<div style="overflow-x:auto;margin-top:12px"><table><thead><tr><th>Date</th><th>Payment</th><th>Amount</th></tr></thead><tbody>'+
       j.days.map(d=>'<tr><td>'+fmtDate(d.date)+'</td><td>'+d.count+' ta</td><td class="amtcell">'+fmtAmt(d.amount)+' Tk</td></tr>').join('')+
       '</tbody></table></div>';
  }
  box.innerHTML=h;
}
(function(){const d=new Date();document.getElementById('mPick').value=d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0');loadMonthly();})();
function refresh(){loadStats();load();loadDaily();}
refresh(); setInterval(refresh,15000);
</script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def dashboard(user: str = Depends(check_dashboard)):
    return DASH_HTML


@app.get("/api/health")
def health():
    return {"ok": True}
