import os, glob, subprocess, datetime, re, time, shlex, json, ipaddress, urllib.request, urllib.parse, threading, secrets as _secrets
from typing import Tuple, Dict, Any, List
import logging
from flask import Flask, render_template, request, redirect, url_for, jsonify, abort, Response, stream_with_context, session
from werkzeug.security import check_password_hash, generate_password_hash

APP_PORT=int(os.environ.get("APP_PORT","8088"))
WG_IFACE=os.environ.get("WG_IFACE","wg0")
WG_DIR=os.environ.get("WG_DIR","/etc/wireguard")
WG_CONF=os.environ.get("WG_CONF",f"/etc/wireguard/{WG_IFACE}.conf")
WG_PORT=int(os.environ.get("WG_PORT","51820"))
SERVER_ADDR_ENV=os.environ.get("SERVER_ADDR","10.8.0.1/24")
CLIENT_DNS=os.environ.get("CLIENT_DNS","1.1.1.1, 1.0.0.1")
HOST_IP=subprocess.check_output(["bash","-lc","hostname -I | awk '{print $1}'"]).decode().strip()
UNIT=f"wg-quick@{WG_IFACE}"

def _detect_public_ip() -> Tuple[str, str]:
    """Return (ip, source) so the UI can show where the address came from."""
    if os.environ.get("SERVER_PUBLIC_IP"):
        return os.environ["SERVER_PUBLIC_IP"].strip(), "SERVER_PUBLIC_IP override"
    for url in ("https://api.ipify.org","https://ifconfig.me/ip","https://icanhazip.com"):
        try:
            ip = urllib.request.urlopen(url, timeout=4).read().decode().strip()
            return ip, url.split("//", 1)[1].split("/", 1)[0]
        except Exception:
            continue
    return HOST_IP, "local interface (no lookup service reachable)"

_public_ip_cache = {"ts": 0.0, "ip": "", "src": ""}

def _public_ip_info(max_age: float = 60.0) -> Tuple[str, str]:
    if _public_ip_cache["ip"] and time.time() - _public_ip_cache["ts"] < max_age:
        return _public_ip_cache["ip"], _public_ip_cache["src"]
    ip, src = _detect_public_ip()
    _public_ip_cache.update(ts=time.time(), ip=ip, src=src)
    return ip, src

def _current_public_ip(max_age: float = 60.0) -> str:
    return _public_ip_info(max_age)[0]

PEERS_DB=os.path.join(WG_DIR,"peers.json")
DYNDNS_DB=os.environ.get("DYNDNS_DB", os.path.join(WG_DIR, "dyndns.json"))

def _load_dyndns() -> dict:
    _default = {"mode": "static", "hostname": "", "provider": None, "token": "", "domain": "", "custom_url": ""}
    content = ""
    try:
        with open(DYNDNS_DB) as f:
            content = f.read()
    except FileNotFoundError:
        return _default
    except PermissionError:
        out, rc = _sudo_cat(DYNDNS_DB)
        if rc != 0 or not out:
            return _default
        content = out
    except Exception:
        return _default
    try:
        data = json.loads(content)
        return {**_default, **data}
    except Exception:
        return _default

def _save_dyndns(data: dict) -> None:
    import tempfile
    fd, tmp_path = tempfile.mkstemp(prefix="dyndns.", suffix=".json.tmp", dir="/tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
        try:
            os.makedirs(os.path.dirname(DYNDNS_DB), exist_ok=True)
            os.replace(tmp_path, DYNDNS_DB)
            return
        except Exception:
            pass
        out, rc = _sudo(["/usr/bin/install", "-m", "640", "-o", "root", "-g", "www-data", tmp_path, DYNDNS_DB])
        if rc != 0:
            raise PermissionError(f"Could not write {DYNDNS_DB}: {out}")
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass

def _get_endpoint_host() -> str:
    cfg = _load_dyndns()
    if cfg.get("mode") == "dyndns" and cfg.get("hostname", "").strip():
        return cfg["hostname"].strip()
    return _current_public_ip()
WELCOME_FLAG=os.path.join(WG_DIR,"welcomed.flag")
_WELCOME_FLAG_FALLBACK=os.path.join(os.path.dirname(__file__),".welcomed")
DATA_BUDGET_DB=os.environ.get("DATA_BUDGET_DB", os.path.join(WG_DIR, "data_budget.json"))
TRAFFIC_HISTORY=os.environ.get("TRAFFIC_HISTORY", os.path.join(WG_DIR, "traffic_history.json"))
TRAFFIC_RETENTION_SECONDS=24*60*60
TRAFFIC_FLUSH_SECONDS=10
PEER_SPARK_HISTORY=os.environ.get("PEER_SPARK_HISTORY", os.path.join(WG_DIR, "peer_spark_history.json"))
PEER_SPARK_RETENTION_SECONDS=60
PEER_THROUGHPUT_RETENTION_SECONDS=2*60
PEER_SPARK_FLUSH_SECONDS=10
HANDSHAKE_CACHE=os.environ.get("HANDSHAKE_CACHE", os.path.join(WG_DIR, "handshakes.json"))
HANDSHAKE_FLUSH_SECONDS=30
DNS_STATS_DB=os.environ.get("DNS_STATS_DB", os.path.join(WG_DIR, "dns_stats.json"))
DNS_STATS_RETENTION_SECONDS=24*60*60
DNS_STATS_FLUSH_SECONDS=15
DNS_MONITOR_LOCK=os.environ.get("DNS_MONITOR_LOCK", "/tmp/wg-dashboard-dns.lock")
_dns_stats_lock=threading.Lock()
UPTIME_DB=os.environ.get("UPTIME_DB", os.path.join(WG_DIR, "uptime_history.json"))
UPTIME_RETENTION_SECONDS=90*24*60*60
UPTIME_SAMPLE_INTERVAL=max(5, int(os.environ.get("UPTIME_SAMPLE_INTERVAL", "30")))
UPTIME_GAP_SECONDS=3*UPTIME_SAMPLE_INTERVAL
UPTIME_FLUSH_SECONDS=60
NET_PING_TARGETS=[t.strip() for t in os.environ.get("NET_PING_TARGETS", "1.1.1.1,8.8.8.8").split(",") if t.strip()]
NET_LATENCY_RETENTION_SECONDS=24*60*60
_PING_WAIT_FLAG="-W2000" if os.uname().sysname == "Darwin" else "-W2"
_uptime_lock=threading.Lock()
PEER_WATCH_HS_TIMEOUT=int(os.environ.get("PEER_WATCH_HS_TIMEOUT", "130"))
PEER_WATCH_INTERVAL=max(10, int(os.environ.get("PEER_WATCH_INTERVAL", "30")))
_peer_watch_lock=threading.Lock()
_peer_watch_state: Dict[str, Dict[str, Any]] = {}
GEO_CACHE_SECONDS=6*60*60
SUDO_BIN=os.environ.get("SUDO_BIN","/usr/bin/sudo")
BASH_BIN=os.environ.get("BASH_BIN","/bin/bash")
TC_BIN=os.environ.get("TC_BIN","/usr/sbin/tc")
IPTABLES_BIN=os.environ.get("IPTABLES_BIN","/usr/sbin/iptables")
_PASSWORD_HASH_FILE = os.path.join(WG_DIR, ".dashboard_password_hash")

def _load_password_hash() -> str:
    if h := os.environ.get("DASHBOARD_PASSWORD_HASH", ""):
        return h
    for _path in (_PASSWORD_HASH_FILE, os.path.join(os.path.dirname(__file__), ".dashboard_password_hash")):
        try:
            with open(_path) as _f:
                h = _f.read().strip()
                if h:
                    return h
        except Exception:
            pass
    return ""

DASHBOARD_PASSWORD_HASH = _load_password_hash()

app=Flask(__name__)

def _load_or_create_secret_key() -> str:
    if k := os.environ.get("SECRET_KEY"):
        return k
    _key_file = os.path.join(WG_DIR, ".secret_key")
    try:
        with open(_key_file) as _f:
            k = _f.read().strip()
            if k:
                return k
    except Exception:
        pass
    k = _secrets.token_hex(32)
    for _path in (_key_file, os.path.join(os.path.dirname(__file__), ".secret_key")):
        try:
            fd = os.open(_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as _f:
                _f.write(k)
            break
        except Exception:
            pass
    return k

app.secret_key = _load_or_create_secret_key()
app.permanent_session_lifetime = datetime.timedelta(days=7)
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("SESSION_COOKIE_SECURE", "0") == "1"
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
app.logger.setLevel(logging.INFO)

def _run(cmd: str) -> Tuple[str,int]:
    r=subprocess.run(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    return r.stdout.strip(), r.returncode

_last_run = {"cmd":"", "rc":None, "out":""}
_geo_cache: Dict[str, Dict[str, Any]] = {}

_bg_notifications: List[Dict[str, Any]] = []
_bg_lock = threading.Lock()
_budget_lock = threading.Lock()

def _sudo_cat(path: str) -> Tuple[str, int]:
    for cat_bin in ("/bin/cat", "/usr/bin/cat"):
        out, rc = _sudo([cat_bin, path])
        if rc == 0:
            return out, 0
    return "", 1

def _sudo(args: List[str], input_data: bytes = None) -> Tuple[str,int]:
    try:
        cmd = [SUDO_BIN, "-n"] + args
        app.logger.info("run_exec: %s", " ".join(shlex.quote(a) for a in cmd))
        r = subprocess.run(cmd, input=input_data, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out = r.stdout.decode().strip()
    except Exception as e:
        out = str(e)
        r = type("obj", (), {"returncode": 1})()
    rc = r.returncode if hasattr(r, "returncode") else 1
    global _last_run
    _last_run = {"cmd": " ".join(args), "rc": rc, "out": out}
    if rc != 0:
        app.logger.warning("command failed: rc=%s\nstdout+stderr:\n%s", rc, out)
    return out, rc

@app.before_request
def _log_request():
    app.logger.info("%s %s", request.method, request.path)

_AUTH_OPEN = {"/", "/welcome", "/mobile", "/manifest.json", "/service-worker.js", "/api/auth/check", "/api/auth/login", "/api/auth/logout", "/api/welcome/dismiss", "/setup", "/api/setup"}

@app.before_request
def _require_auth():
    if not DASHBOARD_PASSWORD_HASH:
        if request.path in {"/setup", "/api/setup"} or request.path.startswith("/static/"):
            return
        if request.path.startswith("/api/"):
            return jsonify({"error": "setup_required"}), 403
        return redirect("/setup")
    if request.path in _AUTH_OPEN or request.path.startswith("/static/"):
        return
    if not session.get("authenticated"):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Unauthorized"}), 401
        return redirect("/")

@app.errorhandler(404)
def _handle_404(_e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Not found", "hint": f"'{request.path}' does not exist"}), 404
    return redirect("/")

@app.errorhandler(405)
def _handle_405(_e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Method not allowed"}), 405
    return redirect("/")

@app.after_request
def _log_response(res):
    app.logger.info("status=%s path=%s", res.status_code, request.path)
    return res

@app.context_processor
def inject_year():
    return {"current_year": datetime.datetime.utcnow().year}

def service_active() -> bool:
    o,c=_run(f"systemctl is-active {UNIT}")
    return o.strip()=="active"

def service_enabled() -> bool:
    o,c=_run(f"systemctl is-enabled {UNIT} || true")
    return o.strip()=="enabled"

def service_started_at_ms() -> int:
    """Return the Unix timestamp (ms) when the service entered active state, or 0."""
    o,c=_run(f"systemctl show {UNIT} --property=ActiveEnterTimestamp --value 2>/dev/null || true")
    val=o.strip()
    if not val or val=="n/a":
        return 0
    try:
        dt=datetime.datetime.strptime(val,"%a %Y-%m-%d %H:%M:%S %Z")
        return int(dt.replace(tzinfo=datetime.timezone.utc).timestamp()*1000)
    except Exception:
        return 0

def ufw_allowed(port: int, proto: str="udp") -> bool:
    o,c=_run("ufw status numbered | grep -E '\\b{}/{}\\b' || true".format(port,proto))
    return bool(o)

def local_listening(port: int, proto: str="udp") -> bool:
    flag = "u" if proto == "udp" else "t"
    o,_=_run(f"ss -l{flag}np 2>/dev/null | grep ':{port}' || true")
    return bool(o.strip())

def ping_ok() -> bool:
    o,c=_run("ping -c1 -W1 1.1.1.1 >/dev/null 2>&1")
    return c==0

_BG_INTERVAL   = int(os.environ.get("BG_CHECK_INTERVAL", "3600"))   
_BG_INIT_DELAY = int(os.environ.get("BG_CHECK_DELAY",    "120"))    

def _bg_run_port_check() -> None:
    conf = _read_conf()
    lp   = int(conf.get("Interface", {}).get("ListenPort", WG_PORT))
    now  = datetime.datetime.now(datetime.timezone.utc)
    ts   = int(now.timestamp())
    when = now.strftime("%H:%M UTC")

    findings: List[Dict[str, Any]] = []

    def _chk(fn):
        try:    return fn()
        except: return None

    if not _chk(service_active):
        findings.append({"id": "bg-svc-down", "level": "error",
            "title": "WireGuard service is down",
            "desc":  f"{UNIT} is not active — peers cannot connect."})

    if not _chk(lambda: local_listening(lp, "udp")):
        findings.append({"id": "bg-port-unbound", "level": "warn",
            "title": f"Nothing listening on UDP {lp}",
            "desc":  "The WireGuard port is not bound. Restart the service."})

    if not _chk(lambda: ufw_allowed(lp, "udp")):
        findings.append({"id": "bg-ufw-blocked", "level": "warn",
            "title": f"Firewall may block UDP {lp}",
            "desc":  "No UFW rule found for the WireGuard port."})

    ip_fwd, _ = _run("cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0")
    if ip_fwd.strip() != "1":
        findings.append({"id": "bg-no-forward", "level": "warn",
            "title": "IP forwarding is disabled",
            "desc":  "Peers can connect but cannot route traffic (net.ipv4.ip_forward = 0)."})

    if not _chk(ping_ok):
        findings.append({"id": "bg-no-internet", "level": "warn",
            "title": "Server has no internet connectivity",
            "desc":  "Cannot reach 1.1.1.1 — peer traffic may not route correctly."})

    def _throttle_broken():
        enf = _load_data_budget_db()["settings"].get("enforcement", {})
        return enf.get("action") in ("throttle", "combined") and not _tc_available()
    if _chk(_throttle_broken):
        findings.append({"id": "bg-tc-missing", "level": "warn",
            "title": "Speed throttling unavailable",
            "desc":  f"Budget enforcement wants to reduce speed, but '{TC_BIN}' cannot run via sudo. Re-run install.sh or add it to /etc/sudoers.d/wg-dashboard."})

    for f in findings:
        f["ts"]         = ts
        f["checked_at"] = when

    with _bg_lock:
        _bg_notifications.clear()
        _bg_notifications.extend(findings)

def _bg_check_loop() -> None:
    time.sleep(_BG_INIT_DELAY)
    while True:
        try:
            _bg_run_port_check()
        except Exception:
            pass
        time.sleep(_BG_INTERVAL)

def _bg_retention_loop() -> None:
    """Re-apply the saved journal retention so it acts as a policy, not a one-shot vacuum."""
    time.sleep(_BG_INIT_DELAY)
    while True:
        try:
            retention = str(_load_dash_settings().get("log_retention", ""))
            if retention in {"1d", "7d", "30d"}:
                _sudo(["/usr/bin/journalctl", f"--vacuum-time={retention}"])
        except Exception:
            app.logger.exception("bg_retention_failed")
        time.sleep(6 * 3600)

_BUDGET_ENFORCE_INTERVAL = int(os.environ.get("BUDGET_ENFORCE_INTERVAL", "60"))

def _bg_budget_loop() -> None:
    """Track usage and enforce budgets even when no dashboard client is polling /api/status."""
    time.sleep(_BG_INIT_DELAY)
    try:
        _ensure_tc_sudo()
    except Exception:
        app.logger.exception("tc_sudo_check_failed")
    while True:
        try:
            issued, live = list_clients()
            _data_budget_state(issued, live)
        except Exception:
            app.logger.exception("bg_budget_enforce_failed")
        time.sleep(_BUDGET_ENFORCE_INTERVAL)

def timedate_ntp() -> str:
    o,c=_run("timedatectl 2>/dev/null | awk -F': ' '/NTP service:|System clock synchronized:/{print $2}' | xargs | sed 's/ /, /g'")
    return o.strip()

def logs_tail(n: int=200, verbose: bool=False) -> str:
    fmt = "short-precise" if verbose else "short"
    args = ["/usr/bin/journalctl", "-u", UNIT, "-n", str(int(n)), "--no-pager", f"--output={fmt}"]
    o, _ = _sudo(args)
    return o

_JOURNAL_MONTHS = {"Jan":1,"Feb":2,"Mar":3,"Apr":4,"May":5,"Jun":6,"Jul":7,"Aug":8,"Sep":9,"Oct":10,"Nov":11,"Dec":12}
_JOURNAL_TS_RE = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})")

def _journal_line_ts(line: str) -> float:
    """Best-effort epoch timestamp of a journalctl short/short-precise line, or 0."""
    m = _JOURNAL_TS_RE.match(line)
    if not m:
        return 0
    now = datetime.datetime.now()
    try:
        d = datetime.datetime(now.year, _JOURNAL_MONTHS[m.group(1)], int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5)))
    except (KeyError, ValueError):
        return 0
    if (d - now).days >= 1:  # journal line from last year (Dec seen in Jan)
        d = d.replace(year=now.year - 1)
    return d.timestamp()

def _budget_alert_log_lines() -> List[Tuple[float, str]]:
    """Budget alert events formatted as journal-style lines, oldest first."""
    try:
        events = _load_data_budget_db().get("alert_log", [])
        host = os.uname().nodename
    except Exception:
        return []
    out = []
    for ev in events:
        try:
            ts = int(ev.get("ts", 0) or 0)
            level = str(ev.get("level", ""))
            pct = float(ev.get("pct", 0) or 0)
            used_gb = int(ev.get("used", 0) or 0) / (1024 ** 3)
            budget_gb = ev.get("budget_gb", "?")
        except (TypeError, ValueError):
            continue
        peer = str(ev.get("peer") or "").strip()
        if peer:
            title = {"100": f"peer '{peer}' budget exceeded", "90": f"peer '{peer}' budget nearly exhausted"}.get(level, f"peer '{peer}' approaching budget")
        else:
            title = {"100": "data budget exceeded", "90": "data budget nearly exhausted"}.get(level, "approaching data budget")
        stamp = time.strftime("%b %d %H:%M:%S", time.localtime(ts))
        out.append((float(ts), f"{stamp} {host} wg-dashboard[budget]: warning: {title} — {pct:.0f}% used ({used_gb:.1f} of {budget_gb} GB)"))
    out.sort(key=lambda x: x[0])
    return out

DASH_EVENTS_DB = os.environ.get("DASH_EVENTS_DB", os.path.join(WG_DIR, "dashboard_events.json"))
_dash_events_lock = threading.Lock()
DASH_SETTINGS_DB = os.environ.get("DASH_SETTINGS_DB", os.path.join(WG_DIR, "dashboard_settings.json"))
_dash_settings_lock = threading.Lock()

def _write_json_file_root(path: str, obj: Any) -> None:
    """Atomic JSON write with sudo fallback for root-owned directories."""
    import tempfile
    fd, tmp_path = tempfile.mkstemp(prefix="dash-json.", suffix=".json.tmp", dir="/tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f)
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            os.replace(tmp_path, path)
            return
        except Exception:
            pass
        _sudo(["/usr/bin/install", "-m", "640", "-o", "root", "-g", "www-data", tmp_path, path])
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except:
            pass

def _load_dash_settings() -> Dict[str, Any]:
    try:
        with open(DASH_SETTINGS_DB, "r", encoding="utf-8") as f:
            s = json.load(f)
    except FileNotFoundError:
        return {}
    except PermissionError:
        out, rc = _sudo_cat(DASH_SETTINGS_DB)
        if rc != 0 or not out:
            return {}
        try:
            s = json.loads(out)
        except Exception:
            return {}
    except Exception:
        return {}
    return s if isinstance(s, dict) else {}

def _save_dash_setting(key: str, value: Any) -> None:
    with _dash_settings_lock:
        s = _load_dash_settings()
        s[key] = value
        _write_json_file_root(DASH_SETTINGS_DB, s)

def _load_dash_events() -> List[Dict[str, Any]]:
    try:
        with open(DASH_EVENTS_DB, "r", encoding="utf-8") as f:
            events = json.load(f)
    except FileNotFoundError:
        return []
    except PermissionError:
        out, rc = _sudo_cat(DASH_EVENTS_DB)
        if rc != 0 or not out:
            return []
        try:
            events = json.loads(out)
        except Exception:
            return []
    except Exception:
        return []
    return events if isinstance(events, list) else []

def _log_dashboard_event(msg: str, level: str = "info") -> None:
    """Record a user-facing event shown in the dashboard Logs panel."""
    app.logger.info("dashboard_event level=%s msg=%s", level, msg)
    try:
        with _dash_events_lock:
            events = _load_dash_events()
            events.append({"ts": int(time.time()), "level": level if level in ("info", "warn", "error") else "info", "msg": str(msg)[:300]})
            del events[:-200]
            _write_json_file_root(DASH_EVENTS_DB, events)
    except Exception:
        app.logger.exception("dashboard_event_save_failed")

def _dashboard_event_lines() -> List[Tuple[float, str]]:
    """Dashboard events formatted as journal-style lines, oldest first."""
    try:
        events = _load_dash_events()
        host = os.uname().nodename
    except Exception:
        return []
    out = []
    for ev in events:
        try:
            ts = int(ev.get("ts", 0) or 0)
        except (TypeError, ValueError):
            continue
        msg = str(ev.get("msg", "")).strip()
        if not ts or not msg:
            continue
        level = str(ev.get("level", "info"))
        prefix = "warning: " if level == "warn" else "error: " if level == "error" else ""
        stamp = time.strftime("%b %d %H:%M:%S", time.localtime(ts))
        out.append((float(ts), f"{stamp} {host} wg-dashboard[events]: {prefix}{msg}"))
    out.sort(key=lambda x: x[0])
    return out

def _merge_dashboard_log_lines(lines: List[str]) -> List[str]:
    """Interleave budget alerts and dashboard events into journal output by timestamp."""
    alerts = _budget_alert_log_lines() + _dashboard_event_lines()
    alerts.sort(key=lambda x: x[0])
    if not alerts:
        return lines
    if lines:
        first_ts = next((t for t in (_journal_line_ts(ln) for ln in lines) if t), 0)
        alerts = [a for a in alerts if a[0] >= first_ts]
    out = []
    ai = 0
    for ln in lines:
        ts = _journal_line_ts(ln)
        if ts:
            while ai < len(alerts) and alerts[ai][0] <= ts:
                out.append(alerts[ai][1])
                ai += 1
        out.append(ln)
    out.extend(a[1] for a in alerts[ai:])
    return out

def _read_conf() -> Dict[str,Any]:
    data = {"Interface": {}, "Peers": []}
    content = ""
    try:
        with open(WG_CONF, encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except FileNotFoundError:
        return data
    except PermissionError:
        out, rc = _sudo_cat(WG_CONF)
        if rc != 0 or not out:
            return data
        content = out
    cur = None
    cur_peer = {}
    for ln in content.splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        if s.lower() == "[interface]":
            cur = "iface"
            continue
        if s.lower() == "[peer]":
            if cur_peer:
                data["Peers"].append(cur_peer)
            cur_peer = {}
            cur = "peer"
            continue
        if "=" in s:
            k, v = [x.strip() for x in s.split("=", 1)]
            if cur == "iface":
                data["Interface"][k] = v
            elif cur == "peer":
                cur_peer[k] = v
    if cur_peer:
        data["Peers"].append(cur_peer)
    return data

def _write_conf(data: Dict[str,Any]) -> None:
    lines=[]
    iface=data.get("Interface",{})
    lines.append("[Interface]")
    for k,v in iface.items():
        lines.append(f"{k} = {v}")
    for p in data.get("Peers",[]):
        lines.append("")
        lines.append("[Peer]")
        for k,v in p.items():
            lines.append(f"{k} = {v}")
    import tempfile
    fd,tmp_path = tempfile.mkstemp(prefix="wg0.", suffix=".conf.tmp", dir="/tmp")
    try:
        with os.fdopen(fd,"w",encoding="utf-8") as f:
            f.write("\n".join(lines).strip()+"\n")
        _sudo(["/usr/bin/install","-m","640","-o","root","-g","www-data",tmp_path,WG_CONF])
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except:
            pass

def _iface_name() -> str:
    return WG_IFACE

def read_bytes() -> Tuple[str,int,int]:
    iface=_iface_name()
    rx=f"/sys/class/net/{iface}/statistics/rx_bytes"
    tx=f"/sys/class/net/{iface}/statistics/tx_bytes"
    try:
        with open(rx) as fr: r=int(fr.read().strip())
        with open(tx) as ft: t=int(ft.read().strip())
        return iface,r,t
    except:
        return iface,0,0

def _valid_traffic_sample(x: Any) -> bool:
    return (
        isinstance(x, dict)
        and isinstance(x.get("ts"), (int, float))
        and isinstance(x.get("rx_bps"), (int, float))
        and isinstance(x.get("tx_bps"), (int, float))
    )

def _load_traffic_history() -> List[Dict[str, Any]]:
    content = ""
    try:
        with open(TRAFFIC_HISTORY, "r", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        return []
    except PermissionError:
        out, rc = _sudo_cat(TRAFFIC_HISTORY)
        if rc != 0:
            return []
        content = out
    except Exception:
        return []
    try:
        raw = json.loads(content)
    except Exception:
        return []
    if not isinstance(raw, list):
        return []
    cutoff = time.time() - TRAFFIC_RETENTION_SECONDS
    history = []
    for sample in raw:
        if not _valid_traffic_sample(sample):
            continue
        ts = float(sample["ts"])
        if ts < cutoff:
            continue
        history.append({
            "ts": ts,
            "rx_bps": max(0.0, float(sample.get("rx_bps", 0))),
            "tx_bps": max(0.0, float(sample.get("tx_bps", 0))),
            "rx": int(sample.get("rx", 0) or 0),
            "tx": int(sample.get("tx", 0) or 0),
        })
    history.sort(key=lambda s: s["ts"])
    return history

def _save_traffic_history(history: List[Dict[str, Any]]) -> None:
    import tempfile
    fd,tmp_path = tempfile.mkstemp(prefix="traffic.", suffix=".json.tmp", dir="/tmp")
    try:
        with os.fdopen(fd,"w",encoding="utf-8") as f:
            json.dump(history, f, separators=(",", ":"))
        try:
            os.makedirs(os.path.dirname(TRAFFIC_HISTORY), exist_ok=True)
            os.replace(tmp_path, TRAFFIC_HISTORY)
            return
        except Exception:
            pass
        _sudo(["/usr/bin/install","-m","640","-o","root","-g","www-data",tmp_path,TRAFFIC_HISTORY])
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except:
            pass

def _traffic_history() -> List[Dict[str, Any]]:
    if "_traffic_history" not in app.config:
        app.config["_traffic_history"] = _load_traffic_history()
        app.config["_traffic_last_flush"] = 0.0
    return app.config["_traffic_history"]

def _prune_traffic_history(history: List[Dict[str, Any]], now: float = None) -> List[Dict[str, Any]]:
    cutoff = (now if now is not None else time.time()) - TRAFFIC_RETENTION_SECONDS
    return [s for s in history if s.get("ts", 0) >= cutoff]

def _record_traffic_sample(sample: Dict[str, Any]) -> None:
    history = _traffic_history()
    if history and sample["ts"] <= history[-1]["ts"]:
        history[-1] = sample
    else:
        history.append(sample)
    history = _prune_traffic_history(history, sample["ts"])
    app.config["_traffic_history"] = history
    last_flush = float(app.config.get("_traffic_last_flush", 0) or 0)
    if sample["ts"] - last_flush >= TRAFFIC_FLUSH_SECONDS:
        _save_traffic_history(history)
        app.config["_traffic_last_flush"] = sample["ts"]

_traffic_snap_lock = threading.Lock()

def _sample_traffic() -> Dict[str, Any]:
    """Take one throughput sample (bps since last snapshot) and record it in history."""
    iface, rx, tx = read_bytes()
    now = time.time()
    with _traffic_snap_lock:
        snap = app.config.get("_snap")
        if snap is None:
            sample = {"ts": now, "rx_bps": 0.0, "tx_bps": 0.0, "rx": rx, "tx": tx}
        else:
            dt = max(1e-6, now - snap["ts"])
            sample = {"ts": now,
                      "rx_bps": max(0, (rx - snap["rx"]) / dt),
                      "tx_bps": max(0, (tx - snap["tx"]) / dt),
                      "rx": rx, "tx": tx}
        app.config["_snap"] = {"ts": now, "rx": rx, "tx": tx}
        _record_traffic_sample(sample)
    return {"iface": iface, **sample}

TRAFFIC_SAMPLE_INTERVAL = max(1, int(os.environ.get("TRAFFIC_SAMPLE_INTERVAL", "2")))

def _bg_traffic_loop() -> None:
    """Keep recording throughput history while no dashboard client is polling /api/traffic."""
    time.sleep(_BG_INIT_DELAY)
    while True:
        try:
            _sample_traffic()
        except Exception:
            pass
        time.sleep(TRAFFIC_SAMPLE_INTERVAL)

def _downsample_traffic(samples: List[Dict[str, Any]], max_points: int) -> List[Dict[str, Any]]:
    if max_points <= 0 or len(samples) <= max_points:
        return samples
    bucket_size = max(1, int((len(samples) + max_points - 1) / max_points))
    out = []
    for i in range(0, len(samples), bucket_size):
        bucket = samples[i:i + bucket_size]
        if not bucket:
            continue
        out.append({
            "ts": bucket[-1]["ts"],
            "rx_bps": sum(s["rx_bps"] for s in bucket) / len(bucket),
            "tx_bps": sum(s["tx_bps"] for s in bucket) / len(bucket),
            "rx": bucket[-1].get("rx", 0),
            "tx": bucket[-1].get("tx", 0),
        })
    return out

def _valid_uptime_event(x: Any) -> bool:
    return (
        isinstance(x, dict)
        and isinstance(x.get("ts"), (int, float))
        and x.get("state") in ("up", "down", "unknown")
    )

def _parse_uptime_events(raw: Any) -> List[Dict[str, Any]]:
    events = [
        {"ts": float(e["ts"]), "state": e["state"]}
        for e in (raw or [])
        if _valid_uptime_event(e)
    ]
    events.sort(key=lambda e: e["ts"])
    return _prune_uptime_events(events)

def _load_uptime_db() -> Dict[str, Any]:
    _default = {"events": [], "last_sample": 0.0,
                "net_events": [], "net_last_sample": 0.0, "net_latency": [], "net_target": ""}
    content = ""
    try:
        with open(UPTIME_DB, "r", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        return _default
    except PermissionError:
        out, rc = _sudo_cat(UPTIME_DB)
        if rc != 0:
            return _default
        content = out
    except Exception:
        return _default
    try:
        raw = json.loads(content)
    except Exception:
        return _default
    if not isinstance(raw, dict):
        return _default
    lat_cutoff = time.time() - NET_LATENCY_RETENTION_SECONDS
    latency = [
        {"ts": float(s["ts"]), "ms": float(s["ms"])}
        for s in (raw.get("net_latency") or [])
        if isinstance(s, dict) and isinstance(s.get("ts"), (int, float))
        and isinstance(s.get("ms"), (int, float)) and float(s["ts"]) >= lat_cutoff
    ]
    return {
        "events": _parse_uptime_events(raw.get("events")),
        "last_sample": float(raw.get("last_sample") or 0.0),
        "net_events": _parse_uptime_events(raw.get("net_events")),
        "net_last_sample": float(raw.get("net_last_sample") or 0.0),
        "net_latency": latency,
        "net_target": str(raw.get("net_target") or ""),
    }

def _save_uptime_db(db: Dict[str, Any]) -> None:
    import tempfile
    fd, tmp_path = tempfile.mkstemp(prefix="uptime.", suffix=".json.tmp", dir="/tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(db, f, separators=(",", ":"))
        try:
            os.makedirs(os.path.dirname(UPTIME_DB), exist_ok=True)
            os.replace(tmp_path, UPTIME_DB)
            return
        except Exception:
            pass
        _sudo(["/usr/bin/install", "-m", "640", "-o", "root", "-g", "www-data", tmp_path, UPTIME_DB])
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except:
            pass

def _uptime_db() -> Dict[str, Any]:
    if "_uptime_db" not in app.config:
        app.config["_uptime_db"] = _load_uptime_db()
        app.config["_uptime_last_flush"] = 0.0
    return app.config["_uptime_db"]

def _prune_uptime_events(events: List[Dict[str, Any]], now: float = None) -> List[Dict[str, Any]]:
    """Drop events past retention but keep the boundary state, clamped to the cutoff."""
    if not events:
        return []
    cutoff = (now if now is not None else time.time()) - UPTIME_RETENTION_SECONDS
    kept = [e for e in events if e["ts"] >= cutoff]
    dropped = [e for e in events if e["ts"] < cutoff]
    if dropped and (not kept or kept[0]["ts"] > cutoff):
        boundary = dict(dropped[-1])
        boundary["ts"] = cutoff
        kept.insert(0, boundary)
    return kept

def _uptime_append_state(db: Dict[str, Any], ev_key: str, ls_key: str, state: str, now: float) -> bool:
    """Append gap + state-change events for one channel; returns True if events changed."""
    events = db.setdefault(ev_key, [])
    changed = False
    last_sample = float(db.get(ls_key) or 0.0)

    if events and last_sample > 0 and now - last_sample > UPTIME_GAP_SECONDS and events[-1]["state"] != "unknown":
        gap_ts = max(events[-1]["ts"], min(last_sample + UPTIME_SAMPLE_INTERVAL, now))
        events.append({"ts": gap_ts, "state": "unknown"})
        changed = True
    if not events or events[-1]["state"] != state:
        events.append({"ts": now, "state": state})
        changed = True
    db[ls_key] = now
    db[ev_key] = _prune_uptime_events(events, now)
    return changed

def _uptime_flush(db: Dict[str, Any], changed: bool, now: float) -> None:
    app.config["_uptime_db"] = db
    last_flush = float(app.config.get("_uptime_last_flush", 0) or 0)
    if changed or now - last_flush >= UPTIME_FLUSH_SECONDS:
        _save_uptime_db(db)
        app.config["_uptime_last_flush"] = now

def _record_uptime_sample(active: bool = None) -> None:
    """Record one service up/down sample; appends an event only on state change."""
    if active is None:
        try:
            active = service_active()
        except Exception:
            return
    now = time.time()
    with _uptime_lock:
        db = _uptime_db()
        changed = _uptime_append_state(db, "events", "last_sample", "up" if active else "down", now)
        _uptime_flush(db, changed, now)

def _ping_internet() -> Tuple[bool, float, str]:
    """Ping the first reachable target; returns (ok, latency_ms, target)."""
    for ip in NET_PING_TARGETS:
        o, c = _run(f"ping -c1 {_PING_WAIT_FLAG} {ip} 2>/dev/null")
        if c == 0:
            m = re.search(r"time[=<]([\d.]+)\s*ms", o)
            return True, float(m.group(1)) if m else 0.0, ip
    return False, 0.0, NET_PING_TARGETS[0] if NET_PING_TARGETS else ""

def _record_net_sample(ok: bool = None, latency_ms: float = None, target: str = "") -> None:
    """Record one internet reachability sample (state + latency)."""
    if ok is None:
        try:
            ok, latency_ms, target = _ping_internet()
        except Exception:
            return
    now = time.time()
    with _uptime_lock:
        db = _uptime_db()
        changed = _uptime_append_state(db, "net_events", "net_last_sample", "up" if ok else "down", now)
        if ok and latency_ms is not None:
            lat = db.setdefault("net_latency", [])
            lat.append({"ts": now, "ms": round(float(latency_ms), 2)})
            cutoff = now - NET_LATENCY_RETENTION_SECONDS
            db["net_latency"] = [s for s in lat if s["ts"] >= cutoff]
        if target:
            db["net_target"] = target
        _uptime_flush(db, changed, now)

def _uptime_intervals(events: List[Dict[str, Any]], now: float) -> List[Tuple[float, float, str]]:
    """Turn the event list into contiguous (start, end, state) spans up to now."""
    out = []
    for i, e in enumerate(events):
        start = float(e["ts"])
        end = float(events[i + 1]["ts"]) if i + 1 < len(events) else now
        if end > start:
            out.append((start, end, e["state"]))
    return out

def _uptime_window_stats(intervals: List[Tuple[float, float, str]], start: float, end: float) -> Dict[str, Any]:
    up = down = unknown = 0.0
    incidents = 0
    longest = 0.0
    for (s, e, st) in intervals:
        s2, e2 = max(s, start), min(e, end)
        if e2 <= s2:
            continue
        d = e2 - s2
        if st == "up":
            up += d
        elif st == "down":
            down += d
            incidents += 1
            longest = max(longest, d)
        else:
            unknown += d
    known = up + down
    return {
        "uptime_pct": round(up / known * 100.0, 3) if known > 0 else None,
        "up_s": int(up),
        "down_s": int(down),
        "unknown_s": int(unknown),
        "incidents": incidents,
        "longest_down_s": int(longest),
    }

def _uptime_buckets(intervals: List[Tuple[float, float, str]], start: float, end: float, n: int) -> List[Dict[str, Any]]:
    size = (end - start) / n
    buckets = []
    for i in range(n):
        bs = start + i * size
        be = bs + size
        up = down = unknown = 0.0
        for (s, e, st) in intervals:
            s2, e2 = max(s, bs), min(e, be)
            if e2 <= s2:
                continue
            d = e2 - s2
            if st == "up":
                up += d
            elif st == "down":
                down += d
            else:
                unknown += d
        known = up + down
        if known <= 0:
            state = "unknown"
        elif down <= 0:
            state = "up"
        elif up <= 0:
            state = "down"
        else:
            state = "partial"
        buckets.append({
            "ts_ms": int(bs * 1000),
            "state": state,
            "up_pct": round(up / known * 100.0, 2) if known > 0 else None,
            "down_s": int(down),
            "unknown_s": int(unknown),
        })
    return buckets

def _uptime_incident_list(intervals: List[Tuple[float, float, str]], now: float, limit: int = 40) -> List[Dict[str, Any]]:
    """Down periods and monitoring gaps, newest first."""
    out = []
    for (s, e, st) in intervals:
        if st == "up":
            continue
        ongoing = e >= now - 1
        out.append({
            "state": st,
            "start_ms": int(s * 1000),
            "end_ms": None if ongoing else int(e * 1000),
            "duration_s": int(e - s),
            "ongoing": ongoing,
        })
    out.reverse()
    return out[:limit]

def _downsample_latency(samples: List[Dict[str, Any]], max_points: int = 96) -> List[Dict[str, Any]]:
    if max_points <= 0 or len(samples) <= max_points:
        return samples
    bucket_size = max(1, int((len(samples) + max_points - 1) / max_points))
    out = []
    for i in range(0, len(samples), bucket_size):
        bucket = samples[i:i + bucket_size]
        if not bucket:
            continue
        out.append({
            "ts": bucket[-1]["ts"],
            "ms": round(sum(s["ms"] for s in bucket) / len(bucket), 2),
        })
    return out

def _bg_uptime_loop() -> None:
    """Record service + internet up/down transitions even when no dashboard client is open."""
    time.sleep(5)
    while True:
        try:
            _record_uptime_sample()
        except Exception:
            pass
        try:
            _record_net_sample()
        except Exception:
            pass
        time.sleep(UPTIME_SAMPLE_INTERVAL)

def _check_peer_handshakes() -> None:
    """Detect per-peer handshake drop/recovery so it lands in the event log even if
    nobody had the dashboard open when it happened. If several peers drop within the
    same check, log that separately — simultaneous drops across peers point at the
    server/network (service restart, firewall, ISP), not one client's own connection."""
    _, live = list_clients()
    now = time.time()
    dropped: List[str] = []
    recovered: List[str] = []

    with _peer_watch_lock:
        seen = set()
        for row in live:
            name = row.get("name") or ""
            if not name:
                continue
            seen.add(name)
            lh = row.get("last_handshake") or 0
            online = lh > 0 and (now - lh) < PEER_WATCH_HS_TIMEOUT
            prev = _peer_watch_state.get(name)
            if prev is None:
                _peer_watch_state[name] = {"online": online, "since": now}
                continue
            if prev["online"] and not online:
                age = int(now - lh) if lh else -1
                _log_dashboard_event(
                    f"peer '{name}' went offline"
                    + (f" (no handshake for {age}s)" if age >= 0 else ""),
                    "warn",
                )
                dropped.append(name)
                _peer_watch_state[name] = {"online": False, "since": now}
            elif not prev["online"] and online:
                outage_s = int(now - prev["since"])
                _log_dashboard_event(f"peer '{name}' back online (was offline {outage_s}s)")
                recovered.append(name)
                _peer_watch_state[name] = {"online": True, "since": now}

        for name in list(_peer_watch_state.keys()):
            if name not in seen:
                _peer_watch_state.pop(name, None)

    if len(dropped) >= 2:
        _log_dashboard_event(
            f"{len(dropped)} peers lost their handshake in the same check ({', '.join(dropped[:6])}"
            + (", …" if len(dropped) > 6 else "")
            + f") — likely a server-side or network cause (service restart, firewall, ISP), not just those clients",
            "error",
        )

def _bg_peer_watch_loop() -> None:
    time.sleep(_BG_INIT_DELAY)
    while True:
        try:
            _check_peer_handshakes()
        except Exception:
            app.logger.exception("bg_peer_watch_failed")
        time.sleep(PEER_WATCH_INTERVAL)

def _load_peer_spark_history() -> Dict[str, List[Dict[str, Any]]]:
    content = ""
    try:
        with open(PEER_SPARK_HISTORY, "r", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        return {}
    except PermissionError:
        out, rc = _sudo_cat(PEER_SPARK_HISTORY)
        if rc != 0:
            return {}
        content = out
    except Exception:
        return {}
    try:
        raw = json.loads(content)
    except Exception:
        return {}
    if not isinstance(raw, dict):
        return {}
    cutoff = time.time() - PEER_THROUGHPUT_RETENTION_SECONDS
    history = {}
    for name, samples in raw.items():
        if not isinstance(samples, list):
            continue
        clean = []
        for sample in samples:
            if not isinstance(sample, dict):
                continue
            try:
                ts = float(sample.get("ts", 0))
                total = max(0.0, float(sample.get("total", 0)))
                rx_bps = max(0.0, float(sample.get("rx_bps", 0)))
                tx_bps = max(0.0, float(sample.get("tx_bps", 0)))
            except Exception:
                continue
            if ts >= cutoff:
                clean.append({"ts": ts, "total": total, "rx_bps": rx_bps, "tx_bps": tx_bps})
        if clean:
            history[str(name)] = clean
    return history

def _save_peer_spark_history(history: Dict[str, List[Dict[str, Any]]]) -> None:
    import tempfile
    fd,tmp_path = tempfile.mkstemp(prefix="peer-sparks.", suffix=".json.tmp", dir="/tmp")
    try:
        with os.fdopen(fd,"w",encoding="utf-8") as f:
            json.dump(history, f, separators=(",", ":"))
        try:
            os.makedirs(os.path.dirname(PEER_SPARK_HISTORY), exist_ok=True)
            os.replace(tmp_path, PEER_SPARK_HISTORY)
            return
        except Exception:
            pass
        _sudo(["/usr/bin/install","-m","640","-o","root","-g","www-data",tmp_path,PEER_SPARK_HISTORY])
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except:
            pass

def _peer_spark_history() -> Dict[str, List[Dict[str, Any]]]:
    if "_peer_spark_history" not in app.config:
        app.config["_peer_spark_history"] = _load_peer_spark_history()
        app.config["_peer_spark_last_flush"] = 0.0
    return app.config["_peer_spark_history"]

def _prune_peer_spark_history(history: Dict[str, List[Dict[str, Any]]], now: float = None) -> Dict[str, List[Dict[str, Any]]]:
    cutoff = (now if now is not None else time.time()) - PEER_THROUGHPUT_RETENTION_SECONDS
    out = {}
    for name, samples in history.items():
        kept = [s for s in samples if s.get("ts", 0) >= cutoff]
        if kept:
            out[name] = kept
    return out

def _record_peer_spark_samples(live: List[Dict[str, Any]]) -> Dict[str, List[float]]:
    now = time.time()
    history = _prune_peer_spark_history(_peer_spark_history(), now)
    prev = app.config.get("_peer_spark_prev", {})
    next_prev = {}
    for p in live:
        name = str(p.get("name") or p.get("cn") or "").strip()
        if not name:
            continue
        rx = int(p.get("bytes_recv", 0) or 0)
        tx = int(p.get("bytes_sent", 0) or 0)
        next_prev[name] = {"rx": rx, "tx": tx, "ts": now}
        old = prev.get(name)
        if not old:
            continue
        dt = max(1e-6, now - float(old.get("ts", now)))
        rx_delta = max(0, rx - int(old.get("rx", 0)))
        tx_delta = max(0, tx - int(old.get("tx", 0)))
        total = rx_delta + tx_delta
        history.setdefault(name, []).append({"ts": now, "total": total, "rx_bps": rx_delta / dt, "tx_bps": tx_delta / dt})
    app.config["_peer_spark_prev"] = next_prev
    history = _prune_peer_spark_history(history, now)
    app.config["_peer_spark_history"] = history
    last_flush = float(app.config.get("_peer_spark_last_flush", 0) or 0)
    if now - last_flush >= PEER_SPARK_FLUSH_SECONDS:
        _save_peer_spark_history(history)
        app.config["_peer_spark_last_flush"] = now
    return _peer_spark_payload(history)

def _peer_spark_payload(history: Dict[str, List[Dict[str, Any]]] = None) -> Dict[str, List[float]]:
    now = time.time()
    history = _prune_peer_spark_history(history if history is not None else _peer_spark_history(), now)
    app.config["_peer_spark_history"] = history
    spark_cutoff = now - PEER_SPARK_RETENTION_SECONDS
    bucket_count = 20
    bucket_seconds = PEER_SPARK_RETENTION_SECONDS / bucket_count
    start = spark_cutoff
    out = {}
    for name, samples in history.items():
        buckets = [0.0] * bucket_count
        for sample in samples:
            try:
                ts = float(sample.get("ts", 0))
                total = float(sample.get("total", 0) or 0)
            except Exception:
                continue
            if ts < spark_cutoff:
                continue
            idx = int((ts - start) / bucket_seconds)
            if 0 <= idx < bucket_count:
                buckets[idx] += max(0.0, total)
        out[name] = buckets
    return out

def _peer_throughput_payload(history: Dict[str, List[Dict[str, Any]]] = None) -> Dict[str, Dict[str, List[float]]]:
    now = time.time()
    history = _prune_peer_spark_history(history if history is not None else _peer_spark_history(), now)
    app.config["_peer_spark_history"] = history
    bucket_count = 40
    bucket_seconds = PEER_THROUGHPUT_RETENTION_SECONDS / bucket_count
    start = now - PEER_THROUGHPUT_RETENTION_SECONDS
    out = {}
    for name, samples in history.items():
        rx = [0.0] * bucket_count
        tx = [0.0] * bucket_count
        counts = [0] * bucket_count
        for sample in samples:
            try:
                ts = float(sample.get("ts", 0))
                rx_bps = float(sample.get("rx_bps", 0) or 0)
                tx_bps = float(sample.get("tx_bps", 0) or 0)
            except Exception:
                continue
            idx = int((ts - start) / bucket_seconds)
            if 0 <= idx < bucket_count:
                rx[idx] += max(0.0, rx_bps)
                tx[idx] += max(0.0, tx_bps)
                counts[idx] += 1
        for i, count in enumerate(counts):
            if count:
                rx[i] /= count
                tx[i] /= count
        out[name] = {"rx": rx, "tx": tx}
    return out

def _tcpdump_bin() -> str:
    return next((p for p in ("/usr/bin/tcpdump", "/usr/sbin/tcpdump") if os.path.exists(p)), "")

def _load_dns_stats() -> Dict[str, Any]:
    default = {"meta": {"capturing": False, "error": "", "updated": 0}, "peers": {}}
    content = ""
    try:
        with open(DNS_STATS_DB, "r", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        return default
    except PermissionError:
        out, rc = _sudo_cat(DNS_STATS_DB)
        if rc != 0 or not out:
            return default
        content = out
    except Exception:
        return default
    try:
        stats = json.loads(content)
    except Exception:
        return default
    if not isinstance(stats, dict):
        return default
    if not isinstance(stats.get("meta"), dict):
        stats["meta"] = dict(default["meta"])
    if not isinstance(stats.get("peers"), dict):
        stats["peers"] = {}
    return stats

def _save_dns_stats(stats: Dict[str, Any]) -> None:
    _write_json_file_root(DNS_STATS_DB, stats)

def _prune_dns_stats(stats: Dict[str, Any], now: float = None) -> Dict[str, Any]:
    cutoff_bucket = int(((now if now is not None else time.time()) - DNS_STATS_RETENTION_SECONDS) // 3600)
    peers = stats.get("peers", {})
    for name in list(peers.keys()):
        buckets = peers[name]
        if not isinstance(buckets, dict):
            del peers[name]
            continue
        for b in list(buckets.keys()):
            try:
                if int(b) < cutoff_bucket:
                    del buckets[b]
            except (TypeError, ValueError):
                del buckets[b]
        if not buckets:
            del peers[name]
    return stats

def _update_dns_meta(stats: Dict[str, Any], capturing: bool = None, error: str = None, force_save: bool = False) -> None:
    meta = stats.setdefault("meta", {"capturing": False, "error": "", "updated": 0})
    changed = force_save
    if capturing is not None and bool(meta.get("capturing")) != capturing:
        meta["capturing"] = capturing
        changed = True
    if error is not None and str(meta.get("error", "")) != error:
        meta["error"] = error
        changed = True
    if changed:
        meta["updated"] = int(time.time())
        _save_dns_stats(stats)

def _dns_enabled_peer_map() -> Dict[str, str]:
    """Tunnel IP -> peer name for every peer with domain monitoring switched on."""
    out = {}
    for name, meta in _load_peers_db().items():
        if isinstance(meta, dict) and meta.get("monitor_dns"):
            ip = _ip_from_allowed_ips(meta.get("address", ""))
            if ip:
                out[ip] = name
    return out

_DNS_QUERY_RE = re.compile(r"\bIP6?\s+(\S+)\.\d+\s+>\s+\S+\.(?:53|domain):\s+(.*)$")
_DNS_QNAME_RE = re.compile(r"\s(?:A|AAAA|HTTPS)\?\s+(\S+)")
_DNS_DOMAIN_OK = re.compile(r"[a-z0-9._-]{1,253}")

def _parse_dns_query(line: str) -> Tuple[str, str]:
    m = _DNS_QUERY_RE.search(line)
    if not m:
        return None
    q = _DNS_QNAME_RE.search(" " + m.group(2))
    if not q:
        return None
    domain = q.group(1).rstrip(".").lower()
    if "." not in domain or domain.endswith(".arpa") or not _DNS_DOMAIN_OK.fullmatch(domain):
        return None
    return m.group(1), domain

def _record_dns_query(stats: Dict[str, Any], name: str, domain: str, now: float) -> None:
    bucket = str(int(now // 3600))
    hour = stats.setdefault("peers", {}).setdefault(name, {}).setdefault(bucket, {})
    try:
        hour[domain] = int(hour.get(domain, 0)) + 1
    except (TypeError, ValueError):
        hour[domain] = 1

def _dns_capture_session(stats: Dict[str, Any], recent: Dict[Tuple[str, str], float]) -> str:
    """Run one tcpdump session until all toggles turn off or tcpdump dies.
    Returns '' on clean stop or an error string for the UI."""
    import select
    proc = subprocess.Popen(
        [SUDO_BIN, "-n", _tcpdump_bin(), "-i", WG_IFACE, "-l", "-n", "udp", "dst", "port", "53"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    _update_dns_meta(stats, capturing=True, error="")
    ip_map = _dns_enabled_peer_map()
    ip_map_ts = time.time()
    last_save = time.time()
    last_prune = time.time()
    err = ""
    try:
        while True:
            now = time.time()

            if now - ip_map_ts >= 5:
                ip_map = _dns_enabled_peer_map()
                ip_map_ts = now
                enabled_names = set(ip_map.values())
                for pname in list(stats.get("peers", {}).keys()):
                    if pname not in enabled_names:
                        del stats["peers"][pname]
                if not ip_map:
                    break
            if proc.poll() is not None:
                tail = ""
                try:
                    tail = (proc.stdout.read() or "").strip().splitlines()[-1:]
                    tail = tail[0] if tail else ""
                except Exception:
                    tail = ""
                err = tail or "tcpdump stopped unexpectedly"
                break
            ready, _, _ = select.select([proc.stdout], [], [], 1.0)
            if not ready:

                for k in [k for k, t in recent.items() if now - t > 30]:
                    recent.pop(k, None)
                if now - last_save >= DNS_STATS_FLUSH_SECONDS:
                    _prune_dns_stats(stats, now)
                    _save_dns_stats(stats)
                    last_save = now
                continue
            line = proc.stdout.readline()
            if not line:
                continue
            low = line.lower()
            if "password is required" in low or "permission denied" in low or "no such device" in low or "syntax error" in low:
                err = line.strip()
                break
            parsed = _parse_dns_query(line)
            if not parsed:
                continue
            ip, domain = parsed
            name = ip_map.get(ip)
            if not name:
                continue
            key = (ip, domain)
            # Browsers fire duplicate A/AAAA lookups back to back — collapse
            # repeats of the same (peer, domain) within a couple of seconds.
            if now - recent.get(key, 0) < 2.0:
                continue
            recent[key] = now
            _record_dns_query(stats, name, domain, now)
            if now - last_prune >= 60:
                _prune_dns_stats(stats, now)
                last_prune = now
            if now - last_save >= DNS_STATS_FLUSH_SECONDS:
                _save_dns_stats(stats)
                last_save = now
    finally:
        try:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except Exception:
                    proc.kill()
        except Exception:
            pass
    _prune_dns_stats(stats, time.time())
    _update_dns_meta(stats, capturing=False, error=err, force_save=True)
    return err

def _dns_acquire_capture_lock():
    import fcntl
    try:
        f = open(DNS_MONITOR_LOCK, "w")
        fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return f
    except Exception:
        try:
            f.close()
        except Exception:
            pass
        return None

def _bg_dns_monitor_loop() -> None:
    """Own the tcpdump capture: start it while any peer opts in, stop otherwise."""
    time.sleep(_BG_INIT_DELAY)
    recent: Dict[Tuple[str, str], float] = {}
    lock_fd = None
    warned_missing = False
    while True:
        try:
            if not _dns_enabled_peer_map():
                time.sleep(5)
                continue

            if lock_fd is None:
                lock_fd = _dns_acquire_capture_lock()
            if lock_fd is None:
                time.sleep(7)
                continue
            if not _tcpdump_bin():
                if not warned_missing:
                    stats = _load_dns_stats()
                    _update_dns_meta(stats, capturing=False, error="tcpdump is not installed on the server", force_save=True)
                    warned_missing = True
                time.sleep(30)
                continue
            warned_missing = False
            stats = _load_dns_stats()
            err = _dns_capture_session(stats, recent)
            if err:
                app.logger.warning("dns_monitor session ended: %s", err)
                time.sleep(10)
        except Exception:
            app.logger.exception("dns_monitor_loop_failed")
            time.sleep(10)

def _dns_top_domains(name: str, limit: int = 30) -> Dict[str, Any]:
    stats = _load_dns_stats()
    _prune_dns_stats(stats, time.time())
    buckets = stats.get("peers", {}).get(name, {})
    counts: Dict[str, int] = {}
    last: Dict[str, int] = {}
    if isinstance(buckets, dict):
        for b, hour in buckets.items():
            try:
                bt = int(b) * 3600
            except (TypeError, ValueError):
                bt = 0
            if not isinstance(hour, dict):
                continue
            for d, c in hour.items():
                try:
                    c = int(c)
                except (TypeError, ValueError):
                    continue
                counts[d] = counts.get(d, 0) + c
                last[d] = max(last.get(d, 0), bt)
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]
    meta = stats.get("meta", {}) if isinstance(stats.get("meta"), dict) else {}
    peer_meta = _load_peers_db().get(name) or {}
    return {
        "enabled": bool(peer_meta.get("monitor_dns")),
        "capturing": bool(meta.get("capturing")),
        "error": str(meta.get("error", "")),
        "total": sum(counts.values()),
        "unique": len(counts),
        "domains": [{"domain": d, "count": counts[d], "last": last[d]} for d, _ in ranked],
    }

def _endpoint_ip(endpoint: str) -> str:
    endpoint = str(endpoint or "").strip()
    if not endpoint or endpoint == "(none)" or endpoint == "—":
        return ""
    host = endpoint
    if endpoint.startswith("["):
        end = endpoint.find("]")
        if end > 0:
            host = endpoint[1:end]
    elif endpoint.count(":") == 1:
        host = endpoint.rsplit(":", 1)[0]
    try:
        ipaddress.ip_address(host)
        return host
    except Exception:
        return ""

def _ip_from_allowed_ips(allowed_ips: str) -> str:
    for piece in re.split(r"[,\s]+", str(allowed_ips or "").strip()):
        if not piece:
            continue
        try:
            iface = ipaddress.ip_interface(piece)
            if iface.network.prefixlen == 0:
                continue
            return str(iface.ip)
        except Exception:
            continue
    return ""

def _ping_ip(ip: str) -> Dict[str, Any]:
    try:
        ipaddress.ip_address(ip)
    except Exception:
        return {"status": "invalid", "ms": None, "out": ""}
    ping_bin = next((p for p in ("/bin/ping", "/usr/bin/ping") if os.path.exists(p)), "ping")
    args = [ping_bin, "-c", "1", "-W", "1", ip]
    out = ""
    rc = 1
    try:
        r = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=2)
        out = r.stdout or ""
        rc = r.returncode
    except Exception as e:
        out = str(e)
    if rc != 0 and ping_bin != "ping":
        out, rc = _sudo(args)
    m = re.search(r"time[=<]([\d.]+)\s*ms", out)
    if not m:
        return {"status": "timeout" if rc != 0 else "unknown", "ms": None, "out": out[-300:]}
    return {"status": "ok", "ms": round(float(m.group(1)), 1), "out": out[-300:]}

def _lookup_location(ip: str) -> Dict[str, Any]:
    try:
        addr = ipaddress.ip_address(ip)
    except Exception:
        return {"label": "—"}
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved:
        return {"ip": ip, "label": "Private network"}
    cached = _geo_cache.get(ip)
    now = time.time()
    if cached and now - cached.get("ts", 0) < GEO_CACHE_SECONDS:
        return cached.get("data", {"ip": ip, "label": "—"})
    data = {"ip": ip, "label": "—"}
    try:
        url = f"https://ipwho.is/{ip}"
        with urllib.request.urlopen(url, timeout=3) as res:
            raw = json.loads(res.read().decode())
        if raw.get("success"):
            city = str(raw.get("city") or "").strip()
            region = str(raw.get("region") or "").strip()
            country = str(raw.get("country") or "").strip()
            parts = [p for p in (city, region, country) if p]
            lat = raw.get("latitude")
            lng = raw.get("longitude")
            data = {
                "ip": ip,
                "city": city,
                "region": region,
                "country": country,
                "label": ", ".join(parts) if parts else country or ip,
                "lat": float(lat) if lat is not None else None,
                "lng": float(lng) if lng is not None else None,
            }
    except Exception:
        pass
    _geo_cache[ip] = {"ts": now, "data": data}
    return data

def _server_pubkey() -> str:
    if os.path.exists("/usr/bin/wg"):
        o,c=_sudo(["/usr/bin/wg","show",WG_IFACE,"public-key"]) 
    else:
        o,c=_run(f"wg show {WG_IFACE} public-key || true")
    if o.strip():
        return o.strip()
    conf=_read_conf()
    priv=conf.get("Interface",{}).get("PrivateKey","").strip()
    if not priv:
        return ""
    o,c=_sudo(["/usr/bin/wg","pubkey"], input_data=(priv+"\n").encode())
    return o.strip()

def _load_peers_db() -> Dict[str,Any]:
    if not os.path.isdir(WG_DIR):
        _sudo(["/usr/bin/install","-d","-m","700",WG_DIR])
    if not os.path.isfile(PEERS_DB):
        return {}
    try:
        with open(PEERS_DB, "r", encoding="utf-8") as f:
            return json.load(f)
    except PermissionError:
        out, rc = _sudo_cat(PEERS_DB)
        if rc == 0 and out:
            try:
                return json.loads(out)
            except Exception:
                return {}
        return {}
    except Exception:
        return {}

def _save_peers_db(db: Dict[str,Any]) -> None:
    import tempfile
    fd,tmp_path = tempfile.mkstemp(prefix="peers.", suffix=".json.tmp", dir="/tmp")
    try:
        with os.fdopen(fd,"w",encoding="utf-8") as f:
            json.dump(db,f,indent=2)
        _sudo(["/usr/bin/install","-m","640","-o","root","-g","www-data",tmp_path,PEERS_DB])
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except:
            pass

def _load_handshake_cache() -> Dict[str, int]:
    try:
        with open(HANDSHAKE_CACHE, "r", encoding="utf-8") as f:
            return {k: int(v) for k, v in json.load(f).items()}
    except FileNotFoundError:
        return {}
    except PermissionError:
        out, rc = _sudo_cat(HANDSHAKE_CACHE)
        if rc == 0 and out:
            try:
                return {k: int(v) for k, v in json.loads(out).items()}
            except Exception:
                return {}
        return {}
    except Exception:
        return {}

def _flush_handshake_cache(cache: Dict[str, int]) -> None:
    import tempfile
    fd, tmp = tempfile.mkstemp(prefix="handshakes.", suffix=".json.tmp", dir="/tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(cache, f)
        try:
            os.replace(tmp, HANDSHAKE_CACHE)
            return
        except Exception:
            pass
        _sudo(["/usr/bin/install", "-m", "640", "-o", "root", "-g", "www-data", tmp, HANDSHAKE_CACHE])
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except:
            pass

def _get_handshake_cache() -> Dict[str, int]:
    if "_hs_cache" not in app.config:
        app.config["_hs_cache"] = _load_handshake_cache()
        app.config["_hs_cache_last_flush"] = 0.0
    return app.config["_hs_cache"]

def _update_handshake_cache(name: str, ts: int) -> None:
    cache = _get_handshake_cache()
    if ts > cache.get(name, 0):
        cache[name] = ts
        app.config["_hs_cache"] = cache
        now = time.time()
        last_flush = float(app.config.get("_hs_cache_last_flush", 0) or 0)
        if now - last_flush >= HANDSHAKE_FLUSH_SECONDS:
            _flush_handshake_cache(cache)
            app.config["_hs_cache_last_flush"] = now

def _load_data_budget_db() -> Dict[str, Any]:
    default = {
        "settings": {"enabled": True, "budget_gb": 50, "alerts": True, "reset_time": "00:00", "peer_budgets": {}, "enforcement": {"action": "none", "throttle_mbps": 5}},
        "period_start": 0,
        "baselines": {},
        "carryover": {},
        "last_totals": {},
        "alert_state": {},
    }
    content = ""
    try:
        with open(DATA_BUDGET_DB, "r", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        return default
    except PermissionError:
        out, rc = _sudo_cat(DATA_BUDGET_DB)
        if rc != 0:
            return default
        content = out
    except Exception:
        return default
    try:
        db = json.loads(content)
    except Exception:
        return default
    if not isinstance(db, dict):
        return default
    settings = db.get("settings") if isinstance(db.get("settings"), dict) else {}
    peer_budgets_raw = settings.get("peer_budgets", {})
    peer_budgets = {k: (v if v == "inf" else max(1, int(v or 1))) for k, v in peer_budgets_raw.items()} if isinstance(peer_budgets_raw, dict) else {}
    enf_raw = settings.get("enforcement") or {}
    enf_action = str(enf_raw.get("action", "none")).lower()
    if enf_action not in {"none", "throttle", "pause", "combined"}:
        enf_action = "none"
    try:
        enf_mbps = max(1, min(1000, int(enf_raw.get("throttle_mbps", 5) or 5)))
    except (TypeError, ValueError):
        enf_mbps = 5
    default["settings"].update({
        "enabled": bool(settings.get("enabled", default["settings"]["enabled"])),
        "budget_gb": max(1, int(settings.get("budget_gb", default["settings"]["budget_gb"]) or 50)),
        "alerts": bool(settings.get("alerts", default["settings"]["alerts"])),
        "reset_time": str(settings.get("reset_time", default["settings"]["reset_time"])),
        "peer_budgets": peer_budgets,
        "enforcement": {"action": enf_action, "throttle_mbps": enf_mbps},
    })
    default["enforce_state"] = db.get("enforce_state") if isinstance(db.get("enforce_state"), dict) else {}
    default["period_start"] = int(db.get("period_start", 0) or 0)
    default["baselines"] = db.get("baselines") if isinstance(db.get("baselines"), dict) else {}
    default["carryover"] = db.get("carryover") if isinstance(db.get("carryover"), dict) else {}
    default["last_totals"] = db.get("last_totals") if isinstance(db.get("last_totals"), dict) else {}
    default["alert_state"] = db.get("alert_state") if isinstance(db.get("alert_state"), dict) else {}
    default["alert_log"] = db.get("alert_log") if isinstance(db.get("alert_log"), list) else []
    return default

def _save_data_budget_db(db: Dict[str, Any]) -> None:
    import tempfile
    fd,tmp_path = tempfile.mkstemp(prefix="data-budget.", suffix=".json.tmp", dir="/tmp")
    try:
        with os.fdopen(fd,"w",encoding="utf-8") as f:
            json.dump(db, f, indent=2)
        try:
            os.makedirs(os.path.dirname(DATA_BUDGET_DB), exist_ok=True)
            os.replace(tmp_path, DATA_BUDGET_DB)
            return
        except Exception:
            pass
        _sudo(["/usr/bin/install","-m","640","-o","root","-g","www-data",tmp_path,DATA_BUDGET_DB])
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except:
            pass

def _valid_reset_time(value: Any) -> bool:
    return bool(re.match(r"^\d{2}:\d{2}$", str(value or ""))) and 0 <= int(str(value)[:2]) <= 23 and 0 <= int(str(value)[3:]) <= 59

def _budget_period_start(reset_time: str, now: float = None) -> int:
    now_dt = datetime.datetime.fromtimestamp(now or time.time())
    hour, minute = [int(x) for x in reset_time.split(":", 1)]
    start = now_dt.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if now_dt < start:
        start -= datetime.timedelta(days=1)
    return int(start.timestamp())

def _peer_current_totals(issued: List[Dict[str, Any]], live: List[Dict[str, Any]]) -> Dict[str, int]:
    out = {p.get("name", ""): 0 for p in issued if p.get("name")}
    for p in live:
        name = p.get("name") or p.get("cn")
        if not name:
            continue
        out[str(name)] = int(p.get("bytes_recv", 0) or 0) + int(p.get("bytes_sent", 0) or 0)
    return out

def _tc_peer_handle(name: str) -> int:
    """Deterministic handle in [1000, 9999] for tc/iptables per-peer throttling."""
    h = 5381
    for b in name.encode("utf-8"):
        h = ((h << 5) + h + b) & 0xFFFFFFFF
    return h % 9000 + 1000

def _tc_available() -> bool:
    _, rc = _sudo([TC_BIN, "qdisc", "show", "dev", WG_IFACE])
    return rc == 0

def _ensure_tc_sudo() -> bool:
    """Older installs miss /usr/sbin/tc in sudoers; drop in an extra rule so throttling works after updates."""
    if _tc_available():
        return True
    import tempfile
    fd, tmp_path = tempfile.mkstemp(prefix="wg-dash-sudo.", dir="/tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(f"www-data ALL=(root) NOPASSWD: {TC_BIN}\n")
        _sudo(["/usr/bin/install", "-m", "440", "-o", "root", "-g", "root", tmp_path, "/etc/sudoers.d/wg-dashboard-tc"])
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
    ok = _tc_available()
    if ok:
        app.logger.info("tc_sudo_selfheal_ok bin=%s", TC_BIN)
    else:
        app.logger.error("tc_unavailable: throttling disabled — add '%s' to /etc/sudoers.d/wg-dashboard", TC_BIN)
    return ok

def _ensure_htb_qdisc() -> None:
    o, rc = _sudo([TC_BIN, "qdisc", "show", "dev", WG_IFACE])
    if rc != 0:
        raise RuntimeError(f"tc unavailable: {o[:200]}")
    if "htb" not in o:
        _sudo([TC_BIN, "qdisc", "add", "dev", WG_IFACE, "root", "handle", "1:", "htb", "default", "1"])
        _sudo([TC_BIN, "class", "add", "dev", WG_IFACE, "parent", "1:", "classid", "1:1", "htb", "rate", "10gbit"])

def _ensure_ingress_qdisc() -> None:
    o, _ = _sudo([TC_BIN, "qdisc", "show", "dev", WG_IFACE, "ingress"])
    if "ingress" not in o:
        _sudo([TC_BIN, "qdisc", "add", "dev", WG_IFACE, "handle", "ffff:", "ingress"])

def _apply_peer_throttle(name: str, addr: str, mbps: int) -> None:
    handle = _tc_peer_handle(name)
    peer_ip = addr.split("/")[0]
    if not peer_ip:
        raise RuntimeError("peer has no address")
    rate = f"{max(1, mbps)}mbit"
    burst = f"{max(32, mbps * 16)}k"
    _ensure_htb_qdisc()
    o, _ = _sudo([TC_BIN, "class", "show", "dev", WG_IFACE, "classid", f"1:{handle}"])
    verb = "change" if str(handle) in o else "add"
    _, rc = _sudo([TC_BIN, "class", verb, "dev", WG_IFACE, "parent", "1:", "classid", f"1:{handle}", "htb", "rate", rate, "ceil", rate])
    if rc != 0:
        raise RuntimeError(f"tc class {verb} failed for {name}")
    _sudo([TC_BIN, "filter", "del", "dev", WG_IFACE, "parent", "1:0", "prio", "1", "handle", str(handle), "fw"])
    _, rc = _sudo([TC_BIN, "filter", "add", "dev", WG_IFACE, "parent", "1:0", "protocol", "all", "prio", "1", "handle", str(handle), "fw", "classid", f"1:{handle}"])
    if rc != 0:
        raise RuntimeError(f"tc filter add failed for {name}")
    for chain in ("FORWARD", "OUTPUT"):
        _, c = _sudo([IPTABLES_BIN, "-t", "mangle", "-C", chain, "-d", peer_ip, "-j", "MARK", "--set-mark", str(handle)])
        if c != 0:
            _sudo([IPTABLES_BIN, "-t", "mangle", "-A", chain, "-d", peer_ip, "-j", "MARK", "--set-mark", str(handle)])
    _ensure_ingress_qdisc()
    _sudo([TC_BIN, "filter", "del", "dev", WG_IFACE, "parent", "ffff:", "prio", str(handle)])
    _sudo([TC_BIN, "filter", "add", "dev", WG_IFACE, "parent", "ffff:", "protocol", "ip", "prio", str(handle),
           "u32", "match", "ip", "src", f"{peer_ip}/32", "police", "rate", rate, "burst", burst, "drop", "flowid", ":1"])

def _remove_peer_throttle(name: str, addr: str) -> None:
    handle = _tc_peer_handle(name)
    peer_ip = addr.split("/")[0]
    if peer_ip:
        for chain in ("FORWARD", "OUTPUT"):
            _sudo([IPTABLES_BIN, "-t", "mangle", "-D", chain, "-d", peer_ip, "-j", "MARK", "--set-mark", str(handle)])
    _sudo([TC_BIN, "filter", "del", "dev", WG_IFACE, "parent", "ffff:", "prio", str(handle)])
    _sudo([TC_BIN, "filter", "del", "dev", WG_IFACE, "parent", "1:0", "prio", "1", "handle", str(handle), "fw"])
    _sudo([TC_BIN, "class", "del", "dev", WG_IFACE, "classid", f"1:{handle}"])

def _enforce_budgets(db: Dict[str, Any], rows: List[Dict[str, Any]], settings: Dict[str, Any], total_pct: float) -> bool:
    """Apply or remove per-peer enforcement based on budget usage. Returns True if state changed."""
    enf = settings.get("enforcement") or {}
    action = str(enf.get("action", "none")).lower()
    throttle_mbps = max(1, int(enf.get("throttle_mbps", 5) or 5))
    enforce_state = db.setdefault("enforce_state", {})
    peer_budgets = settings.get("peer_budgets", {})
    peer_db = _load_peers_db()
    peer_db_changed = False
    changed = False

    if action == "none":
        for name, state in list(enforce_state.items()):
            if state == "none":
                continue
            meta = peer_db.get(name, {})
            if state == "throttled":
                try: _remove_peer_throttle(name, meta.get("address", ""))
                except Exception: pass
            elif state == "paused" and meta.get("paused"):
                try:
                    _sudo(["/usr/bin/wg", "set", WG_IFACE, "peer", meta.get("public_key", ""), "allowed-ips", meta.get("address", "")])
                    meta["paused"] = False
                    peer_db[name] = meta
                    peer_db_changed = True
                except Exception: pass
            enforce_state[name] = "none"
            changed = True
        if peer_db_changed:
            _save_peers_db(peer_db)
        return changed

    known = {row["name"] for row in rows}
    for name in list(enforce_state.keys()):
        if name in known or enforce_state.get(name) == "none":
            continue
        meta = peer_db.get(name, {})
        if enforce_state[name] == "throttled":
            try: _remove_peer_throttle(name, meta.get("address", ""))
            except Exception: pass
        enforce_state.pop(name, None)
        changed = True

    for row in rows:
        name = row["name"]
        used = row["bytes"]
        meta = peer_db.get(name, {})
        pub = meta.get("public_key", "")
        addr = meta.get("address", "")
        if not pub or not addr:
            continue
        pb = peer_budgets.get(name)
        if pb and pb != "inf":
            peer_cap = int(pb) * 1024 * 1024 * 1024
            pct = (used / peer_cap * 100) if peer_cap else 0
        else:
            pct = total_pct
        prev = enforce_state.get(name, "none")
        if action == "pause":
            desired = "paused" if pct >= 100 else "none"
        elif action == "throttle":
            desired = "throttled" if pct >= 100 else "none"
        elif action == "combined":
            desired = "paused" if pct >= 100 else ("throttled" if pct >= 80 else "none")
        else:
            desired = "none"
        if desired == prev:
            continue
        if prev == "throttled":
            try: _remove_peer_throttle(name, addr)
            except Exception as e: app.logger.warning("throttle_remove_failed peer=%s err=%s", name, e)
        if prev == "paused" and desired != "paused" and meta.get("paused"):
            try:
                _sudo(["/usr/bin/wg", "set", WG_IFACE, "peer", pub, "allowed-ips", addr])
                meta["paused"] = False
                peer_db[name] = meta
                peer_db_changed = True
            except Exception as e: app.logger.warning("resume_failed peer=%s err=%s", name, e)
        if desired == "throttled":
            try: _apply_peer_throttle(name, addr, throttle_mbps)
            except Exception as e:
                app.logger.error("throttle_apply_failed peer=%s err=%s", name, e)
                desired = prev
        elif desired == "paused" and not meta.get("paused"):
            try:
                _sudo(["/usr/bin/wg", "set", WG_IFACE, "peer", pub, "remove"])
                meta["paused"] = True
                peer_db[name] = meta
                peer_db_changed = True
            except Exception as e:
                app.logger.error("pause_apply_failed peer=%s err=%s", name, e)
                desired = prev
        if desired != prev:
            enforce_state[name] = desired
            app.logger.info("budget_enforce peer=%s prev=%s now=%s pct=%.1f action=%s", name, prev, desired, pct, action)
            if desired == "throttled":
                _log_dashboard_event(f"peer '{name}' throttled to {throttle_mbps} Mbps — budget at {pct:.0f}%", "warn")
            elif desired == "paused":
                _log_dashboard_event(f"peer '{name}' paused — budget exceeded ({pct:.0f}%)", "warn")
            else:
                _log_dashboard_event(f"peer '{name}' budget enforcement lifted")
            changed = True

    if peer_db_changed:
        _save_peers_db(peer_db)
    return changed

def _data_budget_state(issued: List[Dict[str, Any]], live: List[Dict[str, Any]], persist: bool = True) -> Dict[str, Any]:
    with _budget_lock:
        return _data_budget_state_locked(issued, live, persist)

def _data_budget_state_locked(issued: List[Dict[str, Any]], live: List[Dict[str, Any]], persist: bool = True) -> Dict[str, Any]:
    db = _load_data_budget_db()
    settings = db["settings"]
    if not _valid_reset_time(settings.get("reset_time")):
        settings["reset_time"] = "00:00"
    period_start = _budget_period_start(settings["reset_time"])
    totals = _peer_current_totals(issued, live)
    _enforce_snap = db.get("enforce_state", {})
    _last_snap = db.get("last_totals", {})
    for _name, _total in totals.items():
        if _total == 0 and _enforce_snap.get(_name) == "paused":
            totals[_name] = int(_last_snap.get(_name, 0) or 0)
    changed = False
    if int(db.get("period_start", 0) or 0) != period_start:
        app.logger.info("data_budget_reset period_start=%s reset_time=%s peers=%s", period_start, settings["reset_time"], len(totals))
        if int(db.get("period_start", 0) or 0):
            _log_dashboard_event(f"data budget period reset (daily reset at {settings['reset_time']})")
        db["period_start"] = period_start
        db["baselines"] = {name: total for name, total in totals.items()}
        db["carryover"] = {}
        db["last_totals"] = dict(totals)
        db["alert_state"] = {}
        changed = True
    baselines = db.setdefault("baselines", {})
    carryover = db.setdefault("carryover", {})
    last_totals = db.setdefault("last_totals", {})
    rows = []
    total_used = 0
    for name, current in totals.items():
        base = baselines.get(name)
        if base is None or current < int(base or 0):
            previous_current = int(last_totals.get(name, base or current) or 0)
            previous_used = max(0, previous_current - int(base or 0))
            carryover[name] = int(carryover.get(name, 0) or 0) + previous_used
            app.logger.info("data_budget_counter_reset peer=%s carryover=%s previous_current=%s current=%s", name, carryover[name], previous_current, current)
            baselines[name] = current
            base = current
            changed = True
        used = int(carryover.get(name, 0) or 0) + max(0, current - int(base or 0))
        if int(last_totals.get(name, -1) or -1) != current:
            last_totals[name] = current
            changed = True
        total_used += used
        rows.append({"name": name, "bytes": used, "current_total": current, "baseline": int(base or 0)})
    rows.sort(key=lambda x: x["bytes"], reverse=True)
    budget_enabled = bool(settings.get("enabled", True))
    budget_bytes = int(settings["budget_gb"]) * 1024 * 1024 * 1024
    pct = (total_used / budget_bytes * 100) if budget_bytes else 0
    if budget_enabled and settings.get("alerts", True):
        state = db.setdefault("alert_state", {})
        level = "100" if pct >= 100 else "90" if pct >= 90 else "70" if pct >= 70 else ""
        if level and state.get("last_level") != level:
            app.logger.warning("data_budget_alert threshold=%s pct=%.1f used=%s budget_gb=%s", level, pct, total_used, settings["budget_gb"])
            alert_log = db.setdefault("alert_log", [])
            alert_log.append({"ts": int(time.time()), "level": level, "pct": round(pct, 1), "used": total_used, "budget_gb": settings["budget_gb"]})
            del alert_log[:-50]
            state["last_level"] = level
            changed = True
        elif not level and state.get("last_level"):
            state.pop("last_level", None)
            changed = True
        peer_budgets = settings.get("peer_budgets", {})
        peer_state = state.setdefault("peers", {})
        seen = set()
        for row in rows:
            name = row["name"]
            pb = peer_budgets.get(name)
            if not pb or pb == "inf":
                continue
            seen.add(name)
            peer_cap = int(pb) * 1024 * 1024 * 1024
            ppct = (row["bytes"] / peer_cap * 100) if peer_cap else 0
            plevel = "100" if ppct >= 100 else "90" if ppct >= 90 else "70" if ppct >= 70 else ""
            if plevel and peer_state.get(name) != plevel:
                app.logger.warning("data_budget_peer_alert peer=%s threshold=%s pct=%.1f used=%s budget_gb=%s", name, plevel, ppct, row["bytes"], pb)
                alert_log = db.setdefault("alert_log", [])
                alert_log.append({"ts": int(time.time()), "level": plevel, "pct": round(ppct, 1), "used": row["bytes"], "budget_gb": pb, "peer": name})
                del alert_log[:-50]
                peer_state[name] = plevel
                changed = True
            elif not plevel and peer_state.get(name):
                peer_state.pop(name, None)
                changed = True
        for name in list(peer_state.keys()):
            if name not in seen:
                peer_state.pop(name, None)
                changed = True
    if persist:
        try:
            enf_settings = settings if budget_enabled else {**settings, "enforcement": {"action": "none", "throttle_mbps": (settings.get("enforcement") or {}).get("throttle_mbps", 5)}}
            if _enforce_budgets(db, rows, enf_settings, pct):
                changed = True
        except Exception:
            app.logger.exception("budget_enforce_failed")
    if changed and persist:
        _save_data_budget_db(db)
    return {
        "settings": settings,
        "period_start": period_start,
        "period_start_iso": datetime.datetime.fromtimestamp(period_start).isoformat(),
        "total": total_used,
        "budget_bytes": budget_bytes,
        "pct": pct,
        "peers": rows,
        "enforce_state": db.get("enforce_state", {}),
    }

def _valid_name(x: Any) -> bool:
    return bool(re.match(r"^[A-Za-z0-9._-]{1,64}$", str(x or "").strip()))

def _valid_ip(x: Any) -> bool:
    try:
        ipaddress.ip_interface(str(x))
        return True
    except:
        return False

def _server_subnets() -> List[ipaddress.IPv4Network]:
    nets=[]
    conf=_read_conf()
    addrs=conf.get("Interface",{}).get("Address","") or SERVER_ADDR_ENV
    for part in re.split(r"[,\s]+", addrs.strip()):
        part=part.strip()
        if not part:
            continue
        try:
            iface=ipaddress.ip_interface(part)
            if isinstance(iface.ip, ipaddress.IPv4Address):
                nets.append(iface.network)
        except:
            continue
    return nets

def _assigned_ips() -> List[ipaddress.IPv4Interface]:
    conf=_read_conf()
    res=[]
    for peer in conf.get("Peers",[]):
        a=peer.get("AllowedIPs","").strip()
        for piece in re.split(r"[,\s]+", a):
            piece=piece.strip()
            if not piece: continue
            try:
                iface=ipaddress.ip_interface(piece)
                res.append(iface)
            except:
                continue
    return res

def _next_client_ip() -> str:
    nets=_server_subnets()
    if not nets:
        return ""
    net=nets[0]
    used=set()
    for iface in _assigned_ips():
        if iface.ip in net:
            used.add(int(iface.ip))
    srv_iface=_read_conf().get("Interface",{}).get("Address","") or SERVER_ADDR_ENV
    for part in re.split(r"[,\s]+", srv_iface.strip()):
        part=part.strip()
        if not part:
            continue
        try:
            ii=ipaddress.ip_interface(part)
            if ii.ip in net:
                used.add(int(ii.ip))
        except:
            pass
    for host in net.hosts():
        if host == net.network_address or host == net.broadcast_address:
            continue
        if str(host).endswith(".1"):
            continue
        if int(host) not in used:
            return f"{host}/32"
    return ""

def list_clients() -> List[Dict[str, Any]]:
    db = _load_peers_db()

    if os.path.exists("/usr/bin/wg"):
        show, c = _sudo(["/usr/bin/wg", "show", WG_IFACE, "dump"])
    else:
        show, c = _run(f"wg show {WG_IFACE} dump || true")

    live = []
    lines = [ln for ln in show.splitlines()[1:] if ln.strip()] 
    now = int(time.time())

    for ln in lines:
        p = ln.split("\t")
        if len(p) < 8:
            continue

        pub = p[0].strip()
        endpoint = p[2].strip()
        allowed = p[3].strip()

        try:
            lh_raw = int(p[4]) 
        except ValueError:
            lh_raw = 0

        try:
            rx = int(p[5])
        except ValueError:
            rx = 0

        try:
            tx = int(p[6])
        except ValueError:
            tx = 0

        name = None
        for k, v in db.items():
            if v.get("public_key") == pub:
                name = k
                break

        if lh_raw > 0 and lh_raw < now + 10:
            if name:
                _update_handshake_cache(name, lh_raw)
            effective_lh = lh_raw
        else:
            effective_lh = _get_handshake_cache().get(name or "", 0) if name else 0

        live.append({
            "name": name or pub[:8],
            "cn": name or pub[:8],
            "remote": endpoint,
            "bytes_recv": rx,   
            "bytes_sent": tx,   
            "last_handshake": effective_lh,
            "since": (
                datetime.datetime.utcfromtimestamp(effective_lh).strftime("%Y-%m-%d %H:%M:%S")
                if effective_lh > 0 else ""
            ),
            "allowed_ips": allowed,
            "public_key": pub,
        })

    issued = []
    for name, meta in db.items():
        issued.append({
            "name": name,
            "status": "active",
            "created": meta.get("created", ""),
            "public_key": meta.get("public_key", ""),
            "ip": meta.get("address", ""),
            "note": meta.get("note", ""),
            "owner": meta.get("owner", ""),
            "long_note": meta.get("long_note", ""),
            "dns": meta.get("dns", ""),
            "client_allowed_ips": meta.get("client_allowed_ips", ""),
            "keepalive": meta.get("keepalive", "25"),
            "search_domains": meta.get("search_domains", ""),
            "mtu": meta.get("mtu", ""),
            "listen_port": meta.get("listen_port", ""),
            "endpoint": meta.get("endpoint", ""),
            "device": meta.get("device", ""),
            "paused": bool(meta.get("paused", False)),
            "monitor_dns": bool(meta.get("monitor_dns", False)),
        })

    return issued, live

def gen_client_conf(name: str) -> Tuple[str,str]:
    db=_load_peers_db()
    meta=db.get(name) or {}
    if not meta:
        lname = name.lower()
        for k,v in db.items():
            if k.lower() == lname:
                meta = v
                name = k
                break
    if not meta:
        raise FileNotFoundError("peer not found")
    client_priv=meta["private_key"]
    client_addr=meta["address"]
    conf=_read_conf()
    dns=meta.get("dns","").strip() or conf.get("Interface",{}).get("DNS","").strip() or CLIENT_DNS
    search_domains=meta.get("search_domains","").strip()
    mtu=meta.get("mtu","").strip()
    client_lp=meta.get("listen_port","").strip()
    srv_pub=_server_pubkey()
    lp=conf.get("Interface",{}).get("ListenPort",str(WG_PORT))
    endpoint=meta.get("endpoint","").strip() or f"{_get_endpoint_host()}:{lp}"
    allowed_client=meta.get("client_allowed_ips","").strip() or "0.0.0.0/0, ::/0"
    keepalive=str(meta.get("keepalive","25") or "25")
    txt=[]
    txt.append("[Interface]")
    txt.append(f"PrivateKey = {client_priv}")
    txt.append(f"Address = {client_addr}")
    if dns.lower()!="none":
        txt.append(f"DNS = {dns}" + (f", {search_domains}" if search_domains else ""))
    if mtu:
        txt.append(f"MTU = {mtu}")
    if client_lp:
        txt.append(f"ListenPort = {client_lp}")
    txt.append("")
    txt.append("[Peer]")
    txt.append(f"PublicKey = {srv_pub}")
    txt.append(f"AllowedIPs = {allowed_client}")
    txt.append(f"Endpoint = {endpoint}")
    if keepalive != "0":
        txt.append(f"PersistentKeepalive = {keepalive}")
    return "\n".join(txt).strip()+"\n", meta.get("public_key","")

def _ensure_peer_removed_from_conf(pubkey: str) -> None:
    data=_read_conf()
    data["Peers"]=[p for p in data.get("Peers",[]) if p.get("PublicKey","").strip()!=pubkey.strip()]
    _write_conf(data)

@app.route("/api/auth/check")
def auth_check():
    return jsonify({
        "authenticated": bool(session.get("authenticated")),
        "setup_required": not bool(DASHBOARD_PASSWORD_HASH),
        "version": _local_version(),
        "service_active": service_active(),
    })

@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    if DASHBOARD_PASSWORD_HASH and check_password_hash(DASHBOARD_PASSWORD_HASH, password):
        session.permanent = True
        session["authenticated"] = True
        return jsonify({"ok": True})
    _log_dashboard_event(f"failed dashboard login attempt from {request.remote_addr}", "warn")
    return jsonify({"error": "Invalid password"}), 401

@app.route("/api/auth/logout", methods=["POST"])
def auth_logout():
    session.clear()
    return jsonify({"ok": True})

@app.route("/api/auth/password", methods=["POST"])
def api_change_password():
    global DASHBOARD_PASSWORD_HASH
    data = request.get_json(silent=True) or {}
    current = str(data.get("current_password", ""))
    new_pw  = str(data.get("new_password", "")).strip()
    if not DASHBOARD_PASSWORD_HASH or not check_password_hash(DASHBOARD_PASSWORD_HASH, current):
        return jsonify({"ok": False, "error": "wrong_password", "hint": "Current password is incorrect"}), 403
    if len(new_pw) < 8:
        return jsonify({"ok": False, "error": "too_short", "hint": "New password must be at least 8 characters"}), 400
    h = generate_password_hash(new_pw)
    candidates = [_PASSWORD_HASH_FILE, os.path.join(os.path.dirname(__file__), ".dashboard_password_hash")]
    saved = False
    for path in candidates:
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(h)
            saved = True
            break
        except Exception:
            continue
    if not saved:
        return jsonify({"ok": False, "error": "save_failed", "hint": "Could not write password file"}), 500
    DASHBOARD_PASSWORD_HASH = h
    _log_dashboard_event("dashboard password changed")
    return jsonify({"ok": True})

@app.route("/setup")
def setup_page():
    if DASHBOARD_PASSWORD_HASH:
        return redirect(url_for("home"))
    return render_template("setup.html", mode="setup", display_version=_display_version(), service_active=service_active())

@app.route("/change-password")
def change_password_page():
    return render_template("setup.html", mode="change", display_version=_display_version(), service_active=service_active())

@app.route("/api/setup", methods=["POST"])
def api_setup():
    global DASHBOARD_PASSWORD_HASH
    if DASHBOARD_PASSWORD_HASH:
        return jsonify({"ok": False, "error": "already_configured"}), 403
    data = request.get_json(silent=True) or {}
    password = str(data.get("password", "")).strip()
    if len(password) < 8:
        return jsonify({"ok": False, "error": "too_short", "hint": "Password must be at least 8 characters"}), 400
    h = generate_password_hash(password)
    candidates = [_PASSWORD_HASH_FILE, os.path.join(os.path.dirname(__file__), ".dashboard_password_hash")]
    saved = False
    for path in candidates:
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(h)
            saved = True
            break
        except Exception:
            continue
    if not saved:
        return jsonify({"ok": False, "error": "save_failed", "hint": "Could not write password file. Check server permissions."}), 500
    DASHBOARD_PASSWORD_HASH = h
    session.permanent = True
    session["authenticated"] = True
    return jsonify({"ok": True})

def _is_welcomed() -> bool:
    if session.get("welcomed"):
        return True
    return os.path.isfile(WELCOME_FLAG) or os.path.isfile(_WELCOME_FLAG_FALLBACK)

def _set_welcomed() -> None:
    session["welcomed"] = True
    for _flag_path in (WELCOME_FLAG, _WELCOME_FLAG_FALLBACK):
        try:
            with open(_flag_path, "a"):
                pass
            return
        except Exception:
            pass

@app.route("/")
def home():
    if not _is_welcomed():
        return redirect(url_for("welcome"))
    issued,live=list_clients()
    data={
        "service_active":service_active(),
        "service_enabled":service_enabled(),
        "host_ip":HOST_IP,
        "udp_port":WG_PORT,
        "unit":UNIT,
        "local_listen":local_listening(WG_PORT),
        "ufw_open":ufw_allowed(WG_PORT),
        "ping_ok":ping_ok(),
        "ntp":timedate_ntp(),
        "clients":len(issued),
        "logs":logs_tail(60)
    }
    iface,_,_=read_bytes()
    return render_template("index.html",data=data,users=issued,iface=iface,app_version=_build_stamp())

@app.route("/welcome")
def welcome():
    return render_template("welcome.html")

@app.route("/mobile")
def mobile():
    return render_template("mobile.html", app_version=_build_stamp())

@app.route("/manifest.json")
def manifest():
    m = {
        "id": "/mobile",
        "name": "WireGuard Dashboard",
        "short_name": "WG Dashboard",
        "description": "WireGuard VPN peer management dashboard",
        "start_url": "/mobile",
        "scope": "/",
        "display": "standalone",
        "display_override": ["standalone", "fullscreen"],
        "orientation": "portrait",
        "background_color": "#F5EEE2",
        "theme_color": "#F5EEE2",
        "icons": [
            {
                "src": "/static/icons/apple-touch-icon.png",
                "sizes": "180x180",
                "type": "image/png",
                "purpose": "any"
            },
            {
                "src": "/static/icons/apple-touch-icon.svg",
                "sizes": "any",
                "type": "image/svg+xml",
                "purpose": "any maskable"
            }
        ]
    }
    resp = Response(json.dumps(m), mimetype="application/manifest+json")
    resp.headers["Cache-Control"] = "no-cache"
    return resp

@app.route("/service-worker.js")
def service_worker():
    js = (
        "self.addEventListener('install', function(e) { self.skipWaiting(); });\n"
        "self.addEventListener('activate', function(e) { e.waitUntil(clients.claim()); });\n"
        "self.addEventListener('fetch', function(e) {\n"
        "  if (e.request.method !== 'GET') return;\n"
        "  e.respondWith(fetch(e.request).catch(function() { return caches.match(e.request); }));\n"
        "});\n"
    )
    resp = Response(js, mimetype="application/javascript")
    resp.headers["Service-Worker-Allowed"] = "/"
    resp.headers["Cache-Control"] = "no-cache"
    return resp

@app.route("/api/welcome/dismiss", methods=["POST"])
def api_welcome_dismiss():
    _set_welcomed()
    return jsonify({"ok": True})

@app.route("/action/<what>", methods=["POST"])
def action(what: str):
    if what not in {"restart", "stop", "start"}:
        abort(400)
    if what=="restart":
        _sudo(["/usr/bin/systemctl","restart",UNIT])
    elif what=="stop":
        _sudo(["/usr/bin/systemctl","stop",UNIT])
    elif what=="start":
        _sudo(["/usr/bin/systemctl","start",UNIT])
    return redirect(url_for("home"))

@app.route("/api/status")
def api_status():
    try:
        iface,rx,tx=read_bytes()
    except:
        iface,rx,tx=WG_IFACE,0,0
    try:
        conf=_read_conf()
    except:
        conf={}
    try:
        issued,live=list_clients()
    except:
        issued,live=[],[]
    try:
        spark_history=_record_peer_spark_samples(live)
        peer_throughput_history=_peer_throughput_payload()
    except Exception:
        spark_history={}
        peer_throughput_history={}
    try:
        data_budget=_data_budget_state(issued, live)
        enforce_state=data_budget.get("enforce_state", {})
        for p in issued:
            p["throttled"] = enforce_state.get(p.get("name", ""), "none") == "throttled"
    except Exception:
        app.logger.exception("data_budget_status_failed")
        data_budget={"settings":{"budget_gb":50,"alerts":True,"reset_time":"00:00"},"total":0,"budget_bytes":50*1024*1024*1024,"pct":0,"peers":[]}
    try:
        ntp=timedate_ntp()
    except:
        ntp="unknown"
    lp=(conf.get("Interface",{}).get("ListenPort") or str(WG_PORT))
    payload={
        "service":{"active":False,"enabled":False,"unit":UNIT,"started_at":0},
        "network":{"host_ip":HOST_IP,"port":int(lp),"ufw_udp_open":False,"listening":False,"ping_ok":False,"iface":iface,"rx":rx,"tx":tx},
        "clients":{"count":len(issued),"issued":issued,"live":live,"status_updated":None,"spark_history":spark_history,"peer_throughput_history":peer_throughput_history},
        "data_budget":data_budget,
        "config":{
            "path":WG_CONF,
            "port":lp,
            "proto":"udp",
            "cipher":None,
            "auth":None,
            "push":[],
            "dhcp_option":[]
        },
        "time":{"ntp":ntp},
    }
    try:
        payload["service"]["active"]=service_active()
    except:
        pass
    try:
        payload["service"]["enabled"]=service_enabled()
    except:
        pass
    try:
        payload["service"]["started_at"]=service_started_at_ms()
    except:
        pass
    try:
        payload["network"]["ufw_udp_open"]=ufw_allowed(int(lp),"udp")
    except:
        pass
    try:
        payload["network"]["listening"]=local_listening(int(lp),"udp")
    except:
        pass
    try:
        payload["network"]["ping_ok"]=ping_ok()
    except:
        pass
    try:
        with _uptime_lock:
            _net_ev=_uptime_db().get("net_events") or []
        payload["network"]["internet"]=_net_ev[-1]["state"] if _net_ev else "unknown"
    except Exception:
        payload["network"]["internet"]="unknown"
    return jsonify(payload)

@app.route("/api/service",methods=["POST"])
def api_service():
    data=request.get_json(force=True,silent=True) or {}
    action=str(data.get("action","")).lower()
    if action not in {"start","stop","restart","enable","disable","reload"}:
        abort(400)
    if action=="enable":
        o,c=_sudo(["/usr/bin/systemctl","enable",UNIT])
    elif action=="disable":
        o,c=_sudo(["/usr/bin/systemctl","disable",UNIT])
    elif action=="reload":
        so,sc=_sudo(["/usr/bin/wg-quick","strip",WG_IFACE])
        if sc==0:
            import tempfile
            fd,tp=tempfile.mkstemp(prefix="wgstrip.",dir="/tmp")
            try:
                with os.fdopen(fd,"w",encoding="utf-8") as f: f.write(so)
                o,c=_sudo(["/usr/bin/wg","syncconf",WG_IFACE,tp])
            finally:
                try: os.remove(tp)
                except: pass
        else:
            o, c = so, sc
    else:
        o,c=_sudo(["/usr/bin/systemctl",action,UNIT])
    if c==0:
        _log_dashboard_event(f"service {action} via dashboard ({UNIT})")
    else:
        _log_dashboard_event(f"service {action} failed ({UNIT})", "error")
    active=service_active()
    try:
        _record_uptime_sample(active)
    except Exception:
        pass
    return jsonify({"ok":c==0,"out":o,"active":active,"enabled":service_enabled()})

_UPTIME_RANGES = {
    "24h": (24 * 3600, 48),          # one bar per half-hour — finer, so short outages stand out
    "7d":  (7 * 24 * 3600, 7),       # one bar per day
    "30d": (30 * 24 * 3600, 30),     # one bar per day
    "90d": (90 * 24 * 3600, 90),     # one bar per day
}

@app.route("/api/uptime")
def api_uptime():
    rng = request.args.get("range", "24h")
    if rng not in _UPTIME_RANGES:
        rng = "24h"
    try:
        active = service_active()
    except Exception:
        active = False
    try:
        _record_uptime_sample(active)
    except Exception:
        app.logger.exception("uptime_sample_failed")
    try:
        with _uptime_lock:
            net_stale = time.time() - float(_uptime_db().get("net_last_sample") or 0.0) > 2 * UPTIME_SAMPLE_INTERVAL
        if net_stale:
            _record_net_sample()
    except Exception:
        app.logger.exception("net_sample_failed")
    now = time.time()
    with _uptime_lock:
        db = _uptime_db()
        events = [dict(e) for e in db["events"]]
        last_sample = float(db.get("last_sample") or 0.0)
        net_events = [dict(e) for e in db.get("net_events") or []]
        net_latency = [dict(s) for s in db.get("net_latency") or []]
        net_target = str(db.get("net_target") or "")
    intervals = _uptime_intervals(events, now)
    net_intervals = _uptime_intervals(net_events, now)

    since_ms = 0
    if active:
        try:
            since_ms = service_started_at_ms()
        except Exception:
            since_ms = 0
    if not since_ms:
        cur_state = "up" if active else "down"
        for (s, _e, st) in reversed(intervals):
            if st != cur_state:
                break
            since_ms = int(s * 1000)

    span_s, n_buckets = _UPTIME_RANGES[rng]
    start = now - span_s
    payload = {
        "unit": UNIT,
        "current": {
            "state": "up" if active else "down",
            "active": active,
            "since_ms": since_ms,
        },
        "monitor": {
            "interval_s": UPTIME_SAMPLE_INTERVAL,
            "since_ms": int(events[0]["ts"] * 1000) if events else 0,
            "last_sample_ms": int(last_sample * 1000),
        },
        "stats": {
            key: _uptime_window_stats(intervals, now - span, now)
            for key, (span, _n) in _UPTIME_RANGES.items()
        },
        "timeline": {
            "range": rng,
            "start_ms": int(start * 1000),
            "end_ms": int(now * 1000),
            "bucket_s": int(span_s / n_buckets),
            "buckets": _uptime_buckets(intervals, start, now, n_buckets),
        },
        "incidents": _uptime_incident_list(intervals, now),
    }

    net_state = net_events[-1]["state"] if net_events else "unknown"
    net_since_ms = 0
    for (s, _e, st) in reversed(net_intervals):
        if st != net_state:
            break
        net_since_ms = int(s * 1000)
    lat_vals = [s["ms"] for s in net_latency]
    payload["net"] = {
        "current": {
            "state": net_state,
            "since_ms": net_since_ms,
            "target": net_target,
            "latency_ms": net_latency[-1]["ms"] if net_latency else None,
        },
        "monitor": {
            "interval_s": UPTIME_SAMPLE_INTERVAL,
            "since_ms": int(net_events[0]["ts"] * 1000) if net_events else 0,
            "targets": NET_PING_TARGETS,
        },
        "stats": {
            key: _uptime_window_stats(net_intervals, now - span, now)
            for key, (span, _n) in _UPTIME_RANGES.items()
        },
        "timeline": {
            "range": rng,
            "start_ms": int(start * 1000),
            "end_ms": int(now * 1000),
            "bucket_s": int(span_s / n_buckets),
            "buckets": _uptime_buckets(net_intervals, start, now, n_buckets),
        },
        "incidents": _uptime_incident_list(net_intervals, now),
        "latency": {
            "avg_ms": round(sum(lat_vals) / len(lat_vals), 1) if lat_vals else None,
            "min_ms": round(min(lat_vals), 1) if lat_vals else None,
            "max_ms": round(max(lat_vals), 1) if lat_vals else None,
            "window_s": NET_LATENCY_RETENTION_SECONDS,
            "series": [
                {"ts_ms": int(s["ts"] * 1000), "ms": s["ms"]}
                for s in _downsample_latency(net_latency)
            ],
        },
    }
    try:
        payload["current"]["enabled"] = service_enabled()
    except Exception:
        payload["current"]["enabled"] = False
    return jsonify(payload)

@app.route("/api/users",methods=["GET","POST"])
def api_users():
    if request.method=="GET":
        issued,live=list_clients()
        return jsonify({"issued":issued,"live":live})
    data=request.get_json(force=True,silent=True) or {}
    name=str(data.get("name","")).strip()
    cn=str(data.get("cn",name)).strip()
    static_ip=str(data.get("ip","")).strip()
    if not _valid_name(name):
        return jsonify({"ok": False, "error": "invalid_name", "hint": "Allowed: A-Z a-z 0-9 . _ - (max 64)"}), 400
    if static_ip and not _valid_ip(static_ip if "/" in static_ip else static_ip+"/32"):
        return jsonify({"ok": False, "error": "invalid_ip", "hint": "Use 10.8.0.23 or 10.8.0.23/32"}), 400
    db=_load_peers_db()
    if name in db:
        return jsonify({"ok": False, "error": "already_exists", "hint": "Peer already exists"}), 409
    extra_fields={}
    err=_apply_peer_config_fields(extra_fields,data)
    if err:
        return err
    o_priv,c=_sudo(["/usr/bin/wg","genkey"])
    if c!=0 or not o_priv.strip():
        return jsonify({"ok":False,"error":"keygen_failed","out":o_priv}),500
    client_priv=o_priv.strip()
    o_pub,c=_sudo(["/usr/bin/wg","pubkey"], input_data=(client_priv+"\n").encode())
    if c!=0 or not o_pub.strip():
        return jsonify({"ok":False,"error":"pubkey_failed","out":o_pub}),500
    client_pub=o_pub.strip()
    addr=static_ip if static_ip else _next_client_ip()
    if not addr:
        return jsonify({"ok":False,"error":"addr_failed","hint":"No free IP in server subnet"}),500
    server_lp=_read_conf().get("Interface",{}).get("ListenPort",str(WG_PORT))
    _sudo(["/usr/bin/wg","set",WG_IFACE,"peer",client_pub,"allowed-ips",addr])
    conf=_read_conf()
    peers=conf.get("Peers",[])
    peers=[p for p in peers if p.get("PublicKey","")!=client_pub]
    peers.append({"PublicKey":client_pub,"AllowedIPs":addr})
    conf["Peers"]=peers
    _write_conf(conf)
    meta={"public_key":client_pub,"private_key":client_priv,"address":addr,"created":datetime.datetime.utcnow().strftime("%Y-%m-%d"),**extra_fields}
    db[name]=meta
    _save_peers_db(db)
    _log_dashboard_event(f"peer '{name}' added ({addr})")
    try:
        profile_text, _ = gen_client_conf(name)
    except Exception:
        profile_text = None
    return jsonify({"ok": True, "name": name, "cn": cn, "port": int(server_lp), "profile": profile_text})

@app.route("/api/users/<name>/rename",methods=["POST"])
def api_users_rename(name: str):
    data=request.get_json(force=True,silent=True) or {}
    new_name=str(data.get("name","")).strip()
    if not _valid_name(new_name):
        return jsonify({"ok":False,"error":"invalid_name","hint":"Allowed: A-Z a-z 0-9 . _ - (max 64)"}),400
    db=_load_peers_db()
    if name not in db:
        abort(404)
    if new_name!=name and new_name in db:
        return jsonify({"ok":False,"error":"already_exists","hint":"A peer with that name already exists"}),409
    db[new_name]=db.pop(name)
    _save_peers_db(db)
    if new_name!=name:
        _log_dashboard_event(f"peer '{name}' renamed to '{new_name}'")
    return jsonify({"ok":True,"name":new_name})

def _apply_peer_config_fields(meta: dict, data: dict):
    """Validate and apply client-config fields shared by peer create and PATCH.
    Returns None on success or an (json, status) error tuple."""
    if "dns" in data:
        dns_val = str(data["dns"]).strip()
        if dns_val and dns_val.lower() != "none" and not re.match(r'^[\d\s.,a-fA-F:]+$', dns_val):
            return jsonify({"ok": False, "error": "invalid_dns", "hint": "Use comma-separated IP addresses, or 'none'"}), 400
        meta["dns"] = dns_val

    if "search_domains" in data:
        sd_val = str(data["search_domains"]).strip()[:500]
        if sd_val and not re.match(r'^[A-Za-z0-9.\-_,\s]+$', sd_val):
            return jsonify({"ok": False, "error": "invalid_search_domains", "hint": "Use comma-separated domain names"}), 400
        meta["search_domains"] = sd_val

    if "client_allowed_ips" in data:
        raw_ips = str(data["client_allowed_ips"]).strip()
        try:
            for cidr in raw_ips.split(","):
                ipaddress.ip_network(cidr.strip(), strict=False)
        except ValueError:
            return jsonify({"ok": False, "error": "invalid_allowed_ips", "hint": "Use comma-separated CIDR prefixes e.g. 0.0.0.0/0, ::/0"}), 400
        meta["client_allowed_ips"] = raw_ips

    if "keepalive" in data:
        try:
            ka_int = int(data["keepalive"])
            if ka_int < 0 or ka_int > 65535:
                return jsonify({"ok": False, "error": "invalid_keepalive", "hint": "0–65535 seconds (0 = disabled)"}), 400
            meta["keepalive"] = str(ka_int)
        except (ValueError, TypeError):
            return jsonify({"ok": False, "error": "invalid_keepalive", "hint": "Must be a number"}), 400

    if "mtu" in data:
        mtu_val = str(data["mtu"]).strip()
        if mtu_val:
            try:
                mtu_int = int(mtu_val)
                if mtu_int < 576 or mtu_int > 9200:
                    return jsonify({"ok": False, "error": "invalid_mtu", "hint": "576–9200"}), 400
                mtu_val = str(mtu_int)
            except (ValueError, TypeError):
                return jsonify({"ok": False, "error": "invalid_mtu", "hint": "Must be a number"}), 400
        meta["mtu"] = mtu_val

    if "listen_port" in data:
        lp_val = str(data["listen_port"]).strip()
        if lp_val:
            try:
                lp_int = int(lp_val)
                if lp_int < 1 or lp_int > 65535:
                    return jsonify({"ok": False, "error": "invalid_listen_port", "hint": "1–65535"}), 400
                lp_val = str(lp_int)
            except (ValueError, TypeError):
                return jsonify({"ok": False, "error": "invalid_listen_port", "hint": "Must be a number"}), 400
        meta["listen_port"] = lp_val

    if "endpoint" in data:
        ep_val = str(data["endpoint"]).strip()[:256]
        if ep_val and not re.match(r'^[A-Za-z0-9.\-\[\]:]+:\d{1,5}$', ep_val):
            return jsonify({"ok": False, "error": "invalid_endpoint", "hint": "Use host:port"}), 400
        meta["endpoint"] = ep_val

    if "device" in data:
        meta["device"] = str(data["device"])[:32].strip()

    return None

@app.route("/api/users/<name>/settings", methods=["PATCH"])
def api_users_settings(name: str):
    data = request.get_json(force=True, silent=True) or {}
    db = _load_peers_db()
    meta = db.get(name)
    if not meta:
        abort(404)

    if "note" in data:
        meta["note"] = str(data["note"])[:200].strip()

    if "owner" in data:
        meta["owner"] = str(data["owner"])[:200].strip()

    if "long_note" in data:
        meta["long_note"] = str(data["long_note"])[:2000].strip()

    if "monitor_dns" in data:
        on = bool(data["monitor_dns"])
        meta["monitor_dns"] = on
        if not on:
            with _dns_stats_lock:
                stats = _load_dns_stats()
                if stats.get("peers", {}).pop(name, None) is not None:
                    _save_dns_stats(stats)

    err = _apply_peer_config_fields(meta, data)
    if err:
        return err

    db[name] = meta
    _save_peers_db(db)
    return jsonify({"ok": True, "name": name})

@app.route("/api/users/<name>/revoke",methods=["POST"])
def api_users_revoke(name: str):
    db=_load_peers_db()
    meta=db.get(name)
    if not meta:
        abort(404)
    pub=meta.get("public_key","")
    _sudo(["/usr/bin/wg","set",WG_IFACE,"peer",pub,"remove"])
    _ensure_peer_removed_from_conf(pub)
    del db[name]
    _save_peers_db(db)
    _sudo(["/usr/bin/systemctl","reload",UNIT])
    _log_dashboard_event(f"peer '{name}' revoked", "warn")
    return jsonify({"ok":True})

@app.route("/api/users/<name>/restore",methods=["POST"])
def api_users_restore(name: str):
    db=_load_peers_db()
    meta=db.get(name)
    if not meta:
        abort(404)
    pub=meta.get("public_key","")
    addr=meta.get("address","")
    _sudo(["/usr/bin/wg","set",WG_IFACE,"peer",pub,"allowed-ips",addr])
    conf=_read_conf()
    peers=conf.get("Peers",[])
    if not any(p.get("PublicKey","")==pub for p in peers):
        peers.append({"PublicKey":pub,"AllowedIPs":addr})
        conf["Peers"]=peers
        _write_conf(conf)
    _log_dashboard_event(f"peer '{name}' restored ({addr})")
    return jsonify({"ok":True})

@app.route("/api/users/<name>/pause", methods=["POST"])
def api_users_pause(name: str):
    db = _load_peers_db()
    meta = db.get(name)
    if not meta:
        abort(404)
    pub = meta.get("public_key", "")
    _sudo(["/usr/bin/wg", "set", WG_IFACE, "peer", pub, "remove"])
    meta["paused"] = True
    db[name] = meta
    _save_peers_db(db)
    _log_dashboard_event(f"peer '{name}' paused")
    return jsonify({"ok": True})

@app.route("/api/users/<name>/resume", methods=["POST"])
def api_users_resume(name: str):
    db = _load_peers_db()
    meta = db.get(name)
    if not meta:
        abort(404)
    pub = meta.get("public_key", "")
    addr = meta.get("address", "")
    _sudo(["/usr/bin/wg", "set", WG_IFACE, "peer", pub, "allowed-ips", addr])
    meta["paused"] = False
    db[name] = meta
    _save_peers_db(db)
    with _budget_lock:
        bdb = _load_data_budget_db()
        if bdb.get("enforce_state", {}).get(name) not in (None, "none"):
            bdb["enforce_state"][name] = "none"
            _save_data_budget_db(bdb)
    _log_dashboard_event(f"peer '{name}' resumed")
    return jsonify({"ok": True})

@app.route("/api/users/<name>/ovpn")
def api_users_conf(name: str):
    try:
        txt, pub = gen_client_conf(name)
        return jsonify({"ok": True, "name": name, "profile": txt})
    except FileNotFoundError:
        return jsonify({
            "ok": False,
            "error": "peer_not_found",
            "hint": "Create the peer first via POST /api/users with {name}, then retry /api/users/<name>/ovpn."
        }), 404
    except Exception as e:
        app.logger.exception("conf build failed name=%s", name)
        return jsonify({"ok": False, "error": "conf_build_failed", "hint": str(e)}), 500

@app.route("/api/users/<name>/diag")
def api_users_diag(name: str):
    issued, live = list_clients()
    peer = next((p for p in live if p.get("name") == name or p.get("cn") == name), None)
    issued_peer = next((p for p in issued if p.get("name") == name), None)
    if not peer:
        db = _load_peers_db()
        if name not in db:
            abort(404)
        ping_ip = _ip_from_allowed_ips((db.get(name) or {}).get("address", ""))
        ping = _ping_ip(ping_ip) if ping_ip else {"status": "no_target", "ms": None, "out": ""}
        return jsonify({
            "ok": True,
            "name": name,
            "endpoint": "—",
            "endpoint_ip": "",
            "ping_ip": ping_ip,
            "ping_ms": ping["ms"],
            "ping_status": ping["status"],
            "location": {"label": "—"},
        })
    endpoint = peer.get("remote", "")
    endpoint_ip = _endpoint_ip(endpoint)
    ping_ip = _ip_from_allowed_ips(peer.get("allowed_ips", ""))
    if not ping_ip and issued_peer:
        ping_ip = _ip_from_allowed_ips(issued_peer.get("ip", ""))
    ping = _ping_ip(ping_ip) if ping_ip else {"status": "no_target", "ms": None, "out": ""}
    location = _lookup_location(endpoint_ip) if endpoint_ip else {"label": "—"}
    return jsonify({
        "ok": True,
        "name": name,
        "endpoint": endpoint or "—",
        "endpoint_ip": endpoint_ip,
        "ping_ip": ping_ip,
        "ping_ms": ping["ms"],
        "ping_status": ping["status"],
        "location": location,
    })

@app.route("/api/users/<name>/dns")
def api_users_dns(name: str):
    if name not in _load_peers_db():
        abort(404)
    payload = _dns_top_domains(name)
    payload["ok"] = True
    payload["name"] = name
    payload["retention_hours"] = DNS_STATS_RETENTION_SECONDS // 3600
    payload["available"] = bool(_tcpdump_bin())
    return jsonify(payload)

@app.route("/api/diag/peers")
def api_diag_peers():
    db = _load_peers_db()
    safe_db = {
        name: {k: v for k, v in peer.items() if k != "private_key"}
        for name, peer in db.items()
    }
    show, _ = _sudo(["/usr/bin/wg", "show", WG_IFACE, "dump"]) if os.path.exists("/usr/bin/wg") else ("", 0)
    return jsonify({"db_keys": sorted(list(safe_db.keys())), "db": safe_db, "wg_dump": show})


@app.route("/api/diag/perms")
def api_diag_perms():
    import stat, pwd, grp
    info = {}
    try:
        st = os.stat(WG_CONF)
        mode_dec = st.st_mode & 0o777
        mode_oct_str = f"{mode_dec:03o}"
        try:
            owner = pwd.getpwuid(st.st_uid).pw_name
        except Exception:
            owner = str(st.st_uid)
        try:
            group = grp.getgrgid(st.st_gid).gr_name
        except Exception:
            group = str(st.st_gid)
        info["wg_conf"] = {
            "path": str(WG_CONF),
            "exists": True,
            "mode_decimal_str": str(mode_dec),
            "mode_octal": "0" + mode_oct_str,
            "uid_str": str(st.st_uid),
            "gid_str": str(st.st_gid),
            "owner": owner,
            "group": group,
            "size_bytes_str": str(st.st_size)
        }
    except Exception as e:
        info["wg_conf_error"] = str(e)
    out_cat, rc_cat = _sudo_cat(WG_CONF)
    info["sudo_cat_rc_str"] = str(rc_cat)
    info["sudo_cat_ok"] = (rc_cat == 0)
    info["sudo_cat_len_str"] = str(len(out_cat) if isinstance(out_cat, str) else 0)
    return jsonify(info)


def _logs_cleared_at() -> int:
    try:
        return int(_load_dash_settings().get("logs_cleared_at", 0) or 0)
    except (TypeError, ValueError):
        return 0

@app.route("/api/logs")
def api_logs():
    n=int(request.args.get("n","200"))
    verbose=request.args.get("verbose","0")=="1"
    lines=logs_tail(n, verbose).splitlines()
    try:
        lines=_merge_dashboard_log_lines(lines)
    except Exception:
        app.logger.exception("dashboard_log_merge_failed")
    cutoff=_logs_cleared_at()
    if cutoff:
        lines=[ln for ln in lines if _journal_line_ts(ln) >= cutoff]
    return jsonify({"lines":lines,"verbose":verbose,"count":len(lines)})

@app.route("/api/logs/clear",methods=["POST"])
def api_logs_clear():
    cutoff=int(time.time())
    _save_dash_setting("logs_cleared_at",cutoff)
    try:
        with _dash_events_lock:
            _write_json_file_root(DASH_EVENTS_DB,[])
    except Exception:
        app.logger.exception("dash_events_clear_failed")
    app.logger.info("logs cleared via dashboard")
    return jsonify({"ok":True,"cleared_at":cutoff})

@app.route("/api/logs/retention",methods=["GET","POST"])
def api_logs_retention():
    if request.method=="GET":
        saved=str(_load_dash_settings().get("log_retention","forever"))
        return jsonify({"retention":saved if saved in {"1d","7d","30d","forever"} else "forever"})
    data=request.get_json(force=True,silent=True) or {}
    retention=str(data.get("retention","7d")).strip()
    if retention not in {"1d","7d","30d","forever"}:
        abort(400)
    _save_dash_setting("log_retention",retention)
    if retention=="forever":
        _log_dashboard_event("journal retention set to forever")
        return jsonify({"ok":True,"retention":retention,"out":"No vacuum needed"})
    o,c=_sudo(["/usr/bin/journalctl",f"--vacuum-time={retention}"])
    if c==0:
        _log_dashboard_event(f"journal retention set to {retention}")
    else:
        _log_dashboard_event(f"journal vacuum failed for retention {retention}","error")
    return jsonify({"ok":c==0,"retention":retention,"out":o})

@app.route("/api/data-budget", methods=["GET", "POST"])
def api_data_budget():
    issued, live = list_clients()
    if request.method == "POST":
        data = request.get_json(force=True, silent=True) or {}
        with _budget_lock:
            db = _load_data_budget_db()
            settings = db.setdefault("settings", {})
            old = dict(settings)
            if "enabled" in data:
                settings["enabled"] = bool(data.get("enabled"))
            if "budget_gb" in data:
                try:
                    settings["budget_gb"] = max(1, min(100000, int(data.get("budget_gb") or 1)))
                except (TypeError, ValueError):
                    return jsonify({"ok": False, "error": "invalid_budget_gb"}), 400
            if "alerts" in data:
                settings["alerts"] = bool(data.get("alerts"))
            if "reset_time" in data:
                rt = str(data.get("reset_time", "")).strip()
                if not _valid_reset_time(rt):
                    return jsonify({"ok": False, "error": "invalid_reset_time"}), 400
                settings["reset_time"] = rt
            if "peer_budgets" in data:
                raw = data.get("peer_budgets") or {}
                if isinstance(raw, dict):
                    peer_budgets = {}
                    for k, v in raw.items():
                        if not _valid_name(k):
                            continue
                        if v == "inf":
                            peer_budgets[k] = "inf"
                        else:
                            try:
                                peer_budgets[k] = max(1, min(100000, int(v or 1)))
                            except (TypeError, ValueError):
                                pass
                    settings["peer_budgets"] = peer_budgets
            if "enforcement" in data:
                enf = data.get("enforcement") or {}
                enf_action = str(enf.get("action", "none")).lower()
                if enf_action not in {"none", "throttle", "pause", "combined"}:
                    enf_action = "none"
                try:
                    enf_mbps = max(1, min(1000, int(enf.get("throttle_mbps", 5) or 5)))
                except (TypeError, ValueError):
                    enf_mbps = 5
                settings["enforcement"] = {"action": enf_action, "throttle_mbps": enf_mbps}
            db["settings"] = settings
            if old.get("reset_time") != settings.get("reset_time"):
                db["period_start"] = 0
            _save_data_budget_db(db)
        app.logger.info("data_budget_settings_update old=%s new=%s", old, settings)
        changes = []
        if old.get("enabled", True) != settings.get("enabled", True):
            changes.append(f"daily budget {'enabled' if settings.get('enabled', True) else 'disabled — tracking usage only'}")
        if old.get("budget_gb") != settings.get("budget_gb"):
            changes.append(f"daily budget {old.get('budget_gb')} → {settings.get('budget_gb')} GB")
        if old.get("alerts") != settings.get("alerts"):
            changes.append(f"alerts {'enabled' if settings.get('alerts') else 'disabled'}")
        if old.get("reset_time") != settings.get("reset_time"):
            changes.append(f"reset time {old.get('reset_time')} → {settings.get('reset_time')}")
        if old.get("peer_budgets") != settings.get("peer_budgets"):
            opb = old.get("peer_budgets") or {}
            npb = settings.get("peer_budgets") or {}
            diffs = [f"{k} {opb.get(k, 'inf')} → {npb.get(k, 'inf')} GB" for k in sorted(set(opb) | set(npb)) if opb.get(k) != npb.get(k)]
            changes.append("peer budgets: " + ", ".join(diffs[:4]) if diffs else "peer budgets updated")
        if old.get("enforcement") != settings.get("enforcement"):
            enf = settings.get("enforcement") or {}
            changes.append(f"enforcement set to '{enf.get('action', 'none')}'" + (f" ({enf.get('throttle_mbps')} Mbps)" if enf.get("action") in ("throttle", "combined") else ""))
        if changes:
            _log_dashboard_event("budget settings changed: " + ", ".join(changes))
    state = _data_budget_state(issued, live)
    return jsonify({"ok": True, **state})

@app.route("/api/data-budget/export", methods=["POST"])
def api_data_budget_export():
    issued, live = list_clients()
    state = _data_budget_state(issued, live)
    app.logger.info("data_budget_export period_start=%s total=%s peers=%s", state.get("period_start"), state.get("total"), len(state.get("peers", [])))
    rows = ["peer,used_bytes,current_total_bytes,baseline_bytes"]
    for p in state.get("peers", []):
        rows.append("{},{},{},{}".format(
            str(p.get("name", "")).replace(",", " "),
            int(p.get("bytes", 0) or 0),
            int(p.get("current_total", 0) or 0),
            int(p.get("baseline", 0) or 0),
        ))
    return jsonify({"ok": True, "filename": f"data-budget-{datetime.datetime.now().strftime('%Y-%m-%d')}.csv", "csv": "\n".join(rows) + "\n"})

@app.route("/api/traffic")
def api_traffic():
    return jsonify(_sample_traffic())

@app.route("/api/traffic/history")
def api_traffic_history():
    range_arg=str(request.args.get("range","1m")).lower()
    ranges={"10s":10,"30s":30,"1m":60,"5m":5*60,"1h":60*60,"24h":24*60*60}
    seconds=ranges.get(range_arg, 60)
    try:
        max_points=int(request.args.get("max_points","1200"))
    except (TypeError, ValueError):
        max_points=1200
    max_points=max(2, min(5000, max_points))
    now=time.time()
    history=_prune_traffic_history(_traffic_history(), now)
    app.config["_traffic_history"]=history
    cutoff=now-seconds
    samples=[s for s in history if s.get("ts", 0) >= cutoff]
    samples=_downsample_traffic(samples, max_points)
    return jsonify({
        "range": range_arg if range_arg in ranges else "1m",
        "seconds": seconds,
        "retention_seconds": TRAFFIC_RETENTION_SECONDS,
        "samples": samples,
    })

@app.route("/api/ports",methods=["GET","POST"])
def api_ports():
    if request.method=="GET":
        proto=request.args.get("proto","udp").lower()
        if proto not in {"udp", "tcp"}:
            abort(400)
        port=int(request.args.get("port",WG_PORT))
        return jsonify({"port":port,"proto":proto,"ufw_allowed":ufw_allowed(port,proto),"listening":local_listening(port,proto)})
    data=request.get_json(force=True,silent=True) or {}
    port=int(data.get("port",WG_PORT))
    proto=str(data.get("proto","udp")).lower()
    allow=bool(data.get("allow",True))
    if proto not in {"udp","tcp"}:
        abort(400)
    if allow:
        o,c=_sudo(["/usr/sbin/ufw","allow",f"{port}/{proto}"])
    else:
        o,c=_sudo(["/usr/sbin/ufw","delete","allow",f"{port}/{proto}"])
    if c==0:
        _log_dashboard_event(f"firewall rule {'added' if allow else 'removed'}: {port}/{proto}")
    else:
        _log_dashboard_event(f"firewall change failed for {port}/{proto}", "error")
    return jsonify({"ok":True,"out":o,"ufw_allowed":ufw_allowed(port,proto)})

_SENSITIVE_KEYS = {"PrivateKey", "PreSharedKey"}

def _scrub_conf(conf: Dict[str, Any]) -> Dict[str, Any]:
    scrubbed = dict(conf)
    iface = dict(scrubbed.get("Interface", {}))
    for k in _SENSITIVE_KEYS:
        iface.pop(k, None)
    scrubbed["Interface"] = iface
    scrubbed["Peers"] = [
        {pk: pv for pk, pv in p.items() if pk not in _SENSITIVE_KEYS}
        for p in scrubbed.get("Peers", [])
    ]
    return scrubbed

@app.route("/api/config",methods=["GET","POST"])
def api_config():
    if request.method=="GET":
        return jsonify({"path":WG_CONF,"data":_scrub_conf(_read_conf())})
    data=request.get_json(force=True,silent=True) or {}
    conf=_read_conf()
    iface=conf.get("Interface",{})
    if "ListenPort" in data:
        iface["ListenPort"]=str(data["ListenPort"])
    if "DNS" in data:
        iface["DNS"]=str(data["DNS"])
    if "Address" in data:
        iface["Address"]=str(data["Address"])
    conf["Interface"]=iface
    _write_conf(conf)
    _sudo(["/usr/bin/systemctl","restart",UNIT])
    changed_keys=[k for k in ("ListenPort","DNS","Address") if k in data]
    _log_dashboard_event(f"interface config changed ({', '.join(changed_keys) or 'no fields'}) — service restarted", "warn")
    return jsonify({"ok":True})

@app.route("/api/dyndns", methods=["GET", "POST"])
def api_dyndns():
    if r := _require_auth(): return r
    if request.method == "GET":
        cfg = _load_dyndns()
        safe = {k: v for k, v in cfg.items() if k != "token"}
        safe["has_token"] = bool(cfg.get("token"))
        safe["public_ip"], safe["public_ip_source"] = _public_ip_info()
        try:
            safe["server_public_key"] = _server_pubkey()
        except Exception:
            safe["server_public_key"] = ""
        safe["endpoint_host"] = _get_endpoint_host()
        try:
            safe["listen_port"] = _read_conf().get("Interface", {}).get("ListenPort", str(WG_PORT))
        except Exception:
            safe["listen_port"] = str(WG_PORT)
        return jsonify(safe)
    data = request.get_json(force=True, silent=True) or {}
    cfg = _load_dyndns()
    for key in ("mode", "hostname", "provider", "domain", "custom_url"):
        if key in data:
            val = data[key]
            cfg[key] = None if val is None else str(val).strip()
    if "token" in data and data["token"] not in ("", "••••"):
        cfg["token"] = data["token"]
    elif "token" in data and data["token"] == "":
        cfg["token"] = ""
    try:
        _save_dyndns(cfg)
    except Exception as e:
        app.logger.error("dyndns_save_failed: %s", e)
        return jsonify({"ok": False, "error": str(e)}), 500
    _log_dashboard_event(f"dyndns settings updated (mode: {cfg.get('mode') or 'static'}" + (f", provider: {cfg.get('provider')}" if cfg.get("provider") else "") + ")")
    return jsonify({"ok": True})

@app.route("/api/dyndns/token", methods=["GET"])
def api_dyndns_token():
    if r := _require_auth(): return r
    cfg = _load_dyndns()
    return jsonify({"token": cfg.get("token", "")})

@app.route("/api/dyndns/resolve", methods=["POST"])
def api_dyndns_resolve():
    if r := _require_auth(): return r
    import socket
    data = request.get_json(force=True, silent=True) or {}
    hostname = (data.get("hostname") or "").strip()
    if not hostname:
        return jsonify({"error": "hostname required"}), 400
    try:
        ip = socket.getaddrinfo(hostname, None)[0][4][0]
        pub_ip, pub_src = _public_ip_info()
        return jsonify({"ip": ip, "hostname": hostname, "public_ip": pub_ip, "public_ip_source": pub_src})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/dyndns/update", methods=["POST"])
def api_dyndns_update():
    if r := _require_auth(): return r
    import base64
    cfg = _load_dyndns()
    provider = cfg.get("provider") or ""
    token = cfg.get("token", "")
    domain = cfg.get("domain", "")
    custom_url = cfg.get("custom_url", "")
    if not provider:
        return jsonify({"error": "No provider configured"}), 400
    current_ip = _current_public_ip(0)

    def _record(ok: bool, detail: str = "") -> None:
        # Remember the outcome of the last real push attempt so the UI
        # can show it after a reload.
        cfg["last_update"] = {
            "ts": int(time.time()),
            "ok": ok,
            "ip": current_ip,
            "provider": provider,
            "detail": detail,
        }
        try:
            _save_dyndns(cfg)
        except Exception as e:
            app.logger.error("dyndns_last_update_save_failed: %s", e)
        if ok:
            _log_dashboard_event(f"dyndns update ok — {provider}: {domain or custom_url} → {current_ip}")
        else:
            _log_dashboard_event(f"dyndns update failed — {provider}: {detail[:120]}", "error")

    try:
        if provider == "duckdns":
            if not token or not domain:
                return jsonify({"error": "Token and domain are required for Duck DNS"}), 400
            url = f"https://www.duckdns.org/update?domains={urllib.parse.quote(domain)}&token={urllib.parse.quote(token)}&ip=&verbose=true"
            resp = urllib.request.urlopen(url, timeout=10).read().decode().strip()
            # verbose reply: OK / <ipv4> / [<ipv6>] / UPDATED|NOCHANGE
            lines = [l.strip() for l in resp.splitlines() if l.strip()]
            if lines and lines[0].upper() == "OK":
                record_ip = lines[1] if len(lines) > 1 else ""
                changed = lines[-1] if lines and lines[-1] in ("UPDATED", "NOCHANGE") else ""
                if record_ip:
                    # Duck DNS stored the source IP of this request — the most
                    # reliable reading of our real egress IP, so cache it.
                    _public_ip_cache.update(ts=time.time(), ip=record_ip, src="duckdns.org update reply")
                detail = f"record → {record_ip or '?'}{f' ({changed.lower()})' if changed else ''}"
                _record(True, detail)
                return jsonify({"ok": True, "response": detail, "record_ip": record_ip, "ip": record_ip or current_ip, "domain": domain})
            _record(False, f"Duck DNS returned: {resp}")
            return jsonify({"error": f"Duck DNS returned: {resp}"}), 400
        elif provider in ("noip", "dynu"):
            if not token or not domain:
                return jsonify({"error": "Credentials and hostname are required"}), 400
            if provider == "noip":
                update_url = f"https://dynupdate.no-ip.com/nic/update?hostname={urllib.parse.quote(domain)}&myip={current_ip}"
            else:
                update_url = f"https://api.dynu.com/nic/update?hostname={urllib.parse.quote(domain)}&myip={current_ip}"
            req = urllib.request.Request(update_url)
            creds = base64.b64encode(token.encode()).decode()
            req.add_header("Authorization", f"Basic {creds}")
            req.add_header("User-Agent", "WG-Dashboard/1.0 python-urllib")
            resp = urllib.request.urlopen(req, timeout=10).read().decode().strip()
            if resp.startswith("good") or resp.startswith("nochg"):
                # reply format: "good <ip>" / "nochg <ip>" — the stored address
                parts = resp.split()
                record_ip = parts[1] if len(parts) > 1 else ""
                if record_ip:
                    _public_ip_cache.update(ts=time.time(), ip=record_ip, src=f"{provider} update reply")
                _record(True, resp)
                return jsonify({"ok": True, "response": resp, "record_ip": record_ip, "ip": record_ip or current_ip, "domain": domain})
            _record(False, f"Provider returned: {resp}")
            return jsonify({"error": f"Provider returned: {resp}"}), 400
        elif provider == "custom":
            if not custom_url:
                return jsonify({"error": "Custom URL is required"}), 400
            url = custom_url.replace("{ip}", current_ip)
            resp = urllib.request.urlopen(url, timeout=10).read().decode().strip()
            _record(True, resp)
            return jsonify({"ok": True, "response": resp, "ip": current_ip})
        return jsonify({"error": "Unknown provider"}), 400
    except Exception as e:
        _record(False, str(e))
        return jsonify({"error": str(e)}), 400

@app.route("/api/health")
def api_health():
    iface,rx,tx=read_bytes()
    lp=_read_conf().get("Interface",{}).get("ListenPort",str(WG_PORT))
    return jsonify({
        "service":service_active(),
        "port_udp_open":ufw_allowed(int(lp),"udp"),
        "listening_udp":local_listening(int(lp),"udp"),
        "ping_ok":ping_ok(),
        "ntp":timedate_ntp(),
        "iface":iface,
        "rx":rx,"tx":tx,
        "live_clients":len(list_clients()[1])
    })

@app.route("/api/diag/last")
def api_diag_last():
    global _last_run
    return jsonify(_last_run)

@app.route("/api/diag/bg-notifications")
def api_bg_notifications():
    with _bg_lock:
        return jsonify(list(_bg_notifications))

@app.route("/api/diag/refresh", methods=["POST"])
def api_diag_refresh():
    _bg_run_port_check()
    with _bg_lock:
        return jsonify(list(_bg_notifications))

@app.route("/api/diag/vpn")
def api_diag_vpn():
    conf=_read_conf()
    iface_cfg=conf.get("Interface",{})
    lp=iface_cfg.get("ListenPort",str(WG_PORT))
    ip_fwd,_=_run("cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0")
    wg_show,_=_sudo(["/usr/bin/wg","show"]) if os.path.exists("/usr/bin/wg") else ("","")
    journal,_=_sudo(["/usr/bin/journalctl","-u",UNIT,"-n","15","--no-pager"])
    return jsonify({
        "public_ip": _current_public_ip(),
        "host_ip": HOST_IP,
        "ip_forward": ip_fwd.strip()=="1",
        "has_postup": "PostUp" in iface_cfg,
        "service_active": service_active(),
        "port": int(lp),
        "listening": local_listening(int(lp),"udp"),
        "ufw_allowed": ufw_allowed(int(lp),"udp"),
        "wg_show": wg_show,
        "journal": [l for l in journal.strip().splitlines() if l.strip()][-12:],
    })

@app.route("/api/fix",methods=["POST"])
def api_fix():
    actions=[]
    errors=[]
    # 1. ip_forward
    fwd,_=_run("cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0")
    if fwd.strip()!="1":
        _,c=_sudo(["/usr/bin/sysctl","-w","net.ipv4.ip_forward=1"])
        if c==0:
            actions.append("Enabled ip_forward")
        else:
            errors.append("Could not enable ip_forward")
    # 2. PostUp / PostDown
    conf=_read_conf()
    iface_cfg=conf.get("Interface",{})
    if "PostUp" not in iface_cfg:
        net_if,_=_run("ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++){if($i==\"dev\"){print $(i+1); exit}}}'")
        net_if=net_if.strip()
        if net_if:
            iface_cfg["PostUp"]=f"iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o {net_if} -j MASQUERADE"
            iface_cfg["PostDown"]=f"iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o {net_if} -j MASQUERADE"
            conf["Interface"]=iface_cfg
            _write_conf(conf)
            actions.append(f"Added NAT PostUp/PostDown (via {net_if})")
        else:
            errors.append("Could not detect outgoing network interface")
    lp=int(iface_cfg.get("ListenPort",WG_PORT))
    if not ufw_allowed(lp,"udp"):
        _,c=_sudo(["/usr/sbin/ufw","allow",f"{lp}/udp"])
        if c==0:
            actions.append(f"Opened UDP {lp} in UFW")
    svc_was=service_active()
    if svc_was and actions:
        o,c=_sudo(["/usr/bin/systemctl","restart",UNIT])
        if c==0:
            actions.append("Restarted wg-quick to apply changes")
        else:
            errors.append(f"Restart failed: {o[:300]}")
    elif not svc_was:
        o,c=_sudo(["/usr/bin/systemctl","start",UNIT])
        if c==0:
            actions.append("Started wg-quick service")
        else:
            errors.append(f"Start failed — check logs: {o[:300]}")
    return jsonify({"ok":len(errors)==0,"actions":actions,"errors":errors,"service_active":service_active()})

_SPEEDTEST_DEFAULT_BYTES = 16_000_000
_SPEEDTEST_MAX_BYTES = 64_000_000
_SPEEDTEST_CHUNK_SIZE = 256 * 1024
_SPEEDTEST_CHUNK = os.urandom(_SPEEDTEST_CHUNK_SIZE)

@app.route("/api/speedtest/ping")
def api_speedtest_ping():
    resp = jsonify({"ok": True, "server_ts": round(time.time() * 1000)})
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return resp

@app.route("/api/speedtest/download")
def api_speedtest_download():
    try:
        total = int(request.args.get("bytes", _SPEEDTEST_DEFAULT_BYTES))
    except Exception:
        total = _SPEEDTEST_DEFAULT_BYTES
    total = max(1, min(_SPEEDTEST_MAX_BYTES, total))

    @stream_with_context
    def generate():
        sent = 0
        while sent < total:
            n = min(_SPEEDTEST_CHUNK_SIZE, total - sent)
            sent += n
            yield _SPEEDTEST_CHUNK[:n]

    resp = Response(generate(), mimetype="application/octet-stream")
    resp.direct_passthrough = True
    resp.headers["Content-Length"] = str(total)
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["X-Speedtest-Bytes"] = str(total)
    resp.headers["X-Accel-Buffering"] = "no"
    resp.headers["Content-Encoding"] = "identity"
    resp.headers["Connection"] = "keep-alive"
    return resp

@app.route("/api/speedtest/upload", methods=["POST"])
def api_speedtest_upload():
    try:
        total = 0
        while True:
            chunk = request.stream.read(_SPEEDTEST_CHUNK_SIZE)
            if not chunk:
                break
            total += len(chunk)
        resp = jsonify({"ok": True, "bytes": total})
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        return resp
    except Exception as e:
        app.logger.warning("speedtest upload failed: %s", e)
        return jsonify({"ok": False, "bytes": 0, "error": str(e)})

@app.route("/download/<name>.conf")
def download_conf(name: str):
    txt, _ = gen_client_conf(name)
    safe_name = name.replace("/", "_")
    resp = Response(txt, mimetype="text/plain")
    resp.headers["Content-Disposition"] = f'attachment; filename="{safe_name}.conf"'
    return resp

def _read_os_release() -> dict:
    fields = {}
    try:
        with open("/etc/os-release") as f:
            for line in f:
                line = line.strip()
                if "=" in line:
                    k, _, v = line.partition("=")
                    fields[k] = v.strip('"')
    except Exception:
        pass
    return fields

@app.route("/api/system/info")
def api_system_info():
    os_rel = _read_os_release()
    platform_name = os_rel.get("PRETTY_NAME") or os_rel.get("NAME", "Linux")
    kernel_out, _ = _run("uname -r")
    uptime_out, _ = _run("uptime -p")
    uptime = uptime_out.replace("up ", "", 1) if uptime_out.startswith("up ") else uptime_out
    uptime = uptime.replace("minutes", "min").replace("minute", "min")
    port_out, _ = _run(f"grep -m1 'ListenPort' {WG_CONF} 2>/dev/null || echo '{WG_PORT}'")
    try:
        wg_port = int(port_out.split("=")[-1].strip()) if "=" in port_out else int(port_out.strip())
    except Exception:
        wg_port = WG_PORT
    iface = WG_IFACE
    return jsonify({
        "platform": platform_name,
        "kernel": kernel_out or "unknown",
        "uptime": uptime or "unknown",
        "interface": f"{iface} · UDP {wg_port}",
        "service": UNIT,
        "service_enabled": service_enabled(),
        "version": _local_version(),
    })

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_BRANCH = os.environ.get("REPO_BRANCH", "main")
VERSION_FILE = ".version"
_DEFAULT_GITHUB_RAW_VERSION = f"https://raw.githubusercontent.com/Migrim/OpenVPN-Dashboard/{REPO_BRANCH}/{VERSION_FILE}"

def _git(args: List[str]) -> Tuple[str, int]:
    try:
        r = subprocess.run(["git", "-C", BASE_DIR, *args],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        return r.stdout.strip(), r.returncode
    except Exception as e:
        return str(e), 1

def _github_raw_version_url() -> str:
    override = os.environ.get("UPDATE_VERSION_URL", "").strip()
    if override:
        return override

    remote, rc = _git(["config", "--get", "remote.origin.url"])
    if rc != 0 or not remote:
        return _DEFAULT_GITHUB_RAW_VERSION

    owner_repo = ""
    if remote.startswith("git@github.com:"):
        owner_repo = remote.split(":", 1)[1]
    else:
        parsed = urllib.parse.urlparse(remote)
        if parsed.netloc.lower() == "github.com":
            owner_repo = parsed.path.lstrip("/")

    if not owner_repo:
        return _DEFAULT_GITHUB_RAW_VERSION

    if owner_repo.endswith(".git"):
        owner_repo = owner_repo[:-4]
    return f"https://raw.githubusercontent.com/{owner_repo}/{REPO_BRANCH}/{VERSION_FILE}"

def _local_version() -> str:
    try:
        with open(os.path.join(BASE_DIR, VERSION_FILE)) as f:
            return f.read().strip()
    except Exception:
        return "unknown"

def _display_version() -> str:
    """Human-facing version label, e.g. 'v2.1.2' or 'v2.1.2-dev'."""
    v = _local_version()
    if v == "unknown":
        return ""
    if v.startswith("dev "):
        return f"v{v[4:].strip()}-dev"
    return f"v{v}"

def _build_stamp() -> str:
    """For dev versions, append a mtime-based stamp so browsers reload changed files."""
    v = _local_version()
    if not _is_dev_version(v):
        return v
    try:
        files = (
            glob.glob(os.path.join(BASE_DIR, "static/js", "*.jsx"))
            + glob.glob(os.path.join(BASE_DIR, "templates", "*.html"))
        )
        return f"{v}.{int(max(os.path.getmtime(f) for f in files))}" if files else v
    except Exception:
        return v

def _remote_version() -> str:
    try:
        req = urllib.request.urlopen(_github_raw_version_url(), timeout=6)
        return req.read().decode().strip()
    except Exception:
        return ""

def _git_version(ref: str) -> str:
    out, rc = _git(["show", f"{ref}:{VERSION_FILE}"])
    return out.strip() if rc == 0 else ""

def _is_version_file_dirty() -> bool:
    out, rc = _git(["status", "--porcelain", "--", VERSION_FILE])
    return rc == 0 and bool(out.strip())

def _write_local_version(version: str) -> bool:
    value = (version or "").strip()
    if not value:
        return False
    try:
        with open(os.path.join(BASE_DIR, VERSION_FILE), "w") as f:
            f.write(value + "\n")
        return True
    except Exception as e:
        app.logger.warning("failed to update local version metadata: %s", e)
        return False

def _is_dev_version(version: str) -> bool:
    return (version or "").strip().lower().startswith("dev ")

def _version_key(version: str):
    value = (version or "").strip()
    if value.lower().startswith("dev "):
        value = value[4:].strip()
    if value.startswith(("v", "V")):
        value = value[1:]
    match = re.match(r"^(\d+(?:\.\d+)*)(?:[-+].*)?$", value)
    if not match:
        return None
    return tuple(int(part) for part in match.group(1).split("."))

def _compare_versions(current: str, candidate: str):
    current_key = _version_key(current)
    candidate_key = _version_key(candidate)
    if current_key is None or candidate_key is None:
        return None

    width = max(len(current_key), len(candidate_key))
    current_key = current_key + (0,) * (width - len(current_key))
    candidate_key = candidate_key + (0,) * (width - len(candidate_key))
    return (candidate_key > current_key) - (candidate_key < current_key)

@app.route("/api/update/check")
def api_update_check():
    dev_opt_in = request.args.get("dev", "0") == "1"
    local = _local_version()
    remote = _remote_version()
    comparison = _compare_versions(local, remote)
    remote_is_dev = _is_dev_version(remote)
    available = comparison == 1 and (not remote_is_dev or dev_opt_in)
    return jsonify({
        "local": local,
        "remote": remote,
        "available": available,
        "comparison": comparison,
        "remote_is_dev": remote_is_dev,
    })

@app.route("/api/update/apply", methods=["POST"])
def api_update_apply():
    dev_opt_in = request.args.get("dev", "0") == "1"

    def _sse(obj: dict) -> str:
        return "data: " + json.dumps(obj) + "\n\n"

    def _stream():
        try:
            local = _local_version()
            remote = _remote_version()
            comparison = _compare_versions(local, remote)
            remote_is_dev = _is_dev_version(remote)
            if comparison != 1 or (remote_is_dev and not dev_opt_in):
                detail = "remote version is not newer"
                if not remote:
                    detail = "remote version unavailable"
                elif comparison is None:
                    detail = "could not compare local and remote versions"
                elif remote_is_dev and not dev_opt_in:
                    detail = "dev updates not enabled"
                yield _sse({"event": "done", "version": local, "remote": remote,
                            "detail": detail, "progress": 100})
                return

            yield _sse({"event": "stage", "id": "fetch", "label": "Fetching updates",
                        "detail": f"checking origin/{REPO_BRANCH}", "progress": 5})
            out, rc = _git(["fetch", "origin", REPO_BRANCH])
            if rc != 0:
                yield _sse({"event": "error", "detail": out[:300]}); return

            origin_ref = f"origin/{REPO_BRANCH}"
            target_version = _git_version(origin_ref) or remote

            if _is_version_file_dirty():
                yield _sse({"event": "stage", "id": "fetch", "label": "Fetching updates",
                            "detail": "refreshing version metadata", "progress": 15})
                out, rc = _git(["checkout", "--", VERSION_FILE])
                if rc != 0:
                    yield _sse({"event": "error", "detail": out[:300]}); return

            ahead_out, _ = _git(["rev-list", f"HEAD..{origin_ref}", "--count"])
            if ahead_out.strip() == "0":
                if _compare_versions(_local_version(), target_version) == 1:
                    _write_local_version(target_version)
                yield _sse({"event": "done", "version": _local_version(),
                            "detail": "already up to date", "progress": 100}); return

            yield _sse({"event": "stage", "id": "pull", "label": "Pulling changes",
                        "detail": "merging commits", "progress": 30})
            out, rc = _git(["pull", "origin", REPO_BRANCH])
            if rc != 0:
                yield _sse({"event": "error", "detail": out[:300]}); return

            first_line = next((l for l in out.splitlines() if l.strip()), out[:80])
            yield _sse({"event": "stage", "id": "pull", "label": "Pulling changes",
                        "detail": first_line[:80], "progress": 65})

            head_version = _git_version("HEAD")
            if head_version and _local_version() != head_version:
                _write_local_version(head_version)

            yield _sse({"event": "stage", "id": "restart", "label": "Restarting service",
                        "detail": "wg-dashboard", "progress": 88})

            def _delayed_restart():
                time.sleep(2)
                _run(f"{SUDO_BIN} systemctl restart wg-dashboard 2>&1")

            threading.Thread(target=_delayed_restart, daemon=True).start()

            _log_dashboard_event(f"dashboard updated to {_local_version() or 'latest'} — restarting service")
            yield _sse({"event": "done", "version": _local_version(), "progress": 100})
        except Exception as e:
            yield _sse({"event": "error", "detail": str(e)})

    resp = Response(stream_with_context(_stream()), content_type="text/event-stream")
    resp.headers["X-Accel-Buffering"] = "no"
    resp.headers["Cache-Control"] = "no-cache"
    return resp

if os.environ.get("WERKZEUG_RUN_MAIN") != "false":
    threading.Thread(target=_bg_check_loop, daemon=True, name="bg-port-check").start()
    threading.Thread(target=_bg_budget_loop, daemon=True, name="bg-budget").start()
    threading.Thread(target=_bg_traffic_loop, daemon=True, name="bg-traffic").start()
    threading.Thread(target=_bg_retention_loop, daemon=True, name="bg-retention").start()
    threading.Thread(target=_bg_dns_monitor_loop, daemon=True, name="bg-dns-monitor").start()
    threading.Thread(target=_bg_uptime_loop, daemon=True, name="bg-uptime").start()
    threading.Thread(target=_bg_peer_watch_loop, daemon=True, name="bg-peer-watch").start()

def create_app():
    return app

if __name__=="__main__":
    app.run(host="0.0.0.0", port=APP_PORT, debug=os.environ.get("FLASK_DEBUG", "0") == "1")
