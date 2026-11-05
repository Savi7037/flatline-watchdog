#!/usr/bin/env python3
"""Flatline Watchdog: receives bot pings, runs the checks, alerts over Telegram. Free and self-hosted."""
import json, math, os, re, secrets, sqlite3, sys, threading, time
import urllib.error, urllib.parse, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

E = os.environ.get
DB_PATH = E("DB_PATH", "flatline.db")
TG_TOKEN = E("TELEGRAM_BOT_TOKEN", "")
TG_API = E("TG_API", "https://api.telegram.org/bot")
BASE_URL = E("BASE_URL", "").rstrip("/")  # your own public address, such as https://flatline.example.com
HOST, PORT = E("APP_HOST", "127.0.0.1"), int(E("APP_PORT", "8091"))
MIN_TIMEOUT = int(E("MIN_TIMEOUT", 60))
CHECK_EVERY = float(E("CHECK_SECS", 5))
MAX_BOTS, MAX_BODY, PINGS_PER_MIN = int(E("MAX_BOTS", 10)), 4096, 120
HALT_TTL = float(E("HALT_TTL_SECS", 600))  # an unconfirmed kill expires, so it can't stop a bot hours later
AGENT_WINDOW = float(E("AGENT_WINDOW_SECS", 120))
LOG_CHARS, LOG_FRESH, BUCKET, BUCKETS, MAX_EVENTS = 1500, 86400, 900, 96, 100
HEARTBEAT_URL = E("HEARTBEAT_URL", "")  # an outside monitor that alerts when these pings stop
HEARTBEAT_EVERY = float(E("HEARTBEAT_SECS", 60))
HEALTH_STALE = float(E("HEALTH_STALE_SECS", 60))
OUTBOX_STALE = float(E("OUTBOX_STALE_SECS", 300))
KILL_FLAGS = {"stop": "a_stop", "funds": "a_funds", "fail": "a_fail", "loss": "a_loss"}
HERE = os.path.dirname(os.path.abspath(__file__))
START = time.time()
ALLOWED_CHATS = {int(x) for x in E("ALLOWED_CHATS", "").split(",") if x.strip()}  # empty means anyone who finds your Telegram bot can use it
NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")

lock = threading.RLock()
db = None
alive_at = {"checks": START, "sender": START}


def open_db(path=DB_PATH):
    global db
    db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users(chat_id INTEGER PRIMARY KEY, created REAL, dash_token TEXT UNIQUE);
    CREATE TABLE IF NOT EXISTS bots(id INTEGER PRIMARY KEY, token TEXT UNIQUE, chat_id INTEGER, name TEXT,
        created REAL, last_ping REAL, grace_from REAL DEFAULT 0, timeout_s INT, balance REAL, errors INT,
        net_today REAL, floor REAL, max_errors INT, loss_limit REAL, paused INT DEFAULT 0,
        a_stop INT DEFAULT 0, a_funds INT DEFAULT 0, a_fail INT DEFAULT 0, a_loss INT DEFAULT 0,
        last_log TEXT, log_at REAL DEFAULT 0, crash_at REAL DEFAULT 0, crash_kind TEXT, crash_code INT,
        halt_req REAL DEFAULT 0, halt_reason TEXT, halted_at REAL DEFAULT 0, kill_on TEXT DEFAULT '',
        kill_cleanup TEXT, agent_seen REAL DEFAULT 0, first_seen INT DEFAULT 0, UNIQUE(chat_id, name));
    CREATE TABLE IF NOT EXISTS outbox(id INTEGER PRIMARY KEY, chat_id INTEGER, text TEXT, created REAL,
        not_before REAL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
    CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, chat_id INTEGER, bot TEXT, kind TEXT, text TEXT, at REAL);
    CREATE INDEX IF NOT EXISTS events_chat ON events(chat_id, id);
    CREATE TABLE IF NOT EXISTS beats(bot_id INTEGER, bucket INTEGER, n INTEGER, PRIMARY KEY(bot_id, bucket));
    """)


def q(sql, *a): return db.execute(sql, a)
def one(sql, *a): return db.execute(sql, a).fetchone()
def rows(sql, *a): return db.execute(sql, a).fetchall()


def send(chat_id, text):
    """Alerts are stored first, so a Telegram outage delays them instead of losing them."""
    with lock:
        q("INSERT INTO outbox(chat_id, text, created) VALUES(?,?,?)", chat_id, text, time.time())


def event(chat_id, bot, kind, text, at=None):
    """The dashboard's timeline. Holds what the customer was told, so it needs no secrets."""
    q("INSERT INTO events(chat_id, bot, kind, text, at) VALUES(?,?,?,?,?)", chat_id, bot, kind, text, at or time.time())
    q("DELETE FROM events WHERE chat_id=? AND id NOT IN (SELECT id FROM events WHERE chat_id=? ORDER BY id DESC LIMIT ?)", chat_id, chat_id, MAX_EVENTS)


def ensure_user(chat_id):
    u = one("SELECT * FROM users WHERE chat_id=?", chat_id)
    if u is None:
        q("INSERT INTO users(chat_id, created) VALUES(?,?)", chat_id, time.time())
        u = one("SELECT * FROM users WHERE chat_id=?", chat_id)
    return u


# ---------- rate limiting ----------
_hits, _hits_lock = {}, threading.Lock()


def allowed(key, limit, window=60.0):
    now = time.time()
    with _hits_lock:
        if len(_hits) > 20000:
            _hits.clear()
        h = [t for t in _hits.get(key, []) if now - t < window]
        ok = len(h) < limit
        if ok:
            h.append(now)
        _hits[key] = h
    return ok


# ---------- crash reasons ----------
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
CTRL_RE = re.compile(r"[^\n\t\x20-\U0010ffff]|[\x7f-\x9f]")
# Best effort: logs can hold anything, so the customer is also told not to rely on this alone.
SECRET_RES = [
    (re.compile(r"(?i)\b(mnemonic|seed[ _-]?phrase|seed)\b[^\n]*"), r"\1 [hidden]"),
    (re.compile(r"(?i)\bbearer\s+\S+"), "Bearer [hidden]"),
    (re.compile(r"://[^/\s:@]+:[^/\s@]+@"), "://[hidden]@"),
    (re.compile(r"""(?i)([\w-]*(?:api[_-]?key|apikey|secret|passw(?:or)?d|pwd|token|private[_-]?key|privkey|signature|credential|authorization)[\w-]*["']?\s*[:=]\s*)("[^"\n]*"|'[^'\n]*'|[^\s,;&}]+)"""), r"\1[hidden]"),
    (re.compile(r"\b\d{6,12}:[A-Za-z0-9_-]{30,}\b"), "[hidden]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_.-]{8,}"), "[hidden]"),
    (re.compile(r"\b(?:0x)?[0-9a-fA-F]{40,}\b"), "[hidden]"),
    (re.compile(r"(?<![A-Za-z0-9/._-])[A-Za-z0-9+_-][A-Za-z0-9+/_-]{31,}={0,2}"), "[hidden]"),
]
CAUSES = [
    (r"memoryerror|out of memory|cannot allocate memory|oom.?kill", "The bot ran out of memory."),
    (r"no space left", "The server's disk is full."),
    (r"(?:http|status|code|error)\D{0,10}429\b|rate.?limit|too many requests", "The exchange or RPC is rate limiting the bot."),
    (r"(?:http|status|code|error)\D{0,10}40[13]\b|unauthori[sz]ed|forbidden|invalid api|api.?key.*(invalid|expired)|invalid signature|signature.*(invalid|mismatch)", "An API key was refused. It may have expired or lost a permission."),
    (r"insufficient (funds|balance|margin)|not enough (funds|balance|margin)|margin is insufficient", "The account doesn't have enough funds or margin."),
    (r"out of gas|intrinsic gas|gas required exceeds|insufficient gas|underpriced", "The transaction ran into a gas problem."),
    (r"nonce too low|nonce too high|replacement transaction|invalid nonce", "The wallet nonce is out of sync."),
    (r"execution reverted|transaction reverted|\brevert(ed)?\b", "Transactions are reverting on chain."),
    (r"timed? ?out|connection (refused|reset|aborted|error)|connectionerror|network is unreachable|name resolution|getaddrinfo|(?:http|status|code|error)\D{0,10}50[234]\b|bad gateway|service unavailable", "A network, exchange or RPC connection failed."),
    (r"modulenotfounderror|importerror|cannot find module", "A code dependency is missing."),
    (r"database is locked", "The bot's database is locked."),
    (r"permission denied", "The bot was refused permission for a file or command."),
]
CAUSES = [(re.compile(a, re.I), b) for a, b in CAUSES]
ERROR_LINE = re.compile(r"(error|exception|fatal|panic|traceback)", re.I)


def scrub(text, limit=LOG_CHARS):
    text = CTRL_RE.sub("", ANSI_RE.sub("", text.replace("\r\n", "\n").replace("\r", "\n")))
    for rx, sub in SECRET_RES:
        text = rx.sub(sub, text)
    return text.strip()[-limit:]


def likely_cause(log, code=None):
    """Plain rules, not AI: the newest matching line in the log wins."""
    best, at = None, -1
    for rx, why in CAUSES:
        for m in rx.finditer(log or ""):
            if m.start() > at:
                best, at = why, m.start()
    if best:
        return best
    if code in (137, -9):
        return "Something force-killed the process. That often means the server ran out of memory."
    if code in (143, -15, 130, -2):
        return "The process was told to stop by a signal, such as a restart or shutdown."
    hits = [l.strip() for l in (log or "").splitlines() if ERROR_LINE.search(l) and l.strip() != "Traceback (most recent call last):"]
    return f"Last error: {hits[-1][:160]}" if hits else None


def diagnosis(b, now):
    log = b["last_log"]
    if not log or now - (b["log_at"] or 0) > LOG_FRESH:
        return ""
    cause = likely_cause(log, b["crash_code"] if b["crash_at"] else None)
    return (f"\n\nLikely cause: {cause}" if cause else "") + f"\n\nLast log lines ({fmt_ago(now - b['log_at'])}):\n{log}"


def fmt_ago(s):
    if s < 90: return "just now"
    return f"{int(s // 60)} min ago" if s < 5400 else f"{int(s // 3600)} hours ago"


# ---------- kill switch ----------
def request_halt(b, reason, now, manual=False):
    """Queues a stop for the agent, which collects it over its own outbound connection. Flatline never contacts the customer's server."""
    n, chat = b["name"], b["chat_id"]
    if not b["agent_seen"]:
        msg = f"KILL SWITCH could not run for {n}: its agent has never connected, so it can't be stopped from here. Stop it by hand. Send /agent {n} to set this up."
        send(chat, msg); event(chat, n, "kill_failed", msg, now)
        return None
    if b["halt_req"]:
        return f"{n} has already been told to stop." if manual else None
    q("UPDATE bots SET halt_req=?, halt_reason=?, kill_cleanup=NULL WHERE id=?", now, reason, b["id"])
    late = now - b["agent_seen"] > AGENT_WINDOW
    msg = f"KILL SWITCH sent to {n}. Reason: {reason}." + (
        f" Its agent was last seen {fmt_ago(now - b['agent_seen'])}, so this may not reach it. Be ready to stop it by hand." if late else " Waiting for its agent to confirm.")
    send(chat, msg); event(chat, n, "kill_sent", msg, now)
    return None


def finish_halt(b, cleanup, now):
    n = b["name"]
    notes = {"ok": "Your clean-up command ran.", "failed": "Your clean-up command FAILED. Check it now.", "none": "No clean-up command is set."}
    cleanup = cleanup if cleanup in notes else "none"
    q("UPDATE bots SET halt_req=0, halted_at=?, crash_at=0, a_stop=0, kill_cleanup=?, grace_from=? WHERE id=?", now, cleanup, now, b["id"])
    msg = f"KILL SWITCH confirmed: {n} has stopped. {notes[cleanup]} Open positions and orders stay as they are unless your clean-up closed them, so check your exchange. Alerts resume when it pings again."
    send(b["chat_id"], msg); event(b["chat_id"], n, "kill_done", msg, now)


# ---------- pings ----------
def clean_report(fields):
    out, ignored = {}, []
    for k, v in fields.items():
        if k not in ("balance", "errors", "net_today"):
            continue
        try:
            n = float(v)
            if not math.isfinite(n) or abs(n) > 1e15 or (k == "errors" and (n < 0 or n != int(n))):
                raise ValueError
            out[k] = int(n) if k == "errors" else n
        except (TypeError, ValueError):
            ignored.append(k)
    return out, ignored


def record_ping(token, fields=None):
    """Answers 200 for any known bot: a monitor must never break the bot's own loop."""
    now = time.time()
    with lock:
        b = one("SELECT * FROM bots WHERE token=?", token)
        if b is None:
            return None
        if not allowed("ping:" + token, PINGS_PER_MIN):
            return {"ok": True, "note": "too many pings, this one was ignored"}
        if not b["first_seen"]:
            q("UPDATE bots SET first_seen=1 WHERE id=?", b["id"])
            send(b["chat_id"], f"First ping received from {b['name']}.\n\n"
                 f"Try the alert: stop this bot's pings for {b['timeout_s']} seconds. You should get a message here. "
                 "Can't stop it right now? Send /test for a sample alert.")
        vals, ignored = clean_report(fields or {})
        q("UPDATE bots SET last_ping=?, crash_at=0, halted_at=0 WHERE id=?", now, b["id"])
        q("INSERT INTO beats VALUES(?,?,1) ON CONFLICT(bot_id, bucket) DO UPDATE SET n=n+1", b["id"], int(now // BUCKET))
        for k, v in vals.items():
            q(f"UPDATE bots SET {k}=? WHERE id=?", v, b["id"])
        log = (fields or {}).get("log")
        if isinstance(log, str) and log.strip():
            q("UPDATE bots SET last_log=?, log_at=? WHERE id=?", scrub(log), now, b["id"])
        res = {"ok": True}
        if b["halt_req"]:
            res.update(halt=True, reason=b["halt_reason"])
        if ignored:
            res["ignored"] = ignored
        return res


def agent_poll(token, alive, now=None):
    """The agent's regular check-in. A frozen bot's agent keeps polling without counting as a ping, so it can still be stopped."""
    now = now or time.time()
    res = record_ping(token) if alive else None
    with lock:
        b = one("SELECT * FROM bots WHERE token=?", token)
        if b is None:
            return None
        if not allowed("poll:" + token, PINGS_PER_MIN):
            return {"ok": True}
        q("UPDATE bots SET agent_seen=? WHERE id=?", now, b["id"])
        res = res or {"ok": True}
        if b["halt_req"]:
            res.update(halt=True, reason=b["halt_reason"])
        return res


def agent_report(token, d, now=None):
    """The agent saying what just happened: kind is crash, hang or killed."""
    now = now or time.time()
    kind = d.get("kind")
    if kind not in ("crash", "hang", "killed"):
        return {"ok": False, "error": "unknown kind"}
    with lock:
        b = one("SELECT * FROM bots WHERE token=?", token)
        if b is None:
            return None
        if not allowed(f"report:{kind}:{token}", 3):
            return {"ok": True, "note": "too many reports, this one was ignored"}
        log = d.get("log")
        if isinstance(log, str) and log.strip():
            q("UPDATE bots SET last_log=?, log_at=? WHERE id=?", scrub(log), now, b["id"])
        code = d.get("code")
        code = code if isinstance(code, int) and not isinstance(code, bool) and abs(code) < 100000 else None
        if kind == "killed":
            finish_halt(b, d.get("cleanup"), now)
        else:
            q("UPDATE bots SET crash_at=?, crash_kind=?, crash_code=? WHERE id=?", now, kind, code, b["id"])
            if kind == "crash":  # the process has already ended, so a waiting kill has nothing left to do
                q("UPDATE bots SET halt_req=0 WHERE id=?", b["id"])
        return {"ok": True}


# ---------- checks ----------
def fmt_num(x): return f"{x:,.2f}".rstrip("0").rstrip(".") if x == x else "?"


def stop_state(b, now):
    if b["paused"] or not b["last_ping"]:
        return False
    if b["halted_at"] and b["halted_at"] >= b["last_ping"]:
        return False
    if b["crash_at"] and b["crash_at"] >= b["last_ping"]:
        return True
    if b["a_stop"]:  # already alerted: only a real ping ends it, so a restart can't falsely report recovery
        return now - max(b["last_ping"], b["grace_from"] or 0) > b["timeout_s"]
    return now - max(b["last_ping"], b["grace_from"] or 0, START) > b["timeout_s"]


def conditions(b, now):
    n = b["name"]
    down = f"{n} stopped. No ping for {b['timeout_s']} seconds."
    if b["crash_at"] and b["crash_at"] >= (b["last_ping"] or 0):
        code = b["crash_code"]
        if b["crash_kind"] == "hang":
            down = f"{n} froze. Its process is still running, but it has stopped producing output."
        elif code is not None and code < 0:
            down = f"{n} stopped. It was ended by signal {-code}."
        else:
            down = f"{n} crashed. Exit code {'unknown' if code is None else code}."
    c = {"a_stop": (stop_state(b, now), down + diagnosis(b, now), f"{n} is back. Pings have resumed.")}
    if b["balance"] is not None and b["floor"] is not None:
        c["a_funds"] = (b["balance"] < b["floor"], f"{n}: funds are low. Balance {fmt_num(b['balance'])}, your floor is {fmt_num(b['floor'])}.", f"{n}: funds are back above your floor ({fmt_num(b['balance'])}).")
    if b["errors"] is not None and b["max_errors"] is not None:
        c["a_fail"] = (b["errors"] > b["max_errors"], f"{n}: failures are high. {b['errors']} reported, your limit is {b['max_errors']}.", f"{n}: failures are back within your limit ({b['errors']}).")
    if b["net_today"] is not None and b["loss_limit"] is not None:
        c["a_loss"] = (b["net_today"] < -b["loss_limit"], f"{n}: loss limit crossed. Net today {fmt_num(b['net_today'])}, your limit is -{fmt_num(b['loss_limit'])}.", f"{n}: net result is back within your limit ({fmt_num(b['net_today'])}).")
    return c


def run_checks(now=None):
    now = now or time.time()
    with lock:
        for b in rows("SELECT * FROM bots"):
            chat = b["chat_id"]
            if b["halt_req"] and now - b["halt_req"] > HALT_TTL:
                q("UPDATE bots SET halt_req=0 WHERE id=?", b["id"])
                msg = f"KILL SWITCH NOT CONFIRMED: {b['name']}'s agent didn't respond, so it may still be running. Stop it by hand. The request has been cancelled."
                send(chat, msg); event(chat, b["name"], "kill_failed", msg, now)
            armed = set(filter(None, (b["kill_on"] or "").split(",")))
            for flag, (bad, down, up) in conditions(b, now).items():
                if b["paused"] and flag == "a_stop":
                    continue
                if bad and not b[flag]:
                    q(f"UPDATE bots SET {flag}=1 WHERE id=?", b["id"]); send(chat, "ALERT: " + down)
                    event(chat, b["name"], flag, down.split("\n\n")[0], now)
                    word = next((k for k, v in KILL_FLAGS.items() if v == flag), None)
                    already_dead = flag == "a_stop" and b["crash_at"] and b["crash_kind"] == "crash"  # its agent has exited too
                    if word in armed and not already_dead:
                        request_halt(one("SELECT * FROM bots WHERE id=?", b["id"]), down.split("\n\n")[0].rstrip("."), now)
                elif not bad and b[flag]:
                    q(f"UPDATE bots SET {flag}=0 WHERE id=?", b["id"]); send(chat, "OK: " + up)
                    event(chat, b["name"], "ok", up, now)


# ---------- telegram ----------
def tg(method, payload, timeout=40):
    req = urllib.request.Request(f"{TG_API}{TG_TOKEN}/{method}", data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def get_bot(chat_id, name):
    return one("SELECT * FROM bots WHERE chat_id=? AND name=?", chat_id, name)


def urls_text(b):
    return (f"Ping address for {b['name']}. Keep it private:\n\n"
            f"curl -fsS {BASE_URL}/ping/{b['token']}\n\n"
            "Run that in your bot's main loop. To send numbers as well:\n\n"
            f"curl -fsS {BASE_URL}/report/{b['token']} -d balance=412.50 -d errors=2 -d net_today=-3.10")


HELP = """Commands:
/newbot NAME - add a bot and get its ping address
/bots - see your bots and their status
/urls NAME - show a bot's ping address again
/floor NAME 0.01 - alert when balance is below this
/maxerrors NAME 5 - alert when errors are above this
/losslimit NAME 20 - alert when net today is below minus this
/timeout NAME 120 - seconds without a ping before an alert
/pause NAME and /resume NAME - stop and restart alerts, such as during an update
/delete NAME - remove a bot
/test - send a sample alert
/agent NAME - set up crash reasons and the kill switch
/killon NAME loss,stop - stop the bot automatically on these alerts: stop, funds, fail, loss
/kill NAME - stop the bot now
/log NAME - see its last log lines and likely cause
/dashboard - open your private live dashboard
Use "off" as the value to clear a limit.

Flatline only uses what your bot sends. Never send it private keys or exchange API keys."""


def agent_text(b):
    return (f"Agent setup for {b['name']}. It runs your bot, reports crashes with the last log lines, and can stop the bot when told to. "
            "It only makes outgoing connections, so you don't open any ports.\n\n"
            f"curl -fsS {BASE_URL}/flatline.py -o flatline.py\n\n"
            f"FLATLINE_SERVER={BASE_URL} FLATLINE_TOKEN={b['token']} python3 flatline.py run -- python3 bot.py\n\n"
            "Replace python3 bot.py with your own start command. Keep the token private.\n\n"
            "Optional, placed before the two dashes:\n"
            '--on-kill "python3 cancel_orders.py" runs your clean-up after the bot stops\n'
            "--hang-after 300 reports a freeze after 300 seconds with no output\n\n"
            "If a supervisor restarts your bot, use restart on failure only. The agent exits with 0 after a kill, so the bot stays stopped.\n\n"
            "On a crash, the last 40 log lines are sent to Flatline and kept until the next report. Keys and tokens are hidden first, but this is best effort, so don't print secrets to your logs.")


def describe(b, now):
    if b["paused"]: st = "paused"
    elif not b["last_ping"]: st = "waiting for first ping"
    elif b["a_stop"]: st = "STOPPED"
    else: st = f"OK, last ping {int(now - b['last_ping'])}s ago"
    if b["halt_req"]: st = "kill switch sent, waiting for agent"
    elif b["halted_at"] and b["halted_at"] >= (b["last_ping"] or 0): st = "stopped by kill switch"
    parts = [f"{b['name']}: {st}"]
    for lab, v, lim, flag in (("balance", b["balance"], b["floor"], b["a_funds"]), ("errors", b["errors"], b["max_errors"], b["a_fail"]), ("net today", b["net_today"], b["loss_limit"], b["a_loss"])):
        if v is not None or lim is not None:
            parts.append(f"  {lab}: {'-' if v is None else fmt_num(v)}, limit {'not set' if lim is None else fmt_num(lim)}{' ALERT' if flag else ''}")
    if b["agent_seen"] or b["kill_on"]:
        seen = "not connected" if not b["agent_seen"] else "connected" if now - b["agent_seen"] <= AGENT_WINDOW else f"last seen {fmt_ago(now - b['agent_seen'])}"
        parts.append(f"  agent: {seen}, auto kill on: {(b['kill_on'] or 'nothing').replace(',', ', ')}")
    return "\n".join(parts)


def set_limit(chat, args, col, kind, label):
    if len(args) != 2:
        return f"Use: /{label} NAME VALUE"
    b = get_bot(chat, args[0])
    if b is None:
        return "No bot with that name. Send /bots to see your bots."
    if args[1].lower() == "off":
        q(f"UPDATE bots SET {col}=NULL WHERE id=?", b["id"])
        return f"{label} is cleared for {b['name']}."
    try:
        v = kind(args[1])
        if not math.isfinite(v) or v < 0 or abs(v) > 1e15:
            raise ValueError
    except ValueError:
        return "That value needs to be a number, 0 or higher."
    q(f"UPDATE bots SET {col}=? WHERE id=?", v, b["id"])
    return f"{label} for {b['name']} is now {args[1]}."


def handle_command(chat, text):
    parts = text.strip().split()
    cmd = parts[0].split("@")[0].lower() if parts else ""
    args = parts[1:]
    now = time.time()
    u = ensure_user(chat)
    if cmd == "/start":
        return ("Welcome to Flatline Watchdog. It alerts you here when a trading bot stops, runs low on funds, keeps failing or loses too much.\n\n"
                "Send /newbot NAME to begin, such as /newbot mybot.\n\n"
                "Flatline can't trade or move funds. It's monitoring only, not financial advice.")
    if cmd in ("/help", ""):
        return HELP
    if cmd == "/newbot":
        if len(args) != 1 or not NAME_RE.match(args[0]):
            return "Use: /newbot NAME. Names can have up to 32 letters, numbers, - or _."
        if one("SELECT COUNT(*) c FROM bots WHERE chat_id=?", chat)["c"] >= MAX_BOTS:
            return f"You can have up to {MAX_BOTS} bots. Use /delete NAME to free a slot."
        if get_bot(chat, args[0]):
            return "You already have a bot with that name."
        q("INSERT INTO bots(token, chat_id, name, created, timeout_s) VALUES(?,?,?,?,?)", secrets.token_urlsafe(24), chat, args[0], now, MIN_TIMEOUT)
        return urls_text(get_bot(chat, args[0]))
    if cmd == "/bots":
        bs = rows("SELECT * FROM bots WHERE chat_id=? ORDER BY id", chat)
        return "\n\n".join(describe(b, now) for b in bs) if bs else "No bots yet. Send /newbot NAME to add one."
    if cmd == "/urls":
        b = get_bot(chat, args[0]) if len(args) == 1 else None
        return urls_text(b) if b else "Use: /urls NAME"
    if cmd == "/floor": return set_limit(chat, args, "floor", float, "floor")
    if cmd == "/maxerrors": return set_limit(chat, args, "max_errors", int, "maxerrors")
    if cmd == "/losslimit": return set_limit(chat, args, "loss_limit", float, "losslimit")
    if cmd == "/timeout":
        b = get_bot(chat, args[0]) if len(args) == 2 else None
        if b is None:
            return "Use: /timeout NAME SECONDS"
        try:
            v = int(args[1])
        except ValueError:
            return "Use a whole number of seconds."
        if not MIN_TIMEOUT <= v <= 86400:
            return f"Choose between {MIN_TIMEOUT} and 86400 seconds."
        q("UPDATE bots SET timeout_s=? WHERE id=?", v, b["id"])
        return f"{b['name']} will alert after {v} seconds without a ping."
    if cmd in ("/pause", "/resume", "/delete"):
        b = get_bot(chat, args[0]) if len(args) == 1 else None
        if b is None:
            return f"Use: {cmd} NAME"
        if cmd == "/pause":
            q("UPDATE bots SET paused=1, a_stop=0 WHERE id=?", b["id"])
            return f"{b['name']} is paused. You won't get a stopped alert until you /resume it."
        if cmd == "/resume":
            q("UPDATE bots SET paused=0, grace_from=? WHERE id=?", now, b["id"])
            return f"{b['name']} is being watched again."
        q("DELETE FROM bots WHERE id=?", b["id"])
        q("DELETE FROM beats WHERE bot_id=?", b["id"])
        q("DELETE FROM events WHERE chat_id=? AND bot=?", chat, b["name"])
        return f"{b['name']} is removed. Its ping address no longer works."
    if cmd == "/agent":
        b = get_bot(chat, args[0]) if len(args) == 1 else None
        return agent_text(b) if b else "Use: /agent NAME"
    if cmd == "/killon":
        b = get_bot(chat, args[0]) if len(args) == 2 else None
        if b is None:
            return "Use: /killon NAME loss,stop\nChoices: stop, funds, fail, loss. Use off to clear."
        if args[1].lower() == "off":
            q("UPDATE bots SET kill_on='' WHERE id=?", b["id"])
            return f"Automatic kill is off for {b['name']}. You can still use /kill {b['name']}."
        words = [w for w in args[1].lower().split(",") if w]
        if not words or any(w not in KILL_FLAGS for w in words):
            return "Choices: stop, funds, fail, loss. Separate them with commas and no spaces."
        q("UPDATE bots SET kill_on=? WHERE id=?", ",".join(sorted(set(words))), b["id"])
        need = "" if b["agent_seen"] else f"\n\nIts agent hasn't connected yet, so this can't work until you set it up: /agent {b['name']}"
        return (f"{b['name']} will be stopped automatically on: {', '.join(sorted(set(words)))}. A false alarm will stop it too, so choose carefully. "
                "The stop rule only helps if the bot froze. If its whole server is down, nothing can reach it." + need)
    if cmd == "/kill":
        b = get_bot(chat, args[0]) if len(args) == 1 else None
        if b is None:
            return "Use: /kill NAME"
        return request_halt(b, "you sent /kill", now, manual=True) or ""
    if cmd == "/log":
        b = get_bot(chat, args[0]) if len(args) == 1 else None
        if b is None:
            return "Use: /log NAME"
        if not b["last_log"]:
            return f"No log lines saved for {b['name']} yet. They arrive with a crash report through /agent {b['name']}, or through the log field on /report."
        return f"{b['name']}:" + diagnosis(b, now) if now - (b["log_at"] or 0) <= LOG_FRESH else f"The last log lines for {b['name']} are over a day old, so they're hidden."
    if cmd == "/dashboard":
        return f"Your private dashboard. Anyone with this link can view it, so don't share it:\n{BASE_URL}/dash/{dash_token(u)}"
    if cmd == "/test":
        return "TEST ALERT: this is a sample. example-bot stopped. No ping for 60 seconds. Your real alerts will look like this."
    return "I don't know that command. Send /help to see what I can do."


def poll_loop():
    with lock:
        row = one("SELECT v FROM meta WHERE k='offset'")
    offset = int(row["v"]) if row else 0
    while True:
        try:
            res = tg("getUpdates", {"offset": offset, "timeout": 25, "allowed_updates": ["message"]}, timeout=40)
            for up in res.get("result", []):
                offset = up["update_id"] + 1
                with lock:
                    q("INSERT OR REPLACE INTO meta VALUES('offset',?)", str(offset))
                m = up.get("message") or {}
                chat = m.get("chat") or {}
                text = m.get("text")
                if chat.get("type") != "private" or not isinstance(text, str) or (ALLOWED_CHATS and chat.get("id") not in ALLOWED_CHATS) or not allowed(f"cmd:{chat['id']}", 20):
                    continue
                with lock:
                    reply = handle_command(chat["id"], text[:300])
                    if reply:
                        send(chat["id"], reply)
        except (urllib.error.URLError, OSError, ValueError, KeyError) as e:
            print("telegram poll failed:", type(e).__name__, flush=True)
            time.sleep(5)


def send_loop():
    while True:
        now = time.time()
        alive_at["sender"] = now
        with lock:
            m = one("SELECT * FROM outbox WHERE not_before<=? ORDER BY id LIMIT 1", now)
        if m is None:
            time.sleep(.2)
            continue
        try:
            tg("sendMessage", {"chat_id": m["chat_id"], "text": m["text"], "disable_web_page_preview": True}, timeout=20)
            with lock:
                q("DELETE FROM outbox WHERE id=?", m["id"])
            time.sleep(.05)
        except urllib.error.HTTPError as e:
            if e.code == 429:
                with lock:
                    q("UPDATE outbox SET not_before=? WHERE id=?", now + 5, m["id"])
            elif e.code in (400, 403):
                print("telegram refused a message:", e.code, flush=True)
                with lock:
                    q("DELETE FROM outbox WHERE id=?", m["id"])
            else:
                with lock:
                    q("UPDATE outbox SET not_before=? WHERE id=?", now + 15, m["id"])
        except (urllib.error.URLError, OSError, ValueError) as e:
            print("telegram send failed:", type(e).__name__, flush=True)
            with lock:
                q("UPDATE outbox SET not_before=? WHERE id=?", now + 15, m["id"])
                q("DELETE FROM outbox WHERE created<?", now - 86400)


def healthy(now=None):
    """True only if alerts can really go out: both loops are running and no alert is stuck."""
    now = now or time.time()
    if now - alive_at["checks"] > HEALTH_STALE or now - alive_at["sender"] > HEALTH_STALE:
        return False
    with lock:
        oldest = one("SELECT MIN(created) m FROM outbox")["m"]
    return oldest is None or now - oldest <= OUTBOX_STALE


def heartbeat_loop():
    """Checks itself through the public address, so a web server or certificate failure counts too. Silence is the alarm."""
    while True:
        time.sleep(HEARTBEAT_EVERY)
        try:
            with urllib.request.urlopen(BASE_URL + "/health", timeout=15) as r:
                good = r.status == 200
            if good:
                urllib.request.urlopen(urllib.request.Request(HEARTBEAT_URL, headers={"User-Agent": "flatline-heartbeat"}), timeout=15).read(64)
        except (urllib.error.URLError, OSError, ValueError) as e:
            print("heartbeat skipped:", type(e).__name__, flush=True)


def check_loop():
    while True:
        try:
            run_checks()
            alive_at["checks"] = time.time()
        except Exception as e:  # keep watching even if one pass fails
            print("check pass failed:", type(e).__name__, str(e)[:120], flush=True)
        time.sleep(CHECK_EVERY)


# ---------- dashboard ----------
def dash_token(u):
    if u["dash_token"]:
        return u["dash_token"]
    tok = secrets.token_urlsafe(24)
    q("UPDATE users SET dash_token=? WHERE chat_id=?", tok, u["chat_id"])
    return tok


def bot_state(b, now):
    if b["halt_req"]: return "killing"
    if b["halted_at"] and b["halted_at"] >= (b["last_ping"] or 0): return "halted"
    if b["paused"]: return "paused"
    if not b["last_ping"]: return "waiting"
    if b["a_stop"] or stop_state(b, now): return "down"
    if b["a_funds"] or b["a_fail"] or b["a_loss"]: return "warn"
    return "ok"


def dash_data(u, now=None):
    """Only what the customer may see: ping tokens and pay tokens are never included."""
    now = now or time.time()
    head = int(now // BUCKET)
    bots = []
    for b in rows("SELECT * FROM bots WHERE chat_id=? ORDER BY id", u["chat_id"]):
        seen = {r["bucket"]: r["n"] for r in rows("SELECT bucket, n FROM beats WHERE bot_id=? AND bucket>?", b["id"], head - BUCKETS)}
        first = int((b["created"] or now) // BUCKET)
        fresh = b["last_log"] and now - (b["log_at"] or 0) <= LOG_FRESH
        bots.append({
            "name": b["name"], "state": bot_state(b, now), "age": None if not b["last_ping"] else round(now - b["last_ping"], 1),
            "last_ping": b["last_ping"], "timeout": b["timeout_s"], "balance": b["balance"], "errors": b["errors"], "net": b["net_today"],
            "floor": b["floor"], "max_errors": b["max_errors"], "loss_limit": b["loss_limit"],
            "alerts": {k: bool(b[v]) for k, v in KILL_FLAGS.items()},
            "beats": [-1 if i < first else seen.get(i, 0) for i in range(head - BUCKETS + 1, head + 1)],
            "kill": {"on": [w for w in (b["kill_on"] or "").split(",") if w], "agent": bool(b["agent_seen"]) and now - b["agent_seen"] <= AGENT_WINDOW,
                     "reason": b["halt_reason"] if b["halt_req"] else None, "cleanup": b["kill_cleanup"]},
            "log": b["last_log"] if fresh else None, "log_age": round(now - b["log_at"]) if fresh else None,
            "cause": likely_cause(b["last_log"], b["crash_code"] if b["crash_at"] else None) if fresh else None,
        })
    evs = rows("SELECT bot, kind, text, at FROM events WHERE chat_id=? ORDER BY id DESC LIMIT 30", u["chat_id"])
    return {"now": now, "bots": bots, "events": [dict(e) for e in evs]}


# ---------- web ----------
DASH_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    "X-Robots-Tag": "noindex", "Referrer-Policy": "no-referrer",
}


def read_static(name):
    with open(os.path.join(HERE, name), encoding="utf-8") as f:
        return f.read()


class Handler(BaseHTTPRequestHandler):
    timeout = 15
    server_version = "Flatline"
    sys_version = ""

    def log_message(self, *a):  # paths contain secret tokens, so they are never logged
        pass

    def out(self, code, body, ctype="application/json", extra=None):
        data = (json.dumps(body) if isinstance(body, dict) else body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def body(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = -1
        if n < 0 or n > MAX_BODY:
            return None
        return self.rfile.read(n) if n else b""

    def route(self):
        path, _, query = self.path.partition("?")
        seg = path.strip("/").split("/")
        raw = self.body()
        if raw is None:
            return self.out(413, {"ok": False, "error": "request too large"})
        if len(seg) == 2 and seg[0] in ("ping", "report") and self.command in ("GET", "HEAD", "POST"):
            fields = {}
            if seg[0] == "report":
                if (self.headers.get("Content-Type") or "").startswith("application/json"):
                    try:
                        j = json.loads(raw or b"{}")
                        fields = j if isinstance(j, dict) else {}
                    except ValueError:
                        pass
                else:
                    fields = {k: v[-1] for k, v in urllib.parse.parse_qs(raw.decode("utf-8", "replace") or query).items()}
            res = record_ping(seg[1], fields)
            return self.out(200, res) if res else self.out(404, {"ok": False, "error": "unknown bot address"})
        if len(seg) == 2 and seg[0] == "poll" and self.command in ("GET", "POST"):
            res = agent_poll(seg[1], "alive=1" in query.split("&"))
            return self.out(200, res) if res else self.out(404, {"ok": False, "error": "unknown bot address"})
        if len(seg) == 2 and seg[0] == "crash" and self.command == "POST":
            try:
                d = json.loads(raw or b"{}")
                d = d if isinstance(d, dict) else {}
            except ValueError:
                d = {}
            res = agent_report(seg[1], d)
            return self.out(200, res) if res else self.out(404, {"ok": False, "error": "unknown bot address"})
        if seg == ["health"] and self.command in ("GET", "HEAD"):
            good = healthy()
            return self.out(200 if good else 503, {"ok": good})
        if seg == ["flatline.py"] and self.command in ("GET", "HEAD"):
            return self.out(200, read_static("flatline.py"), "text/x-python; charset=utf-8")
        if seg == ["demo"] and self.command in ("GET", "HEAD"):
            return self.out(200, read_static("dash.html"), "text/html; charset=utf-8", DASH_HEADERS)
        if seg[0] == "dash" and len(seg) in (2, 3) and self.command in ("GET", "HEAD"):
            with lock:
                u = one("SELECT * FROM users WHERE dash_token=?", seg[1])
            if u is None:
                return self.out(404, "Not found", "text/plain")
            if len(seg) == 2:
                return self.out(200, read_static("dash.html"), "text/html; charset=utf-8", DASH_HEADERS)
            if seg[2] == "data":
                if not allowed("dash:" + seg[1], 60):
                    return self.out(429, {"error": "Too many requests."})
                with lock:
                    return self.out(200, dash_data(u))
            return self.out(404, "Not found", "text/plain")
        return self.out(404, {"ok": False, "error": "not found"})

    def safe(self):
        try:
            self.route()
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            pass
        except Exception as e:
            print("request failed:", type(e).__name__, flush=True)
            try:
                self.out(500, {"ok": False, "error": "server error"})
            except OSError:
                pass

    do_GET = do_POST = do_HEAD = safe


def main():
    for name, val in (("TELEGRAM_BOT_TOKEN", TG_TOKEN), ("BASE_URL", BASE_URL)):
        if not val:
            raise SystemExit(f"{name} is not set. See .env.example")
    open_db()
    for fn in (poll_loop, send_loop, check_loop):
        threading.Thread(target=fn, daemon=True).start()
    if HEARTBEAT_URL:
        threading.Thread(target=heartbeat_loop, daemon=True).start()
    print(f"Flatline app on {HOST}:{PORT}", flush=True)
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
