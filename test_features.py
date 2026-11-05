#!/usr/bin/env python3
"""Kill switch, crash reasons and dashboard, run against a fake Telegram with the real flatline.py agent."""
import json, os, re, signal, subprocess, sys, tempfile, threading, time, urllib.error, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
HERE = os.path.dirname(os.path.abspath(__file__))
sent, updates, hb, broken = [], [], [], [False]
class Fake(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def j(self, o):
        d = json.dumps(o).encode(); self.send_response(200); self.send_header("Content-Length", str(len(d))); self.end_headers(); self.wfile.write(d)
    def do_GET(self):
        hb.append(time.time()); self.j({"ok": True})
    def do_POST(self):
        b = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        if self.path.endswith("/getUpdates"):
            time.sleep(.1); u = updates[:]; del updates[:len(u)]; return self.j({"ok": True, "result": u})
        if broken[0]:
            self.send_response(500); self.send_header("Content-Length", "0"); self.end_headers(); return
        sent.append((b["chat_id"], b["text"])); self.j({"ok": True})
fs = ThreadingHTTPServer(("127.0.0.1", 0), Fake); threading.Thread(target=fs.serve_forever, daemon=True).start(); FP = fs.server_address[1]
tmp = tempfile.mkdtemp(dir=sys.argv[1]); PORT = 18092; A = f"http://127.0.0.1:{PORT}"
env = dict(os.environ, DB_PATH=tmp + "/a.db", TELEGRAM_BOT_TOKEN="T", TG_API=f"http://127.0.0.1:{FP}/bot", 
           BASE_URL=A, APP_PORT=str(PORT), MIN_TIMEOUT="2", CHECK_SECS="0.2", RECONCILE_SECS="60", HALT_TTL_SECS="4", MAX_BOTS="20", ALLOWED_CHATS="1,2,3,4", HEARTBEAT_URL=f"http://127.0.0.1:{FP}/hb", HEARTBEAT_SECS="0.5", OUTBOX_STALE_SECS="2")
P = subprocess.Popen([sys.executable, "-I", "-B", HERE + "/app.py"], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
fails, uid, agents = [], [0], []
def ok(n, c):
    print(("PASS " if c else "FAIL ") + n, flush=True)
    if not c: fails.append(n)
def cmd(t, chat=1):
    uid[0] += 1; updates.append({"update_id": uid[0], "message": {"chat": {"id": chat, "type": "private"}, "text": t}})
def wait(sub, chat=1, t=8, frm=0):
    e = time.time() + t
    while time.time() < e:
        for c, m in sent[frm:]:
            if c == chat and sub in m: return m
        time.sleep(.05)
def http(path, data=None):
    r = urllib.request.Request(A + path, data=data, method="POST" if data is not None else "GET", headers={"Content-Type": "application/json"} if data is not None else {})
    try:
        with urllib.request.urlopen(r, timeout=8) as x: return x.status, x.read().decode(), dict(x.headers)
    except urllib.error.HTTPError as e: return e.code, e.read().decode(), dict(e.headers)
def newbot(name, chat=1):
    cmd("/newbot " + name, chat); return wait(f"Ping address for {name}", chat).split("/ping/")[1].split()[0]
def agent(tok, *opts, bot=()):
    e = dict(os.environ, FLATLINE_TOKEN=tok, FLATLINE_SERVER=A, FLATLINE_MIN_INTERVAL="0.3")
    p = subprocess.Popen([sys.executable, "-I", "-B", HERE + "/flatline.py", "run", "--interval", "0.4", *opts, "--", *bot], env=e, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    agents.append(p); return p
py = sys.executable
time.sleep(1)
try:
    cmd("/start"); wait("Welcome")
    cmd("/start", 99); time.sleep(.6); ok("chats outside ALLOWED_CHATS are ignored", not any(c == 99 for c, _ in sent))
    # scrubbing
    t = newbot("scrub"); http("/ping/" + t)
    leak = "\n".join(["api_key=ABC123SECRET", 'password: "hunter2 two"', "Authorization: Bearer abc.def", "pk 0x" + "ab" * 32, "https://user:pw123@rpc.example.com/x",
                      "seed phrase word word word", "tg 123456789:" + "A" * 35, "eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0", "\x1b[31mHTTP status 429 from exchange\x1b[0m"])
    s, b, _ = http("/report/" + t, json.dumps({"log": leak}).encode())
    cmd("/log scrub"); m = wait("scrub:")
    ok("log saved through /report", m and "Last log lines" in m)
    for bad in ("ABC123SECRET", "hunter2", "abc.def", "ab" * 32, "pw123", "word word", "A" * 35, "eyJhbGci", "\x1b"):
        ok("secret hidden: " + bad[:8], m and bad not in m)
    ok("cause from log", m and "rate limiting" in m)
    s, b, _ = http("/report/" + t, b'{"log": 5, "balance": 3}'); ok("non-text log ignored", s == 200)
    # crash reason
    t = newbot("crasher")
    bot = (py, "-c", "import sys\nprint('starting')\nprint('ccxt.InsufficientFunds: insufficient balance api_key=SECRET1', flush=True)\nsys.exit(3)")
    n = len(sent); p = agent(t, bot=bot); ok("agent exit code is bot's", p.wait(10) == 3)
    m = wait("ALERT: crasher crashed", frm=n); ok("instant crash alert", m and "Exit code 3" in m)
    ok("crash has cause", m and "enough funds" in m); ok("crash has log", m and "starting" in m); ok("crash log scrubbed", m and "SECRET1" not in m)
    ok("agent passes output through", "starting" in p.stdout.read())
    n = len(sent); time.sleep(1); ok("no repeat crash alert", not any("crasher" in x and "ALERT" in x for _, x in sent[n:]))
    n = len(sent); http("/ping/" + t); ok("recovery after crash", wait("OK: crasher is back", frm=n))
    # bad command
    t = newbot("nocmd"); n = len(sent); p = agent(t, bot=("/nonexistent/bot",)); ok("missing command exit", p.wait(10) == 127)
    ok("missing command alert", wait("nocmd crashed", frm=n))
    # manual kill with clean-up
    t = newbot("killme"); marker = tmp + "/cleanup"
    n = len(sent); cmd("/kill killme"); m = wait("KILL SWITCH could not run", frm=n); ok("kill refused with no agent", m and "/agent killme" in m)
    time.sleep(.4); ok("refusal only sent once", sum("could not run" in x for _, x in sent[n:]) == 1)
    p = agent(t, "--on-kill", f"touch {marker}", bot=(py, "-c", "import time\nprint('up',flush=True)\ntime.sleep(60)")); time.sleep(1.2)
    cmd("/bots"); m = wait("killme: OK"); ok("/bots shows agent connected", m and "agent: connected" in m)
    n = len(sent); cmd("/kill killme"); ok("kill sent", wait("KILL SWITCH sent to killme", frm=n))
    m = wait("KILL SWITCH confirmed: killme", frm=n); ok("kill confirmed", m); ok("cleanup reported", m and "clean-up command ran" in m)
    ok("agent exits 0 after kill", p.wait(10) == 0); ok("cleanup really ran", os.path.exists(marker))
    ok("kill warns about positions", m and "check your exchange" in m)
    n = len(sent); time.sleep(3); ok("no stop alert after kill", not any("ALERT: killme" in x for _, x in sent[n:]))
    # stale kill can't hit a later restart: no agent is polling, so the request expires
    t = newbot("late"); p = agent(t, bot=(py, "-c", "import time\ntime.sleep(1)")); p.wait(10)  # agent has been seen, then gone
    n = len(sent); cmd("/kill late"); ok("kill queued", wait("KILL SWITCH sent to late", frm=n))
    ok("unconfirmed kill expires", wait("KILL SWITCH NOT CONFIRMED", frm=n, t=9))
    s, b, _ = http("/ping/" + t); ok("expired kill not delivered", "halt" not in json.loads(b))
    # automatic kill on loss, and a frozen bot
    t = newbot("auto"); cmd("/killon auto nonsense"); ok("bad /killon rejected", wait("Choices: stop"))
    cmd("/losslimit auto 5"); wait("losslimit for auto"); cmd("/killon auto loss,stop"); ok("/killon set", wait("stopped automatically on: loss, stop"))
    p = agent(t, bot=(py, "-c", "import time\nprint('up',flush=True)\ntime.sleep(60)")); time.sleep(1.2)
    n = len(sent); http("/report/" + t, json.dumps({"net_today": -9}).encode())
    ok("loss alert", wait("ALERT: auto: loss limit", frm=n)); ok("auto kill confirmed", wait("KILL SWITCH confirmed: auto", frm=n)); ok("agent stopped", p.wait(10) == 0)
    t = newbot("frozen"); cmd("/killon frozen stop"); wait("frozen will be stopped")
    p = agent(t, "--hang-after", "1", bot=(py, "-c", "import time\nprint('last words',flush=True)\ntime.sleep(60)"))
    n = len(sent); m = wait("ALERT: frozen froze", frm=n, t=6); ok("freeze alert", m and "last words" in m); ok("frozen bot killed", wait("KILL SWITCH confirmed: frozen", frm=n)); ok("frozen agent exit", p.wait(10) == 0)
    # armed stop + real crash shouldn't queue a kill that can never confirm
    cmd("/delete scrub"); wait("scrub is removed"); cmd("/delete nocmd"); wait("nocmd is removed")
    # dashboard and isolation
    n = len(sent); cmd("/dashboard"); m = wait("/dash/", frm=n); d = m.split("/dash/")[1].split()[0]
    s, b, h = http(f"/dash/{d}"); ok("dash page", s == 200 and "<canvas" in b or "canvas" in b); ok("dash csp", "default-src 'none'" in h.get("Content-Security-Policy", ""))
    ok("dash noindex", h.get("X-Robots-Tag") == "noindex")
    s, b, _ = http(f"/dash/{d}/data"); j = json.loads(b); names = [x["name"] for x in j["bots"]]
    ok("dash data has bots", "crasher" in names and "auto" in names); ok("deleted bot gone", "scrub" not in names and not any(e["bot"] == "scrub" for e in j["events"]))
    ok("dash shows no tokens", not any(x in b for x in re.findall(r"/ping/(\S+)", " ".join(m for _, m in sent))))
    ok("dash beats length", all(len(x["beats"]) == 96 for x in j["bots"]))
    st = {x["name"]: x["state"] for x in j["bots"]}; ok("dash states", st["killme"] == "halted" and st["auto"] == "halted", )
    ok("dash has events", any(e["kind"] == "kill_done" for e in j["events"]))
    ok("bad dash token 404", http("/dash/nope")[0] == 404 and http("/dash/nope/data")[0] == 404)
    cmd("/newbot other", 2); wait("Ping address for other", 2); n = len(sent); cmd("/dashboard", 2); d2 = wait("/dash/", 2, frm=n).split("/dash/")[1].split()[0]
    s, b, _ = http(f"/dash/{d2}/data"); ok("dash isolated", d2 != d and "crasher" not in b)
    s, b, _ = http("/demo"); ok("demo page", s == 200 and "canvas" in b)
    s, b, _ = http("/flatline.py"); ok("agent served", s == 200 and "class Agent" in b)
    ok("no ping with unknown poll", http("/poll/nope", b"")[0] == 404); ok("bad crash token 404", http("/crash/nope", b'{"kind":"crash"}')[0] == 404)
    s, b, _ = http("/crash/" + t, b'{"kind":"weird"}'); ok("bad kind rejected", json.loads(b).get("ok") is False)
    s, _, _ = http("/crash/" + t, b"not json"); ok("bad crash body is safe", s == 200)
    ok("health ok", json.loads(http("/health")[1])["ok"] is True); ok("heartbeat is sent", len(hb) > 3)
    broken[0] = True; cmd("/test", 4); time.sleep(3.5); s, b, _ = http("/health"); ok("stuck alerts fail health", s == 503 and json.loads(b)["ok"] is False)
    n = len(hb); time.sleep(1.5); ok("heartbeat stops when unhealthy", len(hb) == n)
    broken[0] = False; ok("stuck alert still delivered", wait("TEST ALERT", 4, t=20)); time.sleep(.2); ok("health recovers", http("/health")[0] == 200)
    n = len(hb); time.sleep(1.5); ok("heartbeat resumes", len(hb) > n)
    r = newbot("restarted", 3); cmd("/timeout restarted 2", 3); wait("restarted will alert", 3); http("/ping/" + r); ok("alert before restart", wait("ALERT: restarted stopped", 3))
    P.terminate(); out = P.communicate(timeout=5)[0]; ok("tokens not in server log", t not in out); ok("no server errors", "failed" not in out); print(out[:400])
    n = len(sent); P = subprocess.Popen([sys.executable, "-I", "-B", HERE + "/app.py"], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True); time.sleep(3)
    ok("restart doesn't report false recovery", not any("restarted is back" in x for _, x in sent[n:])); ok("restart doesn't repeat the alert", not any("ALERT: restarted" in x for _, x in sent[n:]))
    http("/ping/" + r); ok("real ping still recovers", wait("OK: restarted is back", 3, frm=n))
    P.terminate(); P.communicate(timeout=5)
finally:
    for a in agents:
        if a.poll() is None: a.kill()
    if P.poll() is None: P.kill()
print("FAILED:", fails) if fails else print("ALL PASSED"); sys.exit(1 if fails else 0)
