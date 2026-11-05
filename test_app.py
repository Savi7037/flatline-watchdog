#!/usr/bin/env python3
"""End-to-end test against a fake Telegram server on localhost."""
import json, os, subprocess, sys, tempfile, threading, time, urllib.error, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
sent, updates = [], []
class Fake(BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def j(self,o,c=200):
        d=json.dumps(o).encode(); self.send_response(c); self.send_header("Content-Length",str(len(d))); self.end_headers(); self.wfile.write(d)
    def do_POST(self):
        b=json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        if self.path.endswith("/getUpdates"):
            time.sleep(.1); ups=updates[:]; del updates[:len(ups)]; return self.j({"ok":True,"result":ups})
        if self.path.endswith("/sendMessage"):
            sent.append((b["chat_id"],b["text"])); return self.j({"ok":True})
            oid=f"order_{len(orders)+1}"; orders[oid]=b; return self.j({"id":oid,"amount":b["amount"],"currency":b["currency"]})
        self.j({},404)
fs=ThreadingHTTPServer(("127.0.0.1",0),Fake); threading.Thread(target=fs.serve_forever,daemon=True).start(); FP=fs.server_address[1]
tmp=tempfile.mkdtemp(dir=sys.argv[1]); APORT=18091; A=f"http://127.0.0.1:{APORT}"
env=dict(os.environ,DB_PATH=tmp+"/a.db",TELEGRAM_BOT_TOKEN="T",TG_API=f"http://127.0.0.1:{FP}/bot",BASE_URL=A,APP_PORT=str(APORT),MAX_BOTS="3",MIN_TIMEOUT="2",CHECK_SECS="0.2")
P=subprocess.Popen([sys.executable,"-I","-B",os.path.join(os.path.dirname(os.path.abspath(__file__)),"app.py")],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
fails=[]; uid=[0]
def ok(n,c):
    print(("PASS " if c else "FAIL ")+n,flush=True)
    if not c: fails.append(n)
def cmd(t,chat=1,typ="private"):
    uid[0]+=1; updates.append({"update_id":uid[0],"message":{"chat":{"id":chat,"type":typ},"text":t}})
def wait(sub,chat=1,t=6,frm=0):
    e=time.time()+t
    while time.time()<e:
        for c,m in sent[frm:]:
            if c==chat and sub in m: return m
        time.sleep(.05)
    return None
def http(path,data=None,ct="application/x-www-form-urlencoded",method=None):
    r=urllib.request.Request(A+path,data=data,method=method,headers={"Content-Type":ct} if data is not None else {})
    try:
        with urllib.request.urlopen(r,timeout=8) as x: return x.status,x.read().decode()
    except urllib.error.HTTPError as e: return e.code,e.read().decode()
time.sleep(1)
try:
    cmd("/start"); ok("start",wait("Welcome"))
    cmd("/newbot bad name"); ok("bad name",wait("Use: /newbot"))
    cmd("/newbot alpha"); m=wait("Ping address"); ok("newbot",m); tok=m.split("/ping/")[1].split()[0]
    ok("unknown token 404",http("/ping/nope")[0]==404)
    ok("web error hides nothing odd",http("/")[0]==404)
    ok("first ping 200",json.loads(http("/ping/"+tok)[1])["ok"] is True)
    ok("first ping message",wait("First ping received"))
    cmd("/timeout alpha 2"); ok("timeout set",wait("will alert after 2"))
    cmd("/timeout alpha 1"); ok("timeout min enforced",wait("Choose between"))
    n=len(sent); ok("stop alert",wait("ALERT: alpha stopped",t=5,frm=n))
    n=len(sent); http("/ping/"+tok); ok("recovery",wait("OK: alpha is back",frm=n))
    n=len(sent); time.sleep(.6); ok("no repeat alert",not any("ALERT" in m for _,m in sent[n:]))
    for c in ("/floor alpha 10","/maxerrors alpha 2","/losslimit alpha 5"): cmd(c)
    ok("limits set",wait("losslimit for alpha"))
    n=len(sent); http("/report/"+tok,b"balance=1&errors=9&net_today=-20")
    ok("funds alert",wait("funds are low",frm=n)); ok("fail alert",wait("failures are high",frm=n)); ok("loss alert",wait("loss limit crossed",frm=n))
    n=len(sent); s,b=http("/report/"+tok,json.dumps({"balance":50,"errors":0,"net_today":1}).encode(),"application/json")
    ok("json report ok",s==200); ok("funds clear",wait("funds are back",frm=n)); ok("fail clear",wait("failures are back",frm=n)); ok("loss clear",wait("net result is back",frm=n))
    s,b=http("/report/"+tok,b"balance=nan&errors=-1&net_today=abc"); ok("bad numbers ignored",s==200 and len(json.loads(b)["ignored"])==3)
    ok("too large 413",http("/report/"+tok,b"x"*5000)[0]==413)
    cmd("/pause alpha"); ok("pause",wait("is paused"))
    n=len(sent); time.sleep(2.6); ok("paused no alert",not any("stopped" in m for _,m in sent[n:]))
    cmd("/resume alpha"); ok("resume",wait("watched again")); http("/ping/"+tok)
    for i in range(3): cmd(f"/newbot b{i}")
    ok("3 bot limit",wait("up to 3 bots"))
    cmd("/newbot other",chat=2); ok("second user isolated",wait("Ping address",chat=2))
    cmd("/bots",chat=2); w=wait("waiting for first ping",chat=2); ok("users don't see each other",w and "alpha" not in w)
    cmd("/start",chat=-5,typ="group"); time.sleep(.5); ok("groups ignored",not any(c==-5 for c,_ in sent))
    cmd("/test"); ok("/test",wait("TEST ALERT"))
    print("LOG:",); P.terminate(); out=P.communicate(timeout=5)[0]; print(out[:500])
    ok("tokens not in log",tok not in out)
finally:
    if P.poll() is None: P.kill()
print("FAILED:",fails) if fails else print("ALL PASSED"); sys.exit(1 if fails else 0)
