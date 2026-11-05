#!/usr/bin/env python3
"""Flatline agent. Runs your bot, reports crashes with the last log lines, and stops the bot when you tell it to.

    FLATLINE_SERVER=https://your-server FLATLINE_TOKEN=your_token python3 flatline.py run -- python3 bot.py

It only makes outgoing connections and only needs Python 3. It sends no logs while the bot is healthy.
If Flatline can't be reached, your bot keeps running.
"""
import argparse, collections, json, os, re, shlex, signal, subprocess, sys, threading, time, urllib.error, urllib.request

SERVER = os.environ.get("FLATLINE_SERVER", "").rstrip("/")
KEEP_LINES, MAX_SEND = 40, 2500
SECRETS = [
    (re.compile(r"(?i)\b(mnemonic|seed[ _-]?phrase|seed)\b[^\n]*"), r"\1 [hidden]"),
    (re.compile(r"(?i)\bbearer\s+\S+"), "Bearer [hidden]"),
    (re.compile(r"://[^/\s:@]+:[^/\s@]+@"), "://[hidden]@"),
    (re.compile(r"""(?i)([\w-]*(?:api[_-]?key|apikey|secret|passw(?:or)?d|pwd|token|private[_-]?key|privkey|signature|credential|authorization)[\w-]*["']?\s*[:=]\s*)("[^"\n]*"|'[^'\n]*'|[^\s,;&}]+)"""), r"\1[hidden]"),
    (re.compile(r"\b\d{6,12}:[A-Za-z0-9_-]{30,}\b"), "[hidden]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_.-]{8,}"), "[hidden]"),
    (re.compile(r"\b(?:0x)?[0-9a-fA-F]{40,}\b"), "[hidden]"),
    (re.compile(r"(?<![A-Za-z0-9/._-])[A-Za-z0-9+_-][A-Za-z0-9+/_-]{31,}={0,2}"), "[hidden]"),
]


def say(msg):
    print(f"[flatline] {msg}", file=sys.stderr, flush=True)


def hidden(text):
    for rx, sub in SECRETS:
        text = rx.sub(sub, text)
    return text


class Agent:
    def __init__(self, token, opts, cmd):
        self.token, self.opts, self.cmd = token, opts, cmd
        self.lines = collections.deque(maxlen=KEEP_LINES)
        self.last_output = time.time()
        self.proc, self.signal_got, self.warned, self.hung = None, None, False, False

    def call(self, path, payload=None, tries=1):
        data = json.dumps(payload).encode() if payload is not None else b""
        req = urllib.request.Request(f"{SERVER}{path}", data=data, method="POST", headers={"Content-Type": "application/json", "User-Agent": "flatline-agent"})
        for attempt in range(tries):
            try:
                with urllib.request.urlopen(req, timeout=10) as r:
                    self.warned = False
                    return json.load(r)
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    self.warn("Flatline doesn't recognise this token. Your bot is still running, but isn't being watched.")
                    return {}
                self.warn(f"Flatline answered {e.code}. Your bot is still running.")
            except (OSError, ValueError):
                self.warn("Can't reach Flatline right now. Your bot is still running.")
            if attempt + 1 < tries:
                time.sleep(3)
        return {}

    def warn(self, msg):
        if not self.warned:
            say(msg)
        self.warned = True

    def tail(self):
        return hidden("".join(self.lines))[-MAX_SEND:]

    def report(self, kind, **extra):
        return self.call(f"/crash/{self.token}", dict(kind=kind, log=self.tail(), **extra), tries=3)

    def pump(self):
        out = getattr(sys.stdout, "buffer", None)
        for raw in iter(self.proc.stdout.readline, b""):
            self.last_output = time.time()
            self.lines.append(raw.decode("utf-8", "replace")[:500])
            try:
                out.write(raw); out.flush()
            except (OSError, ValueError, AttributeError):
                pass

    def signal_bot(self, sig):
        try:
            if os.name == "posix":
                os.killpg(self.proc.pid, sig)
            else:
                self.proc.terminate()
        except (ProcessLookupError, PermissionError, OSError):
            pass

    def stop_bot(self):
        self.signal_bot(signal.SIGTERM)
        try:
            self.proc.wait(self.opts.grace)
        except subprocess.TimeoutExpired:
            self.signal_bot(signal.SIGKILL if os.name == "posix" else signal.SIGTERM)
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                say("The bot would not stop.")
                return False
        return True

    def cleanup(self):
        if not self.opts.on_kill:
            return "none"
        try:
            ok = subprocess.run(shlex.split(self.opts.on_kill), timeout=120).returncode == 0
        except (OSError, ValueError, subprocess.TimeoutExpired):
            ok = False
        return "ok" if ok else "failed"

    def on_signal(self, num, _frame):
        self.signal_got = num
        self.signal_bot(num)

    def run(self):
        child_env = {k: v for k, v in os.environ.items() if k not in ("FLATLINE_TOKEN", "FLATLINE_SERVER")}
        self.call(f"/poll/{self.token}?alive=1")  # the first ping comes before the bot starts, so even an instant crash is reported
        try:
            self.proc = subprocess.Popen(self.cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=child_env, start_new_session=os.name == "posix")
        except OSError as e:
            self.lines.append(f"Couldn't start the bot: {e}\n")
            say(f"Couldn't start the bot: {e}")
            self.report("crash", code=127)
            return 127
        for s in (signal.SIGINT, signal.SIGTERM):
            signal.signal(s, self.on_signal)
        reader = threading.Thread(target=self.pump, daemon=True)
        reader.start()
        say(f"Watching your bot (pid {self.proc.pid}).")
        next_poll = time.time() + self.opts.interval
        while True:
            code = self.proc.poll()
            if code is not None:
                reader.join(2)
                if self.signal_got:
                    code = -self.signal_got
                self.report("crash", code=code)
                say(f"Your bot exited with code {code}. Flatline has been told.")
                return 128 + abs(code) if code < 0 else code
            if time.time() >= next_poll:
                next_poll = time.time() + self.opts.interval
                silent = time.time() - self.last_output
                now_hung = bool(self.opts.hang_after) and silent > self.opts.hang_after
                if now_hung and not self.hung:
                    self.report("hang")
                self.hung = now_hung
                res = self.call(f"/poll/{self.token}" + ("" if now_hung else "?alive=1"))
                if res.get("halt"):
                    say(f"Kill switch: {res.get('reason') or 'stop requested'}. Stopping your bot.")
                    stopped = self.stop_bot()
                    reader.join(2)
                    if not stopped:
                        return 1  # no confirmation: Flatline then tells the customer to stop it by hand
                    self.report("killed", cleanup=self.cleanup())
                    say("Your bot is stopped. Flatline has been told.")
                    return 0
            time.sleep(.2)


def main():
    ap = argparse.ArgumentParser(description="Run a trading bot under Flatline.", usage="FLATLINE_SERVER=url FLATLINE_TOKEN=token python3 flatline.py run [options] -- your bot command")
    sub = ap.add_subparsers(dest="action", required=True)
    r = sub.add_parser("run")
    r.add_argument("--interval", type=float, default=15, help="seconds between check-ins, 5 or more")
    r.add_argument("--hang-after", type=float, default=0, help="report a freeze after this many seconds with no output")
    r.add_argument("--on-kill", default="", help="clean-up command to run after a kill, such as cancelling orders")
    r.add_argument("--grace", type=float, default=10, help="seconds the bot gets to exit before it's force-stopped")
    r.add_argument("cmd", nargs=argparse.REMAINDER)
    o = ap.parse_args()
    cmd = o.cmd[1:] if o.cmd[:1] == ["--"] else o.cmd
    token = os.environ.get("FLATLINE_TOKEN", "")
    if not cmd or not token or not SERVER:
        ap.error("set FLATLINE_SERVER and FLATLINE_TOKEN, and give your bot's command after --")
    o.interval = max(o.interval, float(os.environ.get("FLATLINE_MIN_INTERVAL", 5)))
    sys.exit(Agent(token, o, cmd).run())


if __name__ == "__main__":
    main()
