# Flatline Watchdog

Free, open-source monitoring for trading bots. You run it yourself, and it messages you on Telegram when a bot stops, freezes, runs low on funds, keeps failing or loses too much.

It can also tell you the likely reason for a crash, and stop a bot from your phone.

![License: MIT](https://img.shields.io/badge/license-MIT-f2b866)

## What it does

- **Alerts:** a bot stopped pinging, froze, crashed, ran low on funds, has too many errors, or crossed your loss limit.
- **Crash reasons:** the alert includes a likely cause and the last log lines, with keys and tokens hidden on a best-effort basis.
- **Kill switch:** send `/kill mybot`, or use `/killon mybot loss,stop` to stop it automatically on the alerts you choose. Your own clean-up command can then run.
- **Live dashboard:** a private page for each Telegram user, with a heartbeat trace and a 3D tower built from the last 24 hours of pings.
- **Interactive demo:** open `/demo` on your server to crash and kill a simulated bot.

It needs only Python 3. There's nothing to install, and no exchange or wallet keys are involved.

## Run your own

You need a server with a public HTTPS address, and a Telegram bot token from [@BotFather](https://t.me/BotFather).

```bash
git clone https://github.com/Savi7037/flatline-watchdog.git
cd flatline-watchdog
cp .env.example .env     # then fill it in
set -a; . ./.env; set +a
python3 app.py
```

To find your chat ID for `ALLOWED_CHATS`, message [@userinfobot](https://t.me/userinfobot). **Set it**, or anyone who finds your Telegram bot can use your server.

For a long-running setup, see [`deploy/flatline.service`](deploy/flatline.service) and [`deploy/Caddyfile.example`](deploy/Caddyfile.example).

## Watch a bot

Send `/newbot mybot` to your Telegram bot. You'll get a private address.

**Simple way:** call it from your bot's main loop.

```bash
curl -fsS https://your-server/ping/YOUR_TOKEN
curl -fsS https://your-server/report/YOUR_TOKEN -d balance=412.50 -d errors=2 -d net_today=-3.10
```

**With crash reasons and the kill switch:** send `/agent mybot` and start your bot through the agent. It only makes outgoing connections, so you don't open any ports.

```bash
curl -fsS https://your-server/flatline.py -o flatline.py
FLATLINE_SERVER=https://your-server FLATLINE_TOKEN=YOUR_TOKEN python3 flatline.py run -- python3 bot.py
```

| Agent option (before the `--`) | What it does |
| --- | --- |
| `--on-kill "python3 cancel_orders.py"` | Runs your clean-up after the bot stops |
| `--hang-after 300` | Reports a freeze after 300 seconds with no output |
| `--grace 10` | Seconds the bot gets to exit before it's force-stopped |

If a supervisor restarts your bot, use restart on failure only. The agent exits with 0 after a kill, so the bot stays stopped.

## Telegram commands

| Command | What it does |
| --- | --- |
| `/newbot NAME` | Add a bot and get its private address |
| `/bots` | See your bots and their status |
| `/urls NAME` | Show a bot's address again |
| `/floor NAME 0.01` | Alert when balance is below this |
| `/maxerrors NAME 5` | Alert when errors are above this |
| `/losslimit NAME 20` | Alert when net today is below minus this |
| `/timeout NAME 120` | Seconds without a ping before an alert |
| `/pause NAME`, `/resume NAME` | Stop and restart alerts, such as during an update |
| `/agent NAME` | Set up crash reasons and the kill switch |
| `/killon NAME loss,stop` | Stop the bot automatically on `stop`, `funds`, `fail` or `loss` |
| `/kill NAME` | Stop the bot now |
| `/log NAME` | See its last log lines and likely cause |
| `/dashboard` | Get your private dashboard link |
| `/delete NAME` | Remove a bot and its data |
| `/test` | Send a sample alert |

## Know the limits

- **Don't rely on it alone.** Alerts and stops can be late, wrong or missed.
- **A stop isn't a trade.** Stopping a bot doesn't close positions or cancel orders unless your own clean-up command does.
- **A dead server can't be reached.** If the bot's whole server is down, the kill switch can't stop anything. An unconfirmed kill is cancelled after 10 minutes, and you're told to stop the bot by hand.
- **A false alarm can stop your bot** if you've set an automatic rule, so choose your rules carefully.
- **Logs can hold secrets.** Hiding them is best effort, so don't print keys or passwords to your logs. The last log lines are stored on your server and sent through Telegram.
- **Likely causes are guesses.** They come from simple pattern rules, not from understanding your bot.
- **Flatline can die too.** Set `HEARTBEAT_URL` to an outside monitor, such as a free [Healthchecks.io](https://healthchecks.io) check, so you hear about it if it stops.
- **Your server, your data.** Back up the database yourself if you need to keep it. It holds your bot tokens, so keep it private.

## Tests

```bash
python3 -I -B test_app.py /tmp
python3 -I -B test_features.py /tmp
```

These run the real app and agent against a fake Telegram server, so they need no tokens. The simulated numbers in the demo and videos aren't real results.

## Media

The [`media`](media) folder holds a profile picture and videos from when this was planned as a paid service. Some prices, links and bot names in them no longer apply. Commands in the tutorial may also differ.

## License

[MIT](LICENSE). Free to use, change and share. It comes with no warranty, and it isn't financial advice.
