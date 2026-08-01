# 🛰 vps-sentinel

A **single-file, zero-dependency** Telegram bot that watches a Linux VPS and tells you the moment something happens — straight to your private chat.

This is the public, sanitized version of the monitoring bot I run 24/7 on my own servers. Pure Python standard library: no pip installs, no framework, nothing to audit but one file.

## What it watches

| Event | Alert |
|---|---|
| ✅ SSH login accepted | 🔐 user, IP and auth method, instantly |
| 🔑 Failed-auth burst | 🚨 warning when brute-force noise spikes (N fails / window) |
| ⚙️ systemd services | 🔴 down notice + 🟢 recovery notice with downtime duration |
| 💾 Disk usage | alert past a threshold, re-arms with hysteresis |
| 📈 Load average | alert when 5-min load exceeds `cores × factor` |
| 💚 Daily heartbeat | one "all quiet" status a day — so silence never means "the bot died" |

## Commands

Answered **only** in the allow-listed chat:

```
/status   uptime, load, memory, disk, service states
/logins   the last accepted SSH logins
/help     command list
```

Example alert:

```
🔐 SSH login on my-vps
user deploy from 203.0.113.7 (publickey)
```

## Quick start

1. Create a bot with [@BotFather](https://t.me/BotFather) → copy the token.
2. Message your new bot once, then get your chat id:
   `curl -s https://api.telegram.org/bot<TOKEN>/getUpdates | grep -o '"id":[0-9]*' | head -1`
3. Configure and run:

```bash
git clone https://github.com/ouiriemmiraed/vps-sentinel && cd vps-sentinel
cp .env.example .env && nano .env        # token, chat id, services to watch
set -a && . ./.env && set +a
python3 sentinel.py
```

## Run it as a service

```bash
sudo cp deploy/sentinel.service /etc/systemd/system/
sudo nano /etc/systemd/system/sentinel.service   # point EnvironmentFile at your .env
sudo systemctl enable --now sentinel
```

## Configuration

Everything is environment variables — no secrets ever touch the code.

| Variable | Default | Meaning |
|---|---|---|
| `SENTINEL_BOT_TOKEN` | — | Telegram bot token (required) |
| `SENTINEL_CHAT_ID` | — | chat allowed to talk to the bot (required) |
| `SENTINEL_SERVICES` | *(empty)* | comma list of systemd units to watch, e.g. `nginx,docker` |
| `SENTINEL_DISK_PATHS` | `/` | comma list of mounts to watch |
| `SENTINEL_DISK_THRESHOLD` | `85` | disk alert threshold, percent |
| `SENTINEL_LOAD_FACTOR` | `2.0` | load alert at `cores × factor` (5-min avg) |
| `SENTINEL_FAILED_BURST` | `20` | failed auths per window before the 🚨 |
| `SENTINEL_FAILED_WINDOW` | `300` | burst window, seconds |
| `SENTINEL_CHECK_INTERVAL` | `30` | seconds between check passes |
| `SENTINEL_HEARTBEAT_HOUR` | `9` | daily heartbeat hour (UTC), `-1` disables |
| `SENTINEL_AUTH_LOG` | `/var/log/auth.log` | auth log to tail (rotation-aware) |
| `SENTINEL_STATE_FILE` | `/var/lib/sentinel/state.json` | offsets + alert flags |

## Security notes

- The bot **ignores every chat except `SENTINEL_CHAT_ID`** — commands from anyone else are dropped silently.
- Run it as a dedicated user in the `adm` group (read access to `auth.log`) — root is not needed.
- The systemd unit ships with `ProtectSystem=strict`, `PrivateTmp=true` and `NoNewPrivileges=true`.
- Alerts are one-shot with hysteresis / recovery notices, so a flapping service can't flood your chat.

## License

[MIT](LICENSE) — © Raed Ouiriemmi · [ouiriemmiraed.me](https://ouiriemmiraed.me)
