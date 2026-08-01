#!/usr/bin/env python3
"""
vps-sentinel — a single-file, zero-dependency Telegram bot that watches
a Linux VPS and reports to a private chat.

What it watches
    • SSH logins            → instant alert with user, IP and auth method
    • failed-auth bursts    → warning when brute-force noise spikes
    • systemd services      → down + recovery notices for a configurable list
    • disk usage            → alert when a mount crosses the threshold
    • load average          → alert when 5-min load exceeds cores × factor
    • daily heartbeat       → one "all good" message so silence ≠ dead bot

Commands (only answered in the allow-listed chat)
    /status   uptime, load, memory, disk, service states
    /logins   most recent accepted SSH logins
    /help     command list

Configuration is environment-only (see .env.example). No secrets in code,
no third-party packages — pure standard library.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

# --------------------------------------------------------------------------
# Configuration (environment only)
# --------------------------------------------------------------------------

BOT_TOKEN = os.environ.get("SENTINEL_BOT_TOKEN", "")
CHAT_ID = os.environ.get("SENTINEL_CHAT_ID", "")

SERVICES = [s.strip() for s in os.environ.get("SENTINEL_SERVICES", "").split(",") if s.strip()]
DISK_PATHS = [p.strip() for p in os.environ.get("SENTINEL_DISK_PATHS", "/").split(",") if p.strip()]
DISK_THRESHOLD = int(os.environ.get("SENTINEL_DISK_THRESHOLD", "85"))        # percent
LOAD_FACTOR = float(os.environ.get("SENTINEL_LOAD_FACTOR", "2.0"))           # × cpu cores
FAILED_BURST = int(os.environ.get("SENTINEL_FAILED_BURST", "20"))            # fails / window
FAILED_WINDOW = int(os.environ.get("SENTINEL_FAILED_WINDOW", "300"))         # seconds
CHECK_INTERVAL = int(os.environ.get("SENTINEL_CHECK_INTERVAL", "30"))        # seconds
HEARTBEAT_HOUR = int(os.environ.get("SENTINEL_HEARTBEAT_HOUR", "9"))         # 0-23 UTC, -1 off
AUTH_LOG = os.environ.get("SENTINEL_AUTH_LOG", "/var/log/auth.log")
STATE_FILE = os.environ.get("SENTINEL_STATE_FILE", "/var/lib/sentinel/state.json")

HOST = socket.gethostname()
API = f"https://api.telegram.org/bot{BOT_TOKEN}"

ACCEPTED_RE = re.compile(r"Accepted (\S+) for (\S+) from (\S+) port \d+")
FAILED_RE = re.compile(r"Failed password|Invalid user|authentication failure")

# --------------------------------------------------------------------------
# Small utilities
# --------------------------------------------------------------------------


def log(msg: str) -> None:
    print(f"[{datetime.now(timezone.utc).isoformat(timespec='seconds')}] {msg}", flush=True)


def load_state() -> dict:
    try:
        with open(STATE_FILE, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def save_state(state: dict) -> None:
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh)
    os.replace(tmp, STATE_FILE)


def run(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


# --------------------------------------------------------------------------
# Telegram (stdlib HTTP, long polling)
# --------------------------------------------------------------------------


def api_call(method: str, params: dict, timeout: int = 15) -> dict:
    data = urllib.parse.urlencode(params).encode()
    req = urllib.request.Request(f"{API}/{method}", data=data)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.load(resp)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        log(f"telegram {method} failed: {exc}")
        return {}


def send(text: str) -> None:
    api_call("sendMessage", {
        "chat_id": CHAT_ID,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": "true",
    })


def get_updates(offset: int) -> list[dict]:
    resp = api_call("getUpdates", {"offset": offset, "timeout": 25}, timeout=35)
    return resp.get("result", []) if resp.get("ok") else []


# --------------------------------------------------------------------------
# Checks
# --------------------------------------------------------------------------


def read_new_auth_lines(state: dict) -> list[str]:
    """Return auth-log lines appended since the last call (rotation-aware)."""
    try:
        st = os.stat(AUTH_LOG)
    except OSError:
        return []
    offset = state.get("auth_offset", 0)
    if state.get("auth_inode") != st.st_ino or offset > st.st_size:
        offset = 0  # rotated or truncated — start over
    with open(AUTH_LOG, errors="replace", encoding="utf-8") as fh:
        fh.seek(offset)
        lines = fh.readlines()
        state["auth_offset"] = fh.tell()
    state["auth_inode"] = st.st_ino
    return lines


def check_ssh(state: dict, quiet_first_pass: bool) -> None:
    lines = read_new_auth_lines(state)
    if quiet_first_pass:
        return  # don't replay history on first boot
    fails = state.setdefault("fail_times", [])
    now = time.time()
    for line in lines:
        m = ACCEPTED_RE.search(line)
        if m:
            method, user, ip = m.groups()
            state.setdefault("logins", []).append(
                {"t": now, "user": user, "ip": ip, "method": method})
            state["logins"] = state["logins"][-20:]
            send(f"🔐 <b>SSH login</b> on <b>{HOST}</b>\n"
                 f"user <code>{user}</code> from <code>{ip}</code> ({method})")
        elif FAILED_RE.search(line):
            fails.append(now)
    state["fail_times"] = [t for t in fails if now - t < FAILED_WINDOW]
    if len(state["fail_times"]) >= FAILED_BURST and not state.get("fail_alerted"):
        state["fail_alerted"] = True
        send(f"🚨 <b>Auth-failure burst</b> on <b>{HOST}</b>\n"
             f"{len(state['fail_times'])} failed attempts in {FAILED_WINDOW // 60} min "
             f"— check <code>fail2ban</code> / firewall.")
    elif not state["fail_times"]:
        state["fail_alerted"] = False


def check_services(state: dict) -> None:
    down = state.setdefault("services_down", {})
    for svc in SERVICES:
        active = run(["systemctl", "is-active", svc]) == "active"
        if not active and svc not in down:
            down[svc] = time.time()
            send(f"🔴 <b>{svc}</b> is DOWN on <b>{HOST}</b>")
        elif active and svc in down:
            mins = int((time.time() - down.pop(svc)) / 60)
            send(f"🟢 <b>{svc}</b> recovered on <b>{HOST}</b> (down ~{mins} min)")


def check_disk(state: dict) -> None:
    alerted = state.setdefault("disk_alerted", {})
    for path in DISK_PATHS:
        try:
            usage = shutil.disk_usage(path)
        except OSError:
            continue
        pct = round(usage.used / usage.total * 100)
        if pct >= DISK_THRESHOLD and not alerted.get(path):
            alerted[path] = True
            free_gb = usage.free / 1e9
            send(f"💾 <b>Disk {pct}% full</b> on <b>{HOST}</b> at <code>{path}</code> "
                 f"({free_gb:.1f} GB free)")
        elif pct < DISK_THRESHOLD - 5:
            alerted[path] = False  # re-arm with hysteresis


def check_load(state: dict) -> None:
    cores = os.cpu_count() or 1
    load5 = os.getloadavg()[1]
    if load5 > cores * LOAD_FACTOR and not state.get("load_alerted"):
        state["load_alerted"] = True
        send(f"📈 <b>High load</b> on <b>{HOST}</b>: {load5:.1f} "
             f"(5-min avg, {cores} cores)")
    elif load5 < cores * LOAD_FACTOR * 0.7:
        state["load_alerted"] = False


def heartbeat(state: dict) -> None:
    if HEARTBEAT_HOUR < 0:
        return
    now = datetime.now(timezone.utc)
    today = now.strftime("%Y-%m-%d")
    if now.hour == HEARTBEAT_HOUR and state.get("heartbeat_day") != today:
        state["heartbeat_day"] = today
        send(f"💚 <b>{HOST}</b> heartbeat — all quiet.\n{status_text()}")


# --------------------------------------------------------------------------
# Command handlers
# --------------------------------------------------------------------------


def human_uptime() -> str:
    try:
        with open("/proc/uptime") as fh:
            secs = int(float(fh.read().split()[0]))
        days, rem = divmod(secs, 86400)
        hours, rem = divmod(rem, 3600)
        return f"{days}d {hours}h {rem // 60}m"
    except OSError:
        return "?"


def mem_line() -> str:
    try:
        info = {}
        with open("/proc/meminfo") as fh:
            for row in fh:
                key, val = row.split(":", 1)
                info[key] = int(val.split()[0])
        used = info["MemTotal"] - info["MemAvailable"]
        return f"{used / 1048576:.1f} / {info['MemTotal'] / 1048576:.1f} GB"
    except (OSError, KeyError):
        return "?"


def status_text() -> str:
    lines = [
        f"⏱ uptime <b>{human_uptime()}</b>",
        f"📊 load <b>{' / '.join(f'{v:.2f}' for v in os.getloadavg())}</b> ({os.cpu_count()} cores)",
        f"🧠 mem <b>{mem_line()}</b>",
    ]
    for path in DISK_PATHS:
        try:
            usage = shutil.disk_usage(path)
            lines.append(f"💾 <code>{path}</code> <b>{round(usage.used / usage.total * 100)}%</b> "
                         f"({usage.free / 1e9:.1f} GB free)")
        except OSError:
            pass
    for svc in SERVICES:
        ok = run(["systemctl", "is-active", svc]) == "active"
        lines.append(f"{'🟢' if ok else '🔴'} {svc}")
    return "\n".join(lines)


def logins_text(state: dict) -> str:
    entries = state.get("logins", [])
    if not entries:
        return "No SSH logins recorded since the sentinel started."
    rows = []
    for e in reversed(entries[-10:]):
        when = datetime.fromtimestamp(e["t"], timezone.utc).strftime("%m-%d %H:%M")
        rows.append(f"<code>{when}</code> {e['user']} ← <code>{e['ip']}</code>")
    return "🔐 <b>Recent SSH logins</b> (UTC)\n" + "\n".join(rows)


HELP = (
    f"🛰 <b>vps-sentinel</b> on <b>{HOST}</b>\n"
    "/status — uptime, load, memory, disk, services\n"
    "/logins — recent accepted SSH logins\n"
    "/help — this message"
)


def handle_command(text: str, state: dict) -> None:
    cmd = text.split("@")[0].strip().lower()
    if cmd == "/status":
        send(f"🛰 <b>{HOST}</b>\n{status_text()}")
    elif cmd == "/logins":
        send(logins_text(state))
    elif cmd in ("/help", "/start"):
        send(HELP)


# --------------------------------------------------------------------------
# Main loop
# --------------------------------------------------------------------------


def main() -> int:
    if not BOT_TOKEN or not CHAT_ID:
        print("Set SENTINEL_BOT_TOKEN and SENTINEL_CHAT_ID (see .env.example).", file=sys.stderr)
        return 1

    state = load_state()
    running = True

    def stop(_sig, _frm):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    log(f"sentinel starting on {HOST} (services: {', '.join(SERVICES) or 'none'})")
    send(f"🛰 Sentinel online on <b>{HOST}</b>. /help for commands.")
    check_ssh(state, quiet_first_pass=True)  # swallow pre-boot history

    next_check = 0.0
    while running:
        for upd in get_updates(state.get("update_offset", 0)):
            state["update_offset"] = upd["update_id"] + 1
            msg = upd.get("message") or {}
            if str(msg.get("chat", {}).get("id")) == str(CHAT_ID):
                text = msg.get("text", "")
                if text.startswith("/"):
                    handle_command(text, state)
        if time.time() >= next_check:
            next_check = time.time() + CHECK_INTERVAL
            check_ssh(state, quiet_first_pass=False)
            check_services(state)
            check_disk(state)
            check_load(state)
            heartbeat(state)
            save_state(state)

    save_state(state)
    log("sentinel stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
