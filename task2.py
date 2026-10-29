#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
task2.py - Student template for Task 2: defended local TCP server.

Student name: _______________
Student ID  : _______________

Goal:
  Implement a defended version of the baseline server using:
    1. SYN-cookie-style stateless validation idea
    2. Per-IP rate limiting
    3. Larger backlog / worker capacity
    4. Shorter timeout for silent connections

Run order:
  Terminal 1:
      python task2.py --run-duration 40 --log-file task2_events.log

  Terminal 2:
      python task1.py

Important:
  This file is the Task 2 defended server. The baseline server is server.py.

Safety:
  This server binds only to localhost by default.
"""

from __future__ import annotations

import argparse
import codecs
import hashlib
import hmac
import os
import secrets
import socket
import sys
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass

if sys.platform == "win32":
    sys.stdout = codecs.getwriter("utf-8")(sys.stdout.buffer, "strict")
    os.system("chcp 65001 > nul")

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}


@dataclass(frozen=True)
class DefenseConfig:
    host: str
    port: int
    backlog: int
    timeout: float
    workers: int
    run_duration: float
    monitor_interval: float
    log_file: str
    enable_syn_cookies: bool
    enable_rate_limit: bool
    max_syn_per_ip: int
    rate_window: float


stats_lock = threading.Lock()
log_lock = threading.Lock()
rate_lock = threading.Lock()
stop_event = threading.Event()
health_history = deque(maxlen=50)
ip_syn_tracker = defaultdict(lambda: {"count": 0, "window_start": time.time()})
log_file_handle = None
start_time = time.time()
last_attack_time = 0.0
was_under_attack = False
SYN_COOKIE_SECRET = secrets.token_bytes(32)

stats = {
    "syn_seen": 0,
    "ack_seen": 0,
    "accepted": 0,
    "handled": 0,
    "rejected": 0,
    "active": 0,
    "syn_cookies_used": 0,
    "rate_limited": 0,
    "last_activity": time.time(),
}

ATTACK_REJECT_RATE = 0.60
DEGRADED_RATE = 0.30
ATTACK_COOLDOWN = 10.0
IDLE_THRESHOLD = 6.0
MIN_TRAFFIC = 3


def addr_text(addr: tuple[str, int]) -> str:
    return f"{addr[0]}:{addr[1]}"


def reset_state() -> None:
    """Reset runtime state before starting the defended server."""
    global start_time, last_attack_time, was_under_attack, log_file_handle
    stop_event.clear()
    start_time = time.time()
    last_attack_time = 0.0
    was_under_attack = False
    log_file_handle = None
    health_history.clear()
    ip_syn_tracker.clear()
    with stats_lock:
        stats.update({
            "syn_seen": 0,
            "ack_seen": 0,
            "accepted": 0,
            "handled": 0,
            "rejected": 0,
            "active": 0,
            "syn_cookies_used": 0,
            "rate_limited": 0,
            "last_activity": time.time(),
        })


def log_event(event_type: str, details: str = "") -> None:
    """Write one timestamped event to the CSV-style lab log."""
    if log_file_handle is None:
        return

    timestamp = time.time() - start_time
    line = f"{timestamp:.3f},{event_type.upper()},{details}\n"

    with log_lock:
        log_file_handle.write(line)
        log_file_handle.flush()


# ============================================================
# TODO 1: SYN Cookie generation
# ============================================================
def generate_syn_cookie(addr: tuple[str, int], timestamp: int | None = None) -> str:
    """
    Generate a simulated SYN Cookie for the client address.

    Suggested steps:
      1. If timestamp is None, set timestamp = int(time.time()).
      2. Extract ip and port from addr.
      3. Build data = f"{ip}:{port}:{timestamp}".encode("utf-8").
      4. Use hmac.new(SYN_COOKIE_SECRET, data, hashlib.sha256).
      5. Return the first 16 characters of the hexadecimal digest.
    """

    # TODO: Write your code here.
    raise NotImplementedError("TODO 1: complete generate_syn_cookie.")


# ============================================================
# TODO 2: SYN Cookie validation
# ============================================================
def validate_syn_cookie(addr: tuple[str, int], cookie: str, max_age_seconds: int = 2) -> bool:
    """
    Validate a simulated SYN Cookie for the client address.

    Suggested steps:
      1. now = int(time.time()).
      2. Check timestamps from now - max_age_seconds to now.
      3. For each timestamp, regenerate the expected cookie.
      4. Use hmac.compare_digest(expected, cookie).
      5. Return True if any expected value matches.
    """

    # TODO: Write your code here.
    raise NotImplementedError("TODO 2: complete validate_syn_cookie.")


# ============================================================
# TODO 3: Per-IP rate limiting
# ============================================================
def check_rate_limit(config: DefenseConfig, addr: tuple[str, int]) -> bool:
    """
    Return False when one IP exceeds the configured SYN rate.

    Suggested steps:
      1. If rate limiting is disabled, return True.
      2. Extract ip from addr.
      3. Use rate_lock to protect ip_syn_tracker.
      4. If the time window expired, reset count and window_start.
      5. If count >= max_syn_per_ip, increment stats["rate_limited"] and return False.
      6. Otherwise, increment count and return True.
    """

    # TODO: Write your code here.
    raise NotImplementedError("TODO 3: complete check_rate_limit.")


def calculate_health_status(delta_acc: int, delta_rej: int) -> tuple[str, str, str]:
    """Classify defended server health from recent accepted/rejected counts."""
    global last_attack_time, was_under_attack

    with stats_lock:
        active = stats["active"]
        last_activity = stats["last_activity"]

    current_total = delta_acc + delta_rej
    current_reject_rate = delta_rej / current_total if current_total else 0.0
    idle_time = time.time() - last_activity
    time_since_attack = time.time() - last_attack_time

    if current_total >= MIN_TRAFFIC and current_reject_rate > ATTACK_REJECT_RATE:
        last_attack_time = time.time()
        was_under_attack = True
        return "RED", "UNDER ATTACK", f"High rejection rate ({current_reject_rate * 100:.0f}%)"

    if was_under_attack and time_since_attack < ATTACK_COOLDOWN:
        if current_reject_rate > 0.0:
            return "YELLOW", "DEGRADED", f"Recovering with partial rejection ({current_reject_rate * 100:.0f}%)"
        return "ORANGE", "RECOVERING", f"Attack ended; cooldown {ATTACK_COOLDOWN - time_since_attack:.0f}s"

    if was_under_attack and time_since_attack >= ATTACK_COOLDOWN:
        was_under_attack = False

    if current_total >= MIN_TRAFFIC and current_reject_rate > DEGRADED_RATE:
        return "YELLOW", "DEGRADED", f"Moderate rejection ({current_reject_rate * 100:.0f}%)"
    if idle_time > IDLE_THRESHOLD:
        return "WHITE", "IDLE", f"No traffic for {idle_time:.0f}s"
    if active > 0 or current_total > 0:
        return "GREEN", "HEALTHY", "Defended operation"
    return "WHITE", "IDLE", "No activity"


def monitor(config: DefenseConfig) -> None:
    """Print defended server status every few seconds."""
    prev_acc = 0
    prev_rej = 0

    while not stop_event.is_set():
        time.sleep(config.monitor_interval)
        with stats_lock:
            snapshot = dict(stats)

        delta_acc = snapshot["accepted"] - prev_acc
        delta_rej = snapshot["rejected"] - prev_rej
        prev_acc = snapshot["accepted"]
        prev_rej = snapshot["rejected"]

        color, status, desc = calculate_health_status(delta_acc, delta_rej)
        health_history.append({
            "time": time.time(),
            "status": status,
            "delta_acc": delta_acc,
            "delta_rej": delta_rej,
            "reject_rate": delta_rej / (delta_acc + delta_rej) if (delta_acc + delta_rej) else 0.0,
        })

        print(
            f"[DEFENDED SERVER] "
            f"syn={snapshot['syn_seen']:4d} | ack={snapshot['ack_seen']:4d} | "
            f"acc={snapshot['accepted']:4d} | hdl={snapshot['handled']:4d} | "
            f"rej={snapshot['rejected']:4d} | act={snapshot['active']:2d} | "
            f"cookies={snapshot['syn_cookies_used']:4d} | rate_limited={snapshot['rate_limited']:4d} | "
            f"delta_acc={delta_acc:3d} delta_rej={delta_rej:3d} | "
            f"{color} {status:14s} | {desc}",
            flush=True,
        )


def handle_client(conn: socket.socket, addr: tuple[str, int], config: DefenseConfig) -> None:
    """Handle one accepted connection. ACK is logged only when data arrives."""
    try:
        conn.settimeout(config.timeout)
        data = conn.recv(1024)

        if data:
            log_event("ACK", addr_text(addr))
            with stats_lock:
                stats["ack_seen"] += 1
                stats["handled"] += 1
                stats["last_activity"] = time.time()
            conn.sendall(b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nOK\n")

    except (socket.timeout, ConnectionError, OSError):
        pass
    finally:
        try:
            conn.close()
        finally:
            with stats_lock:
                stats["active"] -= 1


def print_final_summary(config: DefenseConfig) -> None:
    """Print the final defended server report."""
    with stats_lock:
        snapshot = dict(stats)

    total = snapshot["accepted"] + snapshot["rejected"]
    rej_rate = snapshot["rejected"] / total * 100 if total else 0.0
    hdl_rate = snapshot["handled"] / snapshot["accepted"] * 100 if snapshot["accepted"] else 0.0

    counts = defaultdict(int)
    for item in health_history:
        counts[item["status"]] += 1

    print("\n" + "=" * 72, flush=True)
    print("TASK 2 DEFENDED SERVER — FINAL SUMMARY", flush=True)
    print("=" * 72, flush=True)
    print(f"  Host/port                 : {config.host}:{config.port}", flush=True)
    print(f"  Backlog / workers         : {config.backlog} / {config.workers}", flush=True)
    print(f"  Timeout                   : {config.timeout:.1f}s", flush=True)
    print(f"  SYN-like attempts logged  : {snapshot['syn_seen']}", flush=True)
    print(f"  ACK/data events logged    : {snapshot['ack_seen']}", flush=True)
    print(f"  Accepted                  : {snapshot['accepted']}", flush=True)
    print(f"  Rejected                  : {snapshot['rejected']} ({rej_rate:.1f}%)", flush=True)
    print(f"  Fully handled             : {snapshot['handled']} ({hdl_rate:.1f}% of accepted)", flush=True)
    print("-" * 72, flush=True)
    print("  Defense mechanisms", flush=True)
    print(f"  SYN cookies enabled       : {config.enable_syn_cookies}", flush=True)
    print(f"  SYN cookies generated     : {snapshot['syn_cookies_used']}", flush=True)
    print(f"  Rate limiting enabled     : {config.enable_rate_limit}", flush=True)
    print(f"  Rate-limited connections  : {snapshot['rate_limited']}", flush=True)
    print(f"  Max SYN/IP/window         : {config.max_syn_per_ip} per {config.rate_window:.1f}s", flush=True)
    print("-" * 72, flush=True)
    print("  Health periods", flush=True)
    print(f"  UNDER ATTACK              : {counts['UNDER ATTACK']}", flush=True)
    print(f"  DEGRADED                  : {counts['DEGRADED']}", flush=True)
    print(f"  RECOVERING                : {counts['RECOVERING']}", flush=True)
    print(f"  HEALTHY                   : {counts['HEALTHY']}", flush=True)
    print(f"  IDLE                      : {counts['IDLE']}", flush=True)
    print(f"  Event log                 : {config.log_file}", flush=True)
    print("=" * 72, flush=True)


def open_log_file(path: str):
    handle = open(path, "w", encoding="utf-8", newline="")
    handle.write("# Defended local SYN-flood-style lab event log\n")
    handle.write("# Format: timestamp,event_type,details\n")
    handle.flush()
    return handle


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Defended local TCP server for Task 2")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--run-duration", type=float, default=40.0, help="seconds; 0 means until Ctrl+C")
    parser.add_argument("--monitor-interval", type=float, default=2.0)
    parser.add_argument("--log-file", default="task2_events.log")
    parser.add_argument("--backlog", type=int, default=100)
    parser.add_argument("--timeout", type=float, default=0.5)
    parser.add_argument("--workers", type=int, default=30)
    parser.add_argument("--max-syn-per-ip", type=int, default=100)
    parser.add_argument("--rate-window", type=float, default=1.0)
    parser.add_argument("--disable-rate-limit", action="store_true")
    parser.add_argument("--disable-syn-cookies", action="store_true")
    return parser.parse_args(argv)


def build_config(args: argparse.Namespace) -> DefenseConfig:
    if args.host not in LOCAL_HOSTS:
        raise SystemExit("This lab server must bind only to localhost / 127.0.0.1.")

    return DefenseConfig(
        host=args.host,
        port=args.port,
        backlog=args.backlog,
        timeout=args.timeout,
        workers=args.workers,
        run_duration=args.run_duration,
        monitor_interval=args.monitor_interval,
        log_file=args.log_file,
        enable_syn_cookies=not args.disable_syn_cookies,
        enable_rate_limit=not args.disable_rate_limit,
        max_syn_per_ip=args.max_syn_per_ip,
        rate_window=args.rate_window,
    )


def run_server(config: DefenseConfig) -> None:
    """Run the defended Task 2 server."""
    global log_file_handle, start_time

    reset_state()
    log_file_handle = open_log_file(config.log_file)
    start_time = time.time()

    print(f"[DEFENDED SERVER] Listening on {config.host}:{config.port}", flush=True)
    print(f"  backlog={config.backlog} | workers={config.workers} | timeout={config.timeout}s", flush=True)
    print(f"  log_file={config.log_file}", flush=True)
    print(
        f"  defenses: syn_cookies={config.enable_syn_cookies}, "
        f"rate_limit={config.enable_rate_limit} ({config.max_syn_per_ip}/{config.rate_window}s)",
        flush=True,
    )
    if config.run_duration > 0:
        print(f"  auto-stop after {config.run_duration:.0f}s\n", flush=True)
    else:
        print("  run_duration=0, press Ctrl+C to stop\n", flush=True)

    threading.Thread(target=monitor, args=(config,), daemon=True).start()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((config.host, config.port))
    srv.listen(config.backlog)
    srv.settimeout(1.0)

    if config.run_duration > 0:
        def auto_stop() -> None:
            time.sleep(config.run_duration)
            print(f"\n[SERVER] {config.run_duration:.0f}s elapsed -> stopping...", flush=True)
            stop_event.set()

        threading.Thread(target=auto_stop, daemon=True).start()

    try:
        while not stop_event.is_set():
            try:
                conn, addr = srv.accept()
                details = addr_text(addr)
                log_event("SYN", details)

                with stats_lock:
                    stats["syn_seen"] += 1
                    stats["last_activity"] = time.time()

                # ========================================================
                # TODO 4: Defense layer 1 - Rate limiting
                # ========================================================
                # If check_rate_limit(config, addr) returns False:
                #   1. Log a REJECTED event with reason=rate-limit.
                #   2. Increment stats["rejected"].
                #   3. Close the connection.
                #   4. Continue to the next accept loop iteration.
                # TODO: Write your code here.
                raise NotImplementedError("TODO 4: complete rate limiting in the accept loop.")

                # ========================================================
                # TODO 5: Defense layer 2 - SYN Cookie accounting
                # ========================================================
                # If SYN cookies are enabled:
                #   1. Generate a cookie for addr.
                #   2. Log a COOKIE event.
                #   3. Increment stats["syn_cookies_used"].
                # TODO: Write your code here.

                # ========================================================
                # TODO 6: Defense layer 3 - Worker capacity check
                # ========================================================
                # If stats["active"] >= config.workers:
                #   1. Increment stats["rejected"].
                #   2. Log a REJECTED event with reason=worker-capacity.
                #   3. Close the connection and continue.
                # Otherwise:
                #   1. Increment stats["accepted"].
                #   2. Increment stats["active"].
                #   3. Log an ACCEPTED event.
                #   4. Start a thread for handle_client.
                # TODO: Write your code here.

            except socket.timeout:
                continue
    except KeyboardInterrupt:
        print("\n[SERVER] Interrupted by user", flush=True)
        stop_event.set()
    finally:
        try:
            srv.close()
        finally:
            if log_file_handle is not None:
                log_file_handle.close()
        time.sleep(config.monitor_interval + 0.2)
        print_final_summary(config)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    config = build_config(args)
    run_server(config)


if __name__ == "__main__":
    main()
