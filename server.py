#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
server.py - Baseline local TCP server for Task 1 and Task 3 logging.

Important:
  This file intentionally contains NO defensive mechanisms.
  It is the vulnerable baseline server used to demonstrate how a
  SYN-flood-style workload can exhaust the limited worker capacity.

Safety:
  The server binds to localhost by default. Keep this lab on 127.0.0.1.
"""

from __future__ import annotations

import argparse
import codecs
import os
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
class ServerConfig:
    host: str
    port: int
    backlog: int
    timeout: float
    workers: int
    run_duration: float
    monitor_interval: float
    log_file: str


stats_lock = threading.Lock()
log_lock = threading.Lock()
stop_event = threading.Event()
health_history = deque(maxlen=50)
log_file_handle = None
start_time = time.time()
last_attack_time = 0.0
was_under_attack = False

stats = {
    "syn_seen": 0,
    "ack_seen": 0,
    "accepted": 0,
    "handled": 0,
    "rejected": 0,
    "active": 0,
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
    """Reset runtime state before starting the server."""
    global start_time, last_attack_time, was_under_attack, log_file_handle
    stop_event.clear()
    start_time = time.time()
    last_attack_time = 0.0
    was_under_attack = False
    log_file_handle = None
    health_history.clear()
    with stats_lock:
        stats.update({
            "syn_seen": 0,
            "ack_seen": 0,
            "accepted": 0,
            "handled": 0,
            "rejected": 0,
            "active": 0,
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


def calculate_health_status(delta_acc: int, delta_rej: int) -> tuple[str, str, str]:
    """Classify baseline server health from recent accepted/rejected counts."""
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
        return "GREEN", "HEALTHY", "Normal baseline operation"
    return "WHITE", "IDLE", "No activity"


def monitor(config: ServerConfig) -> None:
    """Print baseline server status every few seconds."""
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
            f"[BASELINE SERVER] "
            f"syn={snapshot['syn_seen']:4d} | ack={snapshot['ack_seen']:4d} | "
            f"acc={snapshot['accepted']:4d} | hdl={snapshot['handled']:4d} | "
            f"rej={snapshot['rejected']:4d} | act={snapshot['active']:2d} | "
            f"delta_acc={delta_acc:3d} delta_rej={delta_rej:3d} | "
            f"{color} {status:14s} | {desc}",
            flush=True,
        )


def handle_client(conn: socket.socket, addr: tuple[str, int], config: ServerConfig) -> None:
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
        # Silent flood connections usually time out here.
        pass
    finally:
        try:
            conn.close()
        finally:
            with stats_lock:
                stats["active"] -= 1


def print_final_summary(config: ServerConfig) -> None:
    """Print the final baseline server report."""
    with stats_lock:
        snapshot = dict(stats)

    total = snapshot["accepted"] + snapshot["rejected"]
    rej_rate = snapshot["rejected"] / total * 100 if total else 0.0
    hdl_rate = snapshot["handled"] / snapshot["accepted"] * 100 if snapshot["accepted"] else 0.0

    counts = defaultdict(int)
    for item in health_history:
        counts[item["status"]] += 1

    print("\n" + "=" * 72, flush=True)
    print("TASK 1 BASELINE SERVER — FINAL SUMMARY", flush=True)
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
    handle.write("# Baseline local SYN-flood-style lab event log\n")
    handle.write("# Format: timestamp,event_type,details\n")
    handle.flush()
    return handle


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Baseline local TCP server for Task 1 and Task 3")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--run-duration", type=float, default=40.0, help="seconds; 0 means until Ctrl+C")
    parser.add_argument("--monitor-interval", type=float, default=2.0)
    parser.add_argument("--log-file", default="task1_events.log")
    parser.add_argument("--backlog", type=int, default=5)
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--workers", type=int, default=3)
    return parser.parse_args(argv)


def build_config(args: argparse.Namespace) -> ServerConfig:
    if args.host not in LOCAL_HOSTS:
        raise SystemExit("This lab server must bind only to localhost / 127.0.0.1.")

    return ServerConfig(
        host=args.host,
        port=args.port,
        backlog=args.backlog,
        timeout=args.timeout,
        workers=args.workers,
        run_duration=args.run_duration,
        monitor_interval=args.monitor_interval,
        log_file=args.log_file,
    )


def run_server(config: ServerConfig) -> None:
    """Run the baseline vulnerable server."""
    global log_file_handle, start_time

    reset_state()
    log_file_handle = open_log_file(config.log_file)
    start_time = time.time()

    print(f"[BASELINE SERVER] Listening on {config.host}:{config.port}", flush=True)
    print(f"  backlog={config.backlog} | workers={config.workers} | timeout={config.timeout}s", flush=True)
    print(f"  log_file={config.log_file}", flush=True)
    print("  defenses=disabled", flush=True)
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

                    if stats["active"] >= config.workers:
                        stats["rejected"] += 1
                        log_event("REJECTED", f"{details};reason=worker-capacity")
                        conn.close()
                        continue

                    stats["accepted"] += 1
                    stats["active"] += 1
                    log_event("ACCEPTED", details)

                threading.Thread(target=handle_client, args=(conn, addr, config), daemon=True).start()

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
