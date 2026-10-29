#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
task1.py - Student template for Task 1: local SYN-flood-style simulation.

Student name: _______________
Student ID  : _______________

Goal:
  Complete the client-side workload that sends many silent TCP connections
  to the vulnerable baseline server and also runs legitimate clients.

Run order:
  Terminal 1:
      python server.py --run-duration 40 --log-file task1_events.log

  Terminal 2:
      python task1.py

Safety:
  This template is restricted to localhost. Do not change it for public IPs.
"""

from __future__ import annotations

import socket
import sys
import threading
import time

# ============================================================
# TODO 1: Configure the local simulation parameters
# ============================================================
TARGET_HOST = "127.0.0.1"
TARGET_PORT = 8080
ATTACK_THREADS = None      # Example after completion: 25
ATTACK_DURATION = None     # Example after completion: 25
HOLD_TIME = None           # Example after completion: 10
LEGIT_CLIENTS = None       # Example after completion: 8
LEGIT_DELAY = 1.0          # Delay between legitimate client attempts

# ============================================================
# Shared runtime state
# ============================================================
open_sockets: list[socket.socket] = []
stop_flag = threading.Event()
lock = threading.Lock()

metrics = {
    "connections_attempted": 0,
    "connections_held": 0,
    "connections_failed": 0,
    "legit_success": 0,
    "legit_failed": 0,
}


def ensure_local_target() -> None:
    """Prevent accidental use outside the local lab environment."""
    if TARGET_HOST not in {"127.0.0.1", "localhost", "::1"}:
        raise SystemExit("This lab must target only localhost / 127.0.0.1.")


def require_config() -> None:
    """Stop execution until the student fills the configuration values."""
    missing = []
    for name in ["ATTACK_THREADS", "ATTACK_DURATION", "HOLD_TIME", "LEGIT_CLIENTS"]:
        if globals()[name] is None:
            missing.append(name)

    if missing:
        print("Please complete TODO 1 before running this file.", file=sys.stderr)
        print("Missing values: " + ", ".join(missing), file=sys.stderr)
        sys.exit(1)


def update_metric(name: str, amount: int = 1) -> None:
    """Thread-safe metric update helper."""
    with lock:
        metrics[name] += amount


# ============================================================
# TODO 2: Flood worker
# ============================================================
def flood_worker(worker_id: int) -> None:
    """
    Create repeated TCP connections and keep them open silently.

    Required behavior:
      1. Run until stop_flag is set.
      2. Create a TCP socket.
      3. Set a short timeout.
      4. Connect to TARGET_HOST:TARGET_PORT.
      5. Store the socket in open_sockets.
      6. Increment connections_attempted and connections_held.
      7. Keep the connection open for HOLD_TIME seconds without sending data.
      8. On errors, increment connections_failed.

    Hint:
      Use socket.AF_INET and socket.SOCK_STREAM.
    """

    # TODO: Write your code here.
    raise NotImplementedError("TODO 2: complete flood_worker.")


# ============================================================
# TODO 3: Legitimate client
# ============================================================
def legitimate_client(client_id: int) -> None:
    """
    Simulate a normal client that completes the application-level request.

    Required behavior:
      1. Create a TCP socket.
      2. Connect to the server.
      3. Send a simple HTTP request.
      4. Wait for a response.
      5. If a response is received, increment legit_success.
      6. If an error or timeout occurs, increment legit_failed.
      7. Close the socket at the end.

    Hint:
      request = b"GET / HTTP/1.0\r\n\r\n"
      response = s.recv(1024)
    """

    # TODO: Write your code here.
    raise NotImplementedError("TODO 3: complete legitimate_client.")


# ============================================================
# TODO 4: Final metrics
# ============================================================
def print_metrics() -> None:
    """
    Print the final Task 1 metrics.

    Required output items:
      - Number of attempted connections
      - Number of held connections
      - Number of failed connections
      - Number of successful legitimate clients
      - Number of failed legitimate clients
      - Success rate of legitimate clients
    """

    # TODO: Write your code here.
    raise NotImplementedError("TODO 4: complete print_metrics.")


# ============================================================
# TODO 5: Close open sockets
# ============================================================
def close_open_sockets() -> None:
    """
    Close all open sockets at the end of the simulation.

    Hint:
      - Use lock.
      - Iterate over open_sockets.
      - For each socket, call close inside try/except.
      - Clear the list at the end.
    """

    # TODO: Write your code here.
    raise NotImplementedError("TODO 5: complete close_open_sockets.")


def main() -> None:
    ensure_local_target()
    require_config()

    print("=" * 70, flush=True)
    print("TASK 1 — LOCAL SYN-FLOOD-STYLE SIMULATION", flush=True)
    print("=" * 70, flush=True)
    print(f"Target          : {TARGET_HOST}:{TARGET_PORT}", flush=True)
    print(f"Attack threads  : {ATTACK_THREADS}", flush=True)
    print(f"Attack duration : {ATTACK_DURATION}s", flush=True)
    print(f"Hold time       : {HOLD_TIME}s", flush=True)
    print(f"Legit clients   : {LEGIT_CLIENTS}", flush=True)
    print("=" * 70, flush=True)

    # TODO 6a: Create and start flood_worker threads.
    attack_threads: list[threading.Thread] = []
    # TODO: Write your code here.

    # TODO 6b: Start legitimate clients while the flood is active.
    legit_threads: list[threading.Thread] = []
    # TODO: Write your code here.

    time.sleep(ATTACK_DURATION)
    stop_flag.set()

    # TODO 6c: Close open connections and collect threads.
    close_open_sockets()

    for t in attack_threads + legit_threads:
        t.join(timeout=1.0)

    print_metrics()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        stop_flag.set()
        print("\nInterrupted by user", file=sys.stderr)
