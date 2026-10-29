# syn-flood-simulation-and-detection
Python-based network security lab for simulating SYN-flood-style DoS attacks, evaluating server defenses, and detecting suspicious traffic through log analysis.  Copy description


**A Python network security lab for studying denial-of-service (DoS) behavior, server-side defenses, and traffic-based attack detection in a controlled localhost environment.**

> **Project status:** Educational assignment / starter implementation. The baseline server is provided and functional, but the uploaded Task 1, Task 2, and Task 3 scripts still contain `TODO` sections and `NotImplementedError` placeholders. Complete those sections before running the full experiment.

## Overview

This project explores how large numbers of idle TCP connections can exhaust a server's limited worker capacity, affect legitimate clients, and produce recognizable patterns in server logs. It compares an intentionally unprotected baseline server with a server designed to include defensive measures, then analyzes logged events to identify potential attack periods.

The assignment is divided into three tasks:

1. **Traffic simulation:** Generate many silent TCP connections alongside legitimate HTTP-like requests, and observe the effect on a baseline server.
2. **Defensive server:** Explore per-IP rate limiting, simulated SYN-cookie generation/validation, increased connection capacity, and shorter timeouts.
3. **Log-based detection:** Group connection events into time windows, calculate traffic metrics, and flag suspicious intervals.

### Important technical distinction

This is a **SYN-flood-style resource-exhaustion simulation**, **not a raw-packet TCP SYN flood**. The workload uses ordinary TCP sockets that complete the TCP handshake and then remain silent. In the server logs, `SYN` is recorded when a connection is accepted, and `ACK` is recorded when application data arrives; these are **lab-level event labels**, not captures of actual TCP SYN and ACK packets. Similarly, the proposed SYN cookies are an **application-level teaching model**, not operating-system TCP SYN cookies.

## Project structure

For a clean GitHub repository, rename the uploaded files as shown below:

```text
syn-flood-simulation-and-detection/
├── README.md
├── server.py             # Unprotected baseline TCP server
├── task1.py              # Silent-connection workload and legitimate clients (TODOs)
├── task2.py              # Defended TCP server (TODOs)
├── task3_detector.py     # Log-based attack detector (TODOs)
└── assignment.pdf        # Optional: original homework instructions
```

| Repository filename | Original uploaded filename | Purpose |
| --- | --- | --- |
| `server.py` | `server(7).py` | Baseline server with limited workers, monitoring, and event logging. |
| `task1.py` | `task1(20261029-212401).py` | Simulates silent and legitimate client connections; requires implementation. |
| `task2.py` | `task2(20261029-212401).py` | Separate server with planned defensive controls; requires implementation. |
| `task3_detector.py` | `task3_detector(20261029-212402).py` | Analyzes server event logs; requires implementation. |

## Requirements

- Python **3.10+**
- A computer that can run local TCP socket connections
- No third-party Python packages required (standard library only)

All experiments are intended to run on **`127.0.0.1` (localhost)** using port **`8080`**.

## Getting started

1. Place the Python files in the same directory and rename them to the clean filenames above.
2. Complete the missing `TODO` sections in `task1.py`, `task2.py`, and `task3_detector.py`.
3. Check that the target host and port in `task1.py` match the server configuration.
4. Use **two terminals** for each server/client test. Run only one server at a time, since both default to port `8080`.

### Task 1 — Baseline server and traffic simulation

Run the baseline server in **Terminal 1**:

```bash
python server.py --run-duration 40 --log-file task1_events.log
```

Run the client simulation in **Terminal 2**:

```bash
python task1.py
```

The client script is intended to open many silent TCP connections while also sending normal requests. The server records accepted and rejected connections, handled requests, and health-state changes.

The baseline server's default configuration includes **3 workers**, a **backlog of 5**, and an **8-second socket timeout**. These values can be changed with command-line options.

**Output:** `task1_events.log`, plus terminal statistics for the server and clients.

### Task 2 — Defended server

After completing the defensive logic, run the defended server in **Terminal 1**:

```bash
python task2.py --run-duration 40 --log-file task2_events.log
```

Run the **same** client workload in **Terminal 2**:

```bash
python task1.py
```

The defended server is designed to demonstrate:

- **Per-IP rate limiting** to restrict connection attempts within a time window.
- **Simulated SYN-cookie generation and validation** using an HMAC-based token.
- **More worker/backlog capacity** for concurrent requests.
- **Shorter socket timeouts** to release resources held by silent clients.

Its default settings include **30 workers**, a **backlog of 100**, a **0.5-second timeout**, and a rate-limit threshold of **100 connections per IP per second**. Optional command-line flags include `--disable-rate-limit` and `--disable-syn-cookies` for controlled comparisons.

**Output:** `task2_events.log`, plus terminal statistics for the defended server and clients.

### Task 3 — Detect suspicious periods from logs

Once the detector's `TODO` sections are complete, analyze the baseline server's log:

```bash
python task3_detector.py task1_events.log
```

You can also analyze the defended server's log:

```bash
python task3_detector.py task2_events.log
```

The detector is designed to group events into **1-second windows** and compute:

- The number of `SYN` and `ACK` lab events
- Accepted, rejected, and dropped connections
- The `SYN`-to-`ACK` event ratio
- The connection rejection rate
- Start times, end times, and durations of detected suspicious periods

The provided detection configuration flags a time window when it contains at least **5 SYN events** and either the **SYN/ACK ratio is at least 3**, or there are at least **3 drops** with a **rejection rate of at least 70%**. These are classroom thresholds, not production detection rules.

## Event log format

The servers generate simple, CSV-style text logs:

```text
# Format: timestamp,event_type,details
2.531,SYN,127.0.0.1:54321
2.600,ACK,127.0.0.1:54321
2.700,REJECTED,127.0.0.1:54322;reason=worker-capacity
```

The example is illustrative; actual values depend on the run. Timestamps are measured in seconds relative to server startup.

## Comparing the experiments

Use the **same client workload** in Tasks 1 and 2 so the results are reasonably comparable. Relevant metrics include:

| Metric | Why it matters |
| --- | --- |
| Accepted connections | Connections admitted by the server. |
| Rejected connections | Connections refused by the lab's server-side capacity or defense logic. |
| Handled requests | Connections that delivered application data and were processed. |
| Legitimate-client success rate | Percentage of normal clients that received a response. |
| Rejection rate | `rejected / (accepted + rejected)` when the denominator is nonzero. |
| SYN/ACK event ratio | Approximate imbalance between connection attempts and requests that sent data. |
| Health status | Server states such as `HEALTHY`, `DEGRADED`, `UNDER ATTACK`, and `RECOVERING`. |

The goal is to observe whether the defensive configuration improves handling of legitimate requests and controls resource pressure. **Results are not guaranteed**: rate limits may also reject legitimate clients, especially since all local clients share a source IP.

## Current implementation status

| Component | Status |
| --- | --- |
| Baseline TCP server and event logging | Provided / implemented |
| Silent-connection workload and legitimate clients | Incomplete — `TODO` placeholders |
| Defensive server logic | Incomplete — `TODO` placeholders |
| Log parsing, windowing, and attack detection | Incomplete — `TODO` placeholders |

This repository can be used as a starting point for implementing and documenting the assignment. Add actual experiment results and screenshots after completing and running the scripts.

## Safety and limitations

- **Use only on your own machine**, against `localhost` (`127.0.0.1`). Do not redirect the workload to third-party services or public hosts.
- The lab demonstrates TCP server capacity exhaustion, **not packet-level SYN spoofing**, actual half-open TCP handshakes, or production-grade SYN-cookie enforcement.
- Log-based attack detection is heuristic and may produce false positives or false negatives.
- The code and results are intended for **learning and controlled experiments**, not for protecting production systems.

## Topics

`python` · `network-security` · `denial-of-service` · `syn-flood` · `tcp` · `socket-programming` · `rate-limiting` · `intrusion-detection` · `log-analysis`
