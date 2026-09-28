# Packet Sniffer UI (MVP)

A beginner cybersecurity desktop project built with **Python + Scapy + PySide6** to capture and view live network packets in a GUI.


## What this project does
- Captures live packets from a selected network interface
- Displays packet info in a table:
  - Time
  - Source IP / Destination IP
  - Protocol
  - Source Port / Destination Port
  - Packet Length
- Supports optional BPF filter input (examples: `tcp`, `udp`, `port 53`)

## Tech stack
- Python 3
- Scapy
- PySide6

## Project structure
- `src/app.py` — GUI + sniffer start/stop logic
- `src/core/parser.py` — packet parsing (`packet_to_row`)

## Setup and run (Linux)
1. Create and activate virtual environment
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```
2. Install dependencies
   ```bash
   pip install -U scapy PySide6
   ```
3. Run app (sudo required for packet capture)
   ```bash
   sudo .venv/bin/python src/app.py
   ```

## How to test quickly
- Open the app
- Select active interface (`eth0` / `wlan0`)
- Click **Start**
- Generate traffic in another terminal:
  ```bash
  ping -c 5 8.8.8.8
  ```

## Current limitations
- Requires root/sudo on Linux (raw socket access)
- Basic table view only (no deep packet details yet)
- No export (CSV/PCAP) yet
- Limited error dialogs/logging
- Unit tests not complete

## Roadmap
- Better filters UI + validation
- Packet counters/statistics
- Export to CSV/PCAP
- Improved logging and error handling
- Unit tests for parser/sniffer components

## Learning notes
Main challenges solved:
- Raw socket permission issues (`PermissionError`)
- Python import/package path conflicts (`core/` vs `src/core/`)
- Wiring async packet capture into GUI updates safely