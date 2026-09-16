# WiFi Sniffer

A monitor-mode WiFi network discovery and WPA handshake capture tool for Linux,
built on [Scapy](https://scapy.net/). It hops across channels to map nearby
access points and clients, tracks WPA 4-way handshakes as they happen, and can
live-verify a WPA/WPA2-PSK passphrase against a captured handshake by MIC
comparison.

> ⚠️ **Legal notice:** Only use this tool on networks you own or have explicit
> written permission to test. Unauthorized interception of wireless traffic is
> illegal in most jurisdictions.

---

## Features

- **Network discovery** — tracks APs (BSSID, SSID, channel, encryption, vendor,
  signal statistics) and clients across 2.4 GHz, 5 GHz and optionally 6 GHz
  (WiFi 6E) channels
- **Channel hopping** — background thread cycles the adapter through all
  standard channels; unsupported/DFS channels are skipped automatically
- **Encryption detection** — OPN / WEP / WPA1 / WPA2 / WPA3 / WPA2+WPA3 / OWE,
  with cipher and AKM (auth) extraction from RSN and vendor IEs
- **Hidden SSID detection** — flags beacons/probe responses with empty SSID IEs
- **Client tracking** — associates stations with APs from data traffic, and
  records probed SSIDs from probe requests
- **WPA handshake capture** — parses EAPOL-Key frames, classifies M1–M4,
  detects replays, and reports progress live (M1+M2 = crackable)
- **Live passphrase verification** — with `--decrypt SSID:passphrase`, derives
  the PMK/PTK and confirms or rejects the passphrase via the M2 MIC
- **JSON export** — writes the full network database to a file on exit
- **Self-test** — built-in crypto consistency checks, no capture needed

---

## Requirements

- **Linux** (Kali, Parrot, Ubuntu, etc.) with root access
- A WiFi adapter that supports **monitor mode** (e.g. Alfa AWUS036ACH,
  TP-Link TL-WN722N v1). Most built-in laptop cards have limited support.
- Python 3.8+
- Python packages: `scapy`
- System tools: `iw`, `aircrack-ng` (for `airmon-ng`)

---

## Installation

Run the one-shot installer:

