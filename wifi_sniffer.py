#!/usr/bin/env python3
"""
wifi_sniffer.py

Main program for the WiFi sniffer. Wires together:
  - network_db.NetworkDatabase   (AP/client tracking)
  - channel_hopper.ChannelHopper (background channel hopping)
  - packet_parsers               (802.11 frame parsing)

Usage (requires root + a monitor-mode interface):
  sudo python3 wifi_sniffer.py -i wlan0mon
  sudo python3 wifi_sniffer.py -i wlan0mon --no-hop --channels 6
  sudo python3 wifi_sniffer.py -i wlan0mon --json out.json --timeout 120
"""

import argparse
import json
import signal
import sys
import threading
import time

from scapy.all import Dot11, sniff

from channel_hopper import ChannelHopper
from network_db import NetworkDatabase
from packet_parsers import classify, extract_frame_info


class Sniffer:
    """Glue: Scapy capture -> packet_parsers -> NetworkDatabase -> UI."""

    def __init__(self, args):
        self.args = args
        self.db = NetworkDatabase(stale_after=args.stale)
        self.hopper = None
        self.stop_event = threading.Event()
        self.eapol_count = 0
        self.deauth_count = 0
        self.packet_count = 0

    # ------------------------------------------------------------ capture

    def process_packet(self, packet) -> None:
        """Scapy prn callback: classify one packet and update the DB."""
        if self.stop_event.is_set():
            return
        self.packet_count += 1
        info = extract_frame_info(packet)
        if info is None:
            return

        kind = info["kind"]
        rssi = info["rssi"]
        freq = info["frequency"]
        channel = info["channel"]

        if kind in ("beacon", "probe_resp"):
            bssid = (info["addr2"] or "").lower()
            if not bssid:
                return
            enc = info["encryption"] or {}
            self.db.update_ap(
                bssid,
                ssid=info["ssid"],
                channel=channel,
                frequency=freq,
                encryption=enc.get("encryption"),
                cipher=enc.get("cipher"),
                auth=enc.get("auth"),
                signal=rssi,
                is_beacon=(kind == "beacon"),
            )

        elif kind == "probe_req":
            src = (info["addr2"] or "").lower()
            if src:
                self.db.update_client(src, signal=rssi, probe_ssid=info["ssid"] or "")

        elif kind in ("data", "eapol"):
            self._track_data(info, kind)
            if kind == "eapol":
                self.eapol_count += 1
                print(f"[+] EAPOL: {info['eapol']}")

        elif kind == "deauth":
            self.deauth_count += 1
            print(
                f"[!] DEAUTH  {info['addr2']} -> {info['addr1']}  "
                f"(reason {info['reason']})"
            )

    def _track_data(self, info: dict, kind: str) -> None:
        """Attribute data/EAPOL frames to the client and its AP."""
        addr1 = (info["addr1"] or "").lower()
        addr2 = (info["addr2"] or "").lower()
        addr3 = (info["addr3"] or "").lower()
        if not addr2:
            return

        ap = self.db.get_ap(addr3) or self.db.get_ap(addr1)
        client_bssid = ap.bssid if ap else None

        # to-DS (STA->AP): addr1 is the AP. from-DS: addr2 is the AP.
        to_ds = False
        fc = getattr(info, "get", None)
        if info["type"] == "data" and kind != "eapol":
            # We cannot see flags here; guess via db membership.
            to_ds = self.db.get_ap(addr1) is not None
        ap_mac = addr1 if to_ds else (addr3 or addr2)
        if self.db.get_ap(ap_mac):
            client_bssid = ap_mac

        self.db.update_client(addr2, bssid=client_bssid, signal=rssi := info["rssi"])
        if client_bssid:
            self.db.update_ap(
                client_bssid,
                channel=info["channel"],
                frequency=freq,
                signal=rssi,
                is_data=True,
            )

    # ------------------------------------------------------------ runtime

    def _display_loop(self) -> None:
        """Print a DB summary every `args.interval` seconds."""
        interval = max(2.0, self.args.interval)
        while not self.stop_event.wait(timeout=interval):
            hop = self.hopper.status() if self.hopper else "ch=fixed"
            print(
                f"\r--- pkts={self.packet_count} eapol={self.eapol_count} "
                f"deauth={self.deauth_count} {hop} ---"
            )
            self.db.prune()
            print(self.db.summary())

    def _start_hopper(self) -> None:
        if self.args.no_hop:
            if self.args.channels:
                from channel_hopper import set_channel
                set_channel(self.args.interface, self.args.channels[0])
            print(f"[*] Channel hopping disabled (fixed channel).")
            return
        self.hopper = ChannelHopper(
            self.args.interface,
            channels=self.args.channels,
            interval=self.args.hop_interval,
            include_6ghz=self.args.include_6ghz,
        )
        self.hopper.start()
        print("[*] Channel hopper started.")

    def _stop(self, *_args) -> None:
        if not self.stop_event.is_set():
            print("\n[*] Stopping...")
            self.stop_event.set()

    def run(self) -> None:
        signal.signal(signal.SIGINT, self._stop)
        self._start_hopper()
        disp = threading.Thread(target=self._display_loop, daemon=True)
        disp.start()

        print(f"[*] Sniffing on {self.args.interface} (Ctrl-C to stop)...")
        try:
            sniff(
                iface=self.args.interface,
                prn=self.process_packet,
                store=False,
                stop_filter=lambda _p: self.stop_event.is_set(),
                timeout=self.args.timeout,
            )
        except OSError as exc:
            print(f"[!] Capture error: {exc}", file=sys.stderr)
        finally:
            self._stop()
            if self.hopper:
                self.hopper.stop()
            if self.args.json:
                with open(self.args.json, "w") as fh:
                    fh.write(self.db.to_json())
                print(f"[*] Wrote {self.args.json}")
            print(self.db.summary())
            print(
                f"[*] Done. packets={self.packet_count} "
                f"eapol={self.eapol_count} deauth={self.deauth_count}"
            )


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="WiFi sniffer (AP/client tracker)")
    p.add_argument("-i", "--interface", required=True,
                   help="monitor-mode interface (e.g. wlan0mon)")
    p.add_argument("--no-hop", action="store_true",
                   help="do not hop channels")
    p.add_argument("--channels", type=int, nargs="+", default=None,
                   help="explicit channel list to hop through")
    p.add_argument("--include-6ghz", action="store_true",
                   help="include 6 GHz channels in the hop list")
    p.add_argument("--hop-interval", type=float, default=0.4,
                   help="seconds per channel (default 0.4)")
    p.add_argument("--interval", type=float, default=10.0,
                   help="display refresh seconds (default 10)")
    p.add_argument("--stale", type=float, default=300.0,
                   help="seconds before entries are pruned (default 300)")
    p.add_argument("--timeout", type=float, default=None,
                   help="stop sniffing after N seconds")
    p.add_argument("--json", metavar="FILE",
                   help="write the network database to FILE on exit")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    Sniffer(args).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
