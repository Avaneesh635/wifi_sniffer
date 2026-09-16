#!/usr/bin/env python3
"""
wifi_sniffer.py

Main program for the WiFi sniffer. Wires together:
  - network_db.NetworkDatabase   (AP/client/handshake tracking)
  - channel_hopper.ChannelHopper (background channel hopping)
  - packet_parsers               (802.11 frame parsing)
  - wpa_decrypt                  (PMK/PTK/MIC for live PSK verification)

Usage (requires root + a monitor-mode interface):
  sudo python3 wifi_sniffer.py -i wlan0mon
  sudo python3 wifi_sniffer.py -i wlan0mon --no-hop --channels 6
  sudo python3 wifi_sniffer.py -i wlan0mon --json out.json --timeout 120
  sudo python3 wifi_sniffer.py -i wlan0mon --decrypt 'MyHomeNet:s3cret!'

Captures WPA 4-way handshake messages (M1..M4) per AP/client pair and
reports progress live. With --decrypt SSID:passphrase, every captured
M1+M2 pair for that SSID is checked against the passphrase by MIC
comparison: correct passphrases are confirmed on the spot (works for
WPA/WPA2-PSK only; SAE/WPA3 and 802.1X cannot be verified this way).
"""

import argparse
import signal
import sys
import threading

from scapy.all import sniff

from channel_hopper import ChannelHopper
from network_db import NetworkDatabase
from packet_parsers import extract_frame_info
from wpa_decrypt import derive_pmk, derive_ptk, parse_eapol_key_bytes, verify_mic


def parse_decrypt_args(values):
    """
    Parse repeated --decrypt 'SSID:passphrase' options into {ssid: pass}.
    Splits on the FIRST colon, so the SSID may not contain a colon.
    """
    nets = {}
    for value in values or []:
        ssid, sep, passphrase = value.partition(":")
        if not sep or not ssid:
            raise SystemExit(f"--decrypt expects SSID:passphrase, got {value!r}")
        nets[ssid] = passphrase
    return nets


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
        self._handshake_alerted = set()  # (bssid, sta) pairs already announced

        # Live passphrase verification (--decrypt)
        self.decrypt_ssids = parse_decrypt_args(args.decrypt)  # ssid -> pass
        self._decrypt_pmks = {}   # ssid -> PMK bytes, derived lazily
        self._decrypt_done = {}   # (ap, sta) -> True (correct) / False (wrong)

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
            self._track_data(info)
            if kind == "eapol":
                self.eapol_count += 1
                if info["eapol_key"]:
                    self._record_handshake(info)
                elif info["eapol"]:
                    print(f"[+] EAPOL: {info['eapol']}")

        elif kind == "deauth":
            self.deauth_count += 1
            print(
                f"[!] DEAUTH  {info['addr2']} -> {info['addr1']}  "
                f"(reason {info['reason']})"
            )

    def _track_data(self, info: dict) -> None:
        """
        Attribute a data/EAPOL frame to its client and AP using the real
        to-DS / from-DS bits resolved by packet_parsers.endpoints_for_data().
        """
        ap_mac = (info["ap"] or "").lower() or None
        sta_mac = (info["sta"] or "").lower() or None
        if not sta_mac:
            return

        # Only link the client to an AP we have actually confirmed exists
        # (seen in a beacon / probe response); otherwise keep it standalone.
        known_ap = ap_mac if (ap_mac and self.db.get_ap(ap_mac)) else None

        self.db.update_client(sta_mac, bssid=known_ap, signal=info["rssi"])
        if known_ap:
            self.db.update_ap(
                known_ap,
                channel=info["channel"],
                frequency=info["frequency"],
                signal=info["rssi"],
                is_data=True,
            )

    def _record_handshake(self, info: dict) -> None:
        """File one EAPOL-Key message into the DB and report progress."""
        key_fields = info["eapol_key"]
        ap_mac = (info["ap"] or "unknown").lower()
        sta_mac = (info["sta"] or "unknown").lower()

        hs, added = self.db.record_eapol(ap_mac, sta_mac, key_fields)
        if not added:
            return  # replayed message: already stored, nothing to report

        msg = key_fields.get("key_msg") or "?"
        ap = self.db.get_ap(ap_mac)
        ssid = ""
        if ap and ap.ssid and ap.ssid != "<hidden>":
            ssid = f" '{ap.ssid}'"

        if hs.complete:
            if (ap_mac, sta_mac) not in self._handshake_alerted:
                self._handshake_alerted.add((ap_mac, sta_mac))
                print(
                    f"[+] FULL 4-WAY HANDSHAKE captured: "
                    f"{ap_mac} <-> {sta_mac}{ssid}"
                )
        elif hs.crackable:
            print(
                f"[+] Handshake {msg} captured: {ap_mac} <-> {sta_mac}{ssid} "
                f"-- M1+M2 present, crackable"
            )
        else:
            print(f"[+] Handshake {msg} captured: {ap_mac} <-> {sta_mac}{ssid}")

        if self.decrypt_ssids:
            self._try_verify(hs, ap_mac, sta_mac)

    # -------------------------------------------------- live verification

    def _pmk_for(self, ssid: str) -> bytes:
        """PMK for a watched SSID, derived once and cached."""
        pmk = self._decrypt_pmks.get(ssid)
        if pmk is None:
            print(f"[*] Deriving PMK for '{ssid}' (PBKDF2, 4096 rounds)...")
            pmk = derive_pmk(self.decrypt_ssids[ssid], ssid)
            self._decrypt_pmks[ssid] = pmk
        return pmk

    def _try_verify(self, hs, ap_mac: str, sta_mac: str) -> None:
        """
        If the handshake for this AP/client pair now contains both an
        ANonce (M1) and an M2 with a MIC, and we have a passphrase for
        its SSID, test the passphrase by MIC comparison -- once per pair.
        """
        if ap_mac == "unknown" or sta_mac == "unknown":
            return
        if self._decrypt_done.get((ap_mac, sta_mac)) is not None:
            return  # already verified / reported for this pair

        ap = self.db.get_ap(ap_mac)
        ssid = ap.ssid if ap else None
        if not ssid or ssid not in self.decrypt_ssids:
            return

        anonce = None   # from any M1
        msg2 = None     # first M2 carrying a MIC + raw EAPOL bytes
        for m in hs.messages:
            if m.get("key_msg") == "M1":
                anonce = m.get("key_nonce")
            if msg2 is None and m.get("key_msg") == "M2":
                msg2 = m
        if anonce is None or msg2 is None or not msg2.get("key_mic"):
            return  # not enough material yet; retried on the next message

        try:
            pmk = self._pmk_for(ssid)
            ptk = derive_ptk(
                pmk, ap_mac, sta_mac,
                anonce=anonce, snonce=msg2["key_nonce"],
            )
            eapol_key = parse_eapol_key_bytes(msg2["eapol_raw"])
            if eapol_key is not None and verify_mic(ptk, eapol_key):
                self._decrypt_done[(ap_mac, sta_mac)] = True
                print(
                    f"[+] PASSPHRASE CORRECT for '{ssid}': "
                    f"verified on {ap_mac} <-> {sta_mac}"
                )
            else:
                self._decrypt_done[(ap_mac, sta_mac)] = False
                print(
                    f"[-] M2 MIC mismatch for '{ssid}' "
                    f"({ap_mac} <-> {sta_mac}): passphrase appears WRONG"
                )
        except (ValueError, TypeError) as exc:
            print(f"[!] Passphrase check failed for '{ssid}': {exc}")

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
            print("[*] Channel hopping disabled (fixed channel).")
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
        if self.decrypt_ssids:
            print(f"[*] Will verify passphrases for: {', '.join(self.decrypt_ssids)}")
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
            self._decrypt_report()
            print(
                f"[*] Done. packets={self.packet_count} "
                f"eapol={self.eapol_count} deauth={self.deauth_count}"
            )

    def _decrypt_report(self) -> None:
        """Final verdict per watched SSID based on verification results."""
        if not self.decrypt_ssids:
            return
        for ssid in self.decrypt_ssids:
            results = [ok for (ap, sta), ok in self._decrypt_done.items() if ok]
            checked = self._decrypt_done
            watched = [k for k in checked if k[0] in self.db_summary_bssids(ssid)]
            correct = any(ok for (ap, sta), ok in checked.items() if ok)
            mismatch = any(not ok for (ap, sta), ok in checked.items() if not ok)
            del results, watched  # only the aggregate flags matter here
            if correct:
                print(f"[=] '{ssid}': passphrase CONFIRMED by captured handshake")
            elif mismatch:
                print(f"[=] '{ssid}': passphrase appears INCORRECT (MIC mismatch)")
            else:
                print(f"[=] '{ssid}': no matching M1+M2 captured -- inconclusive")

    def db_summary_bssids(self, ssid: str):
        """BSSIDs currently known for an SSID (empty set if unknown)."""
        return {ap.bssid for ap in self.db.aps() if ap.ssid == ssid}


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
    p.add_argument("--decrypt", metavar="SSID:PASSPHRASE", action="append",
                   default=None,
                   help="verify a WPA/WPA2-PSK passphrase live against "
                        "captured M1+M2 handshakes (repeatable; split on "
                        "the first colon)")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    Sniffer(args).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
