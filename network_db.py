#!/usr/bin/env python3
"""
network_db.py

Thread-safe in-memory database that tracks the access points and
clients discovered while sniffing.

Part 1 of the wifi_sniffer upgrade:
  1. network_db.py      <- this file (AP/client tracking)
  2. channel_hopper.py  (background channel hopping thread)
  3. packet_parsers.py  (advanced 802.11 parsing)
  4. wifi_sniffer.py    (rewritten main program)
"""

import json
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


def _now() -> float:
    return time.time()


def _fmt_age(ts: float) -> str:
    """Human readable 'seconds ago' string."""
    delta = int(max(0, _now() - ts))
    if delta < 60:
        return f"{delta}s"
    if delta < 3600:
        return f"{delta // 60}m{delta % 60:02d}s"
    return f"{delta // 3600}h{(delta % 3600) // 60:02d}m"


def vendor_for_mac(mac: str) -> str:
    """
    Best-effort vendor (OUI) lookup using scapy's manufacturer database.
    Returns '?' when the lookup is unavailable.
    """
    try:
        from scapy.all import conf  # imported lazily to avoid hard dependency

        db = getattr(conf, "manufdb", None)
        if db is None:
            return "?"
        try:
            manuf = db.lookup(mac)
            if isinstance(manuf, tuple):
                manuf = manuf[0]
            if manuf:
                return str(manuf)
        except Exception:
            pass
    except Exception:
        pass
    return "?"


@dataclass
class AccessPoint:
    """Everything we know about a single access point (BSSID)."""

    bssid: str
    ssid: str = "<hidden>"
    channel: Optional[int] = None
    frequency: Optional[int] = None
    encryption: str = "?"
    cipher: str = "?"
    auth: str = "?"
    vendor: str = "?"
    first_seen: float = field(default_factory=_now)
    last_seen: float = field(default_factory=_now)
    beacon_count: int = 0
    data_count: int = 0
    signal_min: Optional[int] = None
    signal_max: Optional[int] = None
    signal_sum: int = 0
    signal_count: int = 0
    clients: Dict[str, "Client"] = field(default_factory=dict)

    def update_signal(self, dbm: int) -> None:
        self.signal_min = dbm if self.signal_min is None else min(self.signal_min, dbm)
        self.signal_max = dbm if self.signal_max is None else max(self.signal_max, dbm)
        self.signal_sum += dbm
        self.signal_count += 1
        self.last_seen = _now()

    @property
    def signal_avg(self) -> Optional[int]:
        if self.signal_count:
            return round(self.signal_sum / self.signal_count)
        return None

    def to_dict(self) -> dict:
        return {
            "bssid": self.bssid,
            "ssid": self.ssid,
            "channel": self.channel,
            "frequency": self.frequency,
            "encryption": self.encryption,
            "cipher": self.cipher,
            "auth": self.auth,
            "vendor": self.vendor,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "beacon_count": self.beacon_count,
            "data_count": self.data_count,
            "signal": {
                "min": self.signal_min,
                "max": self.signal_max,
                "avg": self.signal_avg,
            },
            "clients": [c.to_dict() for c in self.clients.values()],
        }


@dataclass
class Client:
    """A wireless client (station) seen in the capture."""

    mac: str
    associated_bssid: Optional[str] = None
    first_seen: float = field(default_factory=_now)
    last_seen: float = field(default_factory=_now)
    packet_count: int = 0
    signal_min: Optional[int] = None
    signal_max: Optional[int] = None
    signal_sum: int = 0
    signal_count: int = 0
    probe_ssids: Set[str] = field(default_factory=set)

    @property
    def signal_avg(self) -> Optional[int]:
        if self.signal_count:
            return round(self.signal_sum / self.signal_count)
        return None

    def to_dict(self) -> dict:
        return {
            "mac": self.mac,
            "associated_bssid": self.associated_bssid,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "packet_count": self.packet_count,
            "signal": {
                "min": self.signal_min,
                "max": self.signal_max,
                "avg": self.signal_avg,
            },
            "probe_ssids": sorted(self.probe_ssids),
        }


class NetworkDatabase:
    """Thread-safe store of all APs and clients seen during a capture."""

    def __init__(self, stale_after: float = 300.0):
        self._lock = threading.RLock()
        self._aps: Dict[str, AccessPoint] = {}
        self._clients: Dict[str, Client] = {}
        self.stale_after = stale_after

    # ------------------------------------------------------------------ APs

    def update_ap(
        self,
        bssid: str,
        *,
        ssid: Optional[str] = None,
        channel: Optional[int] = None,
        frequency: Optional[int] = None,
        encryption: Optional[str] = None,
        cipher: Optional[str] = None,
        auth: Optional[str] = None,
        signal: Optional[int] = None,
        is_beacon: bool = False,
        is_data: bool = False,
    ) -> AccessPoint:
        """Create or update an AP record. Returns the record."""
        bssid = bssid.lower()
        with self._lock:
            ap = self._aps.get(bssid)
            if ap is None:
                ap = AccessPoint(bssid=bssid, vendor=vendor_for_mac(bssid))
                self._aps[bssid] = ap
            if ssid:
                ap.ssid = ssid
            if channel is not None:
                ap.channel = channel
            if frequency is not None:
                ap.frequency = frequency
            if encryption:
                ap.encryption = encryption
            if cipher:
                ap.cipher = cipher
            if auth:
                ap.auth = auth
            if is_beacon:
                ap.beacon_count += 1
            if is_data:
                ap.data_count += 1
            if signal is not None:
                ap.update_signal(signal)
            else:
                ap.last_seen = _now()
            return ap

    def get_ap(self, bssid: str) -> Optional[AccessPoint]:
        with self._lock:
            return self._aps.get(bssid.lower())

    def aps(self) -> List[AccessPoint]:
        with self._lock:
            return sorted(self._aps.values(), key=lambda a: a.last_seen, reverse=True)

    # -------------------------------------------------------------- clients

    def update_client(
        self,
        mac: str,
        *,
        bssid: Optional[str] = None,
        signal: Optional[int] = None,
        probe_ssid: Optional[str] = None,
    ) -> Client:
        """Create or update a client record. Returns the record."""
        mac = mac.lower()
        with self._lock:
            client = self._clients.get(mac)
            if client is None:
                client = Client(mac=mac)
                self._clients[mac] = client
            if bssid:
                client.associated_bssid = bssid.lower()
                ap = self._aps.get(bssid.lower())
                if ap is not None:
                    ap.clients[mac] = client
            if probe_ssid:
                client.probe_ssids.add(probe_ssid)
            client.packet_count += 1
            if signal is not None:
                client.signal_min = (
                    signal if client.signal_min is None else min(client.signal_min, signal)
                )
                client.signal_max = (
                    signal if client.signal_max is None else max(client.signal_max, signal)
                )
                client.signal_sum += signal
                client.signal_count += 1
            client.last_seen = _now()
            return client

    def get_client(self, mac: str) -> Optional[Client]:
        with self._lock:
            return self._clients.get(mac.lower())

    def clients(self) -> List[Client]:
        with self._lock:
            return sorted(self._clients.values(), key=lambda c: c.last_seen, reverse=True)

    # -------------------------------------------------------------- utility

    def prune(self) -> None:
        """Drop entries that have not been seen for `stale_after` seconds."""
        cutoff = _now() - self.stale_after
        with self._lock:
            for mac in [m for m, c in self._clients.items() if c.last_seen < cutoff]:
                del self._clients[mac]
            for bssid in [b for b, a in self._aps.items() if a.last_seen < cutoff]:
                del self._aps[bssid]

    def to_json(self, indent: int = 2) -> str:
        with self._lock:
            payload = {
                "generated": _now(),
                "ap_count": len(self._aps),
                "client_count": len(self._clients),
                "aps": [ap.to_dict() for ap in self.aps()],
            }
        return json.dumps(payload, indent=indent)

    def summary(self) -> str:
        """Multi-line human readable summary of everything seen so far."""
        with self._lock:
            lines = [
                "",
                f"=== Networks seen: {len(self._aps)} | "
                f"Clients seen: {len(self._clients)} ===",
            ]
            for ap in self.aps():
                sig = ap.signal_avg
                sig_s = f"{sig} dBm" if sig is not None else "n/a"
                lines.append(
                    f"{ap.bssid}  ch{str(ap.channel or '?'):>3}  {sig_s:>8}  "
                    f"{ap.encryption:<10} {ap.ssid}  "
                    f"({ap.beacon_count} beacons, {len(ap.clients)} clients, "
                    f"last seen {_fmt_age(ap.last_seen)} ago)"
                )
                for client in ap.clients.values():
                    lines.append(f"    -> client {client.mac}  pkts={client.packet_count}")

            probing = [c for c in self._clients.values() if c.probe_ssids]
            if probing:
                lines.append("--- Clients probing for networks ---")
                for client in probing:
                    ssids = ", ".join(sorted(client.probe_ssids)) or "<broadcast probe>"
                    lines.append(f"{client.mac}  probing for: {ssids}")
            return "\n".join(lines)
