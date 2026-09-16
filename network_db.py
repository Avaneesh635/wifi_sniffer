#!/usr/bin/env python3
"""
network_db.py

Thread-safe in-memory database that tracks the access points, clients
and WPA handshakes discovered while sniffing.

Part 1 of the wifi_sniffer upgrade:
  1. network_db.py      <- this file (AP/client/handshake tracking)
  2. channel_hopper.py  (background channel hopping thread)
  3. packet_parsers.py  (advanced 802.11 parsing)
  4. wifi_sniffer.py    (rewritten main program)
"""

import json
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


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


def _b2h(data) -> object:
    """Bytes -> hex string for JSON export (anything else passes through)."""
    if isinstance(data, (bytes, bytearray)):
        return bytes(data).hex()
    return data


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


@dataclass
class Handshake:
    """
    Captured EAPOL-Key messages (M1..M4) for one AP/client pair.

    'crackable' means M1+M2 are present: the ANonce (M1) plus SNonce and
    MIC (M2) are enough to verify a candidate PSK via MIC comparison.
    """

    bssid: str
    client: str
    messages: List[Dict] = field(default_factory=list)
    first_seen: float = field(default_factory=_now)
    last_seen: float = field(default_factory=_now)

    @property
    def messages_seen(self) -> Set[str]:
        return {m.get("key_msg") for m in self.messages} - {None}

    @property
    def complete(self) -> bool:
        """All four handshake messages captured."""
        return {"M1", "M2", "M3", "M4"} <= self.messages_seen

    @property
    def crackable(self) -> bool:
        """M1+M2 captured: enough to test a PSK against the M2 MIC."""
        return {"M1", "M2"} <= self.messages_seen

    def record(self, fields: Dict) -> bool:
        """
        Append one parsed EAPOL-Key message.
        Returns False (and changes nothing) for a replayed message.
        """
        for old in self.messages:
            if (old.get("replay_counter") == fields.get("replay_counter")
                    and old.get("key_msg") == fields.get("key_msg")):
                self.last_seen = _now()
                return False
        self.messages.append(fields)
        self.last_seen = _now()
        return True

    def to_dict(self) -> dict:
        return {
            "bssid": self.bssid,
            "client": self.client,
            "complete": self.complete,
            "crackable": self.crackable,
            "messages_seen": sorted(self.messages_seen),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "messages": [
                {k: _b2h(v) for k, v in msg.items()} for msg in self.messages
            ],
        }


class NetworkDatabase:
    """Thread-safe store of all APs, clients and handshakes seen."""

    def __init__(self, stale_after: float = 300.0):
        self._lock = threading.RLock()
        self._aps: Dict[str, AccessPoint] = {}
        self._clients: Dict[str, Client] = {}
        self._handshakes: Dict[str, Handshake] = {}
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

    # ----------------------------------------------------------- handshakes

    def record_eapol(
        self, bssid: Optional[str], client: Optional[str], fields: Dict
    ) -> Tuple[Handshake, bool]:
        """
        Store one parsed EAPOL-Key message (from packet_parsers
        eapol_key_fields()) for the given AP/client pair.
        Returns (handshake, added) where added is False for replays.
        """
        bssid = (bssid or "unknown").lower()
        client = (client or "unknown").lower()
        with self._lock:
            key = f"{bssid}|{client}"
            hs = self._handshakes.get(key)
            if hs is None:
                hs = Handshake(bssid=bssid, client=client)
                self._handshakes[key] = hs
            added = hs.record(fields)
            return hs, added

    def get_handshake(self, bssid: str, client: str) -> Optional[Handshake]:
        with self._lock:
            return self._handshakes.get(f"{bssid.lower()}|{client.lower()}")

    def handshakes(self) -> List[Handshake]:
        with self._lock:
            return sorted(self._handshakes.values(),
                          key=lambda h: h.last_seen, reverse=True)

    # -------------------------------------------------------------- utility

    def prune(self) -> None:
        """
        Drop AP/client entries that have not been seen for
        `stale_after` seconds. Captured handshakes are never pruned:
        they are small and valuable for later decryption.
        """
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
                "handshake_count": len(self._handshakes),
                "aps": [ap.to_dict() for ap in self.aps()],
                "handshakes": [hs.to_dict() for hs in self.handshakes()],
            }
        return json.dumps(payload, indent=indent)

    def summary(self) -> str:
        """Multi-line human readable summary of everything seen so far."""
        with self._lock:
            lines = [
                "",
                f"=== Networks seen: {len(self._aps)} | "
                f"Clients seen: {len(self._clients)} | "
                f"Handshakes: {len(self._handshakes)} ===",
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

            hss = self.handshakes()
            if hss:
                lines.append("--- WPA handshakes captured ---")
                for hs in hss:
                    if hs.complete:
                        state = "COMPLETE"
                    elif hs.crackable:
                        state = "M1+M2 (crackable)"
                    else:
                        state = "/".join(sorted(hs.messages_seen)) or "?"
                    lines.append(
                        f"{hs.bssid} <-> {hs.client}  {state}  "
                        f"({len(hs.messages)} msgs, last {_fmt_age(hs.last_seen)} ago)"
                    )
            return "\n".join(lines)
