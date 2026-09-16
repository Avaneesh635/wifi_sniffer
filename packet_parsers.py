#!/usr/bin/env python3
"""
packet_parsers.py

Advanced 802.11 frame parsing for the WiFi sniffer.

Part 3 of the wifi_sniffer upgrade:
  1. network_db.py      (AP/client tracking)
  2. channel_hopper.py  (background channel hopping)
  3. packet_parsers.py  <- this file (deep frame parsing)
  4. wifi_sniffer.py    (rewritten main program)

Handles:
  - Encryption detection: OPN / WEP / WPA1 / WPA2 / WPA3 / WPA2+WPA3 / OWE
  - Cipher and AKM (auth) extraction from RSN and vendor IEs
  - Hidden SSID detection (beacons/probe responses with empty SSID IE)
  - EAPOL (4-way handshake) frame detection AND full EAPOL-Key parsing
    (M1..M4 classification, nonces, MIC, replay counter, raw bytes) so
    network_db can track handshakes for later decryption
  - Deauth / auth / association frame classification
  - RSSI and frequency extraction from RadioTap
"""

from typing import Dict, Iterator, Optional

from scapy.all import (
    Dot11,
    Dot11AssoReq,
    Dot11Auth,
    Dot11Beacon,
    Dot11Deauth,
    Dot11Elt,
    Dot11ProbeReq,
    Dot11ProbeResp,
    Dot11ReassoReq,
    EAPOL,
    RadioTap,
)

from wpa_decrypt import parse_eapol_key_bytes

FRAME_TYPES = {0: "mgmt", 1: "ctrl", 2: "data"}

# RSN group cipher suite type byte -> name
GROUP_CIPHERS = {
    1: "WEP-40", 2: "TKIP", 4: "CCMP", 5: "WEP-104",
    6: "BIP", 7: "GCMP-128", 8: "GCMP-256", 9: "CCMP-256",
}

# RSN AKM suite type -> auth method
AKM_SUITES = {
    1: "802.1X", 2: "PSK", 3: "FT-802.1X", 4: "FT-PSK",
    5: "802.1X-SHA256", 6: "PSK-SHA256", 8: "SAE", 9: "FT-SAE",
    11: "SUITE-B", 12: "SUITE-B-192", 18: "OWE",
}

WPA_OUI = b"\x00\x50\xf2"  # Microsoft OUI (WPA1 vendor IE)


# --------------------------------------------------------------- IE walking

def iter_ies(packet) -> Iterator[Dot11Elt]:
    """Iterate over every Dot11Elt information element in the frame."""
    elt = packet.getlayer(Dot11Elt)
    while elt is not None and isinstance(elt, Dot11Elt):
        yield elt
        elt = elt.payload.getlayer(Dot11Elt)


def get_ssid(packet) -> Optional[str]:
    """
    SSID from the SSID IE (ID 0).
    Returns None when the AP hides its SSID (empty IE).
    """
    for elt in iter_ies(packet):
        if elt.ID == 0:
            if not elt.info:
                return None  # hidden SSID
            return elt.info.decode(errors="replace").strip("\x00")
    return None


def get_channel(packet) -> Optional[int]:
    """Channel from the DS parameter set IE (ID 3), if present."""
    for elt in iter_ies(packet):
        if elt.ID == 3 and len(elt.info) >= 1:
            return elt.info[0]
    return None


# ----------------------------------------------------------------- radio

def get_rssi(packet) -> Optional[int]:
    """RSSI in dBm from RadioTap, or None."""
    if not packet.haslayer(RadioTap):
        return None
    dbm = getattr(packet[RadioTap], "dBm_AntSignal", None)
    if dbm is None:
        return None
    if dbm > 128:  # some drivers report unsigned
        dbm -= 256
    return int(dbm)


def get_frequency(packet) -> Optional[int]:
    """Tuning frequency in MHz from RadioTap, or None."""
    if not packet.haslayer(RadioTap):
        return None
    freq = getattr(packet[RadioTap], "Channel", None)
    return int(freq) if freq else None


def frequency_to_channel(freq: Optional[int]) -> Optional[int]:
    """Best-effort channel number from a frequency in MHz."""
    if not freq:
        return None
    if 2412 <= freq <= 2484:
        return (freq - 2412) // 5 + 1 if freq < 2484 else 14
    if 5000 <= freq <= 5995:
        return (freq - 5000) // 5
    if 5955 <= freq <= 7115:  # 6 GHz
        return (freq - 5950) // 5
    return None


# ------------------------------------------------------------ encryption

def _parse_rsn(info: bytes) -> Dict[str, Optional[str]]:
    """
    Parse the payload of an RSN IE (ID 48).
    Returns {'encryption': ..., 'cipher': ..., 'auth': ...}.
    """
    result: Dict[str, Optional[str]] = {
        "encryption": "WPA2", "cipher": None, "auth": None,
    }
    try:
        if len(info) < 8:
            return result
        pairwise_count = int.from_bytes(info[6:8], "little")
        akm_off = 8 + 4 * pairwise_count
        if akm_off + 2 <= len(info):
            akm_count = int.from_bytes(info[akm_off:akm_off + 2], "little")
            akms = set()
            for i in range(min(akm_count, 8)):
                off = akm_off + 2 + 4 * i
                if off + 4 <= len(info):
                    akms.add(info[off + 3])
            if 8 in akms or 9 in akms:
                result["encryption"] = "WPA2/WPA3" if (2 in akms or 1 in akms) else "WPA3"
                result["auth"] = "SAE" if 8 in akms else "FT-SAE"
            elif 18 in akms:
                result["encryption"] = "OWE"
                result["auth"] = "OWE"
            elif akms:
                result["auth"] = AKM_SUITES.get(min(akms), "802.1X")
        result["cipher"] = GROUP_CIPHERS.get(info[3], f"suite {info[3]}")
    except (IndexError, ValueError):
        pass
    return result


def _has_wpa_ie(packet) -> bool:
    """True if a Microsoft WPA1 vendor IE (00:50:f2 type 1) is present."""
    for elt in iter_ies(packet):
        if elt.ID == 221 and elt.info[:4] == WPA_OUI + b"\x01":
            return True
    return False


def detect_encryption(packet) -> Dict[str, Optional[str]]:
    """
    Determine {'encryption', 'cipher', 'auth'} for a beacon/probe response.
    Order: RSN IE > WPA vendor IE > privacy bit (WEP) > open.
    """
    for elt in iter_ies(packet):
        if elt.ID == 48:
            return _parse_rsn(elt.info)

    dot11 = packet[Dot11]
    privacy = bool(getattr(dot11, "cap", 0) & 0x10)
    if _has_wpa_ie(packet):
        return {"encryption": "WPA1", "cipher": "TKIP", "auth": "PSK/802.1X"}
    if privacy:
        return {"encryption": "WEP", "cipher": "WEP", "auth": None}
    return {"encryption": "OPN", "cipher": None, "auth": None}


# ----------------------------------------------------------------- EAPOL

def eapol_info(packet) -> Optional[str]:
    """
    Returns a description when the frame carries EAPOL (handshake
    traffic), else None.
    """
    if not packet.haslayer(EAPOL):
        return None
    eapol = packet[EAPOL]
    label = "EAPOL-EAP" if eapol.type == 0 else "EAPOL-START" if eapol.type == 1 \
        else "EAPOL-LOGOFF" if eapol.type == 2 else "EAPOL-KEY" if eapol.type == 3 \
        else f"EAPOL-type-{eapol.type}"
    src = packet[Dot11].addr2 or "?"
    dst = packet[Dot11].addr1 or "?"
    return f"{label} ({src} -> {dst})"


def eapol_key_fields(packet) -> Optional[Dict]:
    """
    Fully parse an EAPOL-Key frame into a dict suitable for storage in
    network_db.Handshake.messages:
      key_msg         'M1'..'M4' classification
      key_nonce       ANonce (M1/M3) or SNonce (M2) -- 32 bytes
      key_mic         the MIC carried by the frame -- 16 bytes
      replay_counter  raw 8-byte replay counter
      key_version     descriptor version (1=MD5, 2=SHA1, 3=CMAC)
      eapol_raw       full raw EAPOL bytes (needed for MIC verification)
    Returns None when the frame is not an EAPOL-Key descriptor.
    """
    if not packet.haslayer(EAPOL):
        return None
    key = parse_eapol_key_bytes(bytes(packet[EAPOL]))
    if key is None:
        return None
    return {
        "key_msg": key.classify(),
        "key_nonce": key.nonce,
        "key_mic": key.key_mic,
        "replay_counter": key.replay_counter,
        "key_version": key.version,
        "eapol_raw": key.eapol_raw,
    }


# ------------------------------------------------------- frame classifier

def classify(packet) -> str:
    """Rough frame kind used to route processing in the main program."""
    if not packet.haslayer(Dot11):
        return "other"
    dot11 = packet[Dot11]
    if packet.haslayer(EAPOL):
        return "eapol"
    if packet.haslayer(Dot11Beacon):
        return "beacon"
    if packet.haslayer(Dot11ProbeResp):
        return "probe_resp"
    if packet.haslayer(Dot11ProbeReq):
        return "probe_req"
    if packet.haslayer(Dot11Deauth):
        return "deauth"
    if packet.haslayer(Dot11Auth):
        return "auth"
    if packet.haslayer(Dot11AssoReq) or packet.haslayer(Dot11ReassoReq):
        return "assoc"
    if dot11.type == 2:
        return "data"
    return "other"


def extract_frame_info(packet) -> Optional[Dict]:
    """
    Parse any packet into a plain dict for the sniffer main loop.
    Returns None for non-802.11 frames.
    """
    if not packet.haslayer(Dot11):
        return None

    dot11 = packet[Dot11]
    kind = classify(packet)
    rssi = get_rssi(packet)
    freq = get_frequency(packet)
    info: Dict = {
        "kind": kind,
        "rssi": rssi,
        "frequency": freq,
        "channel": get_channel(packet) or frequency_to_channel(freq),
        "addr1": dot11.addr1,
        "addr2": dot11.addr2,
        "addr3": dot11.addr3,
        "type": FRAME_TYPES.get(dot11.type, str(dot11.type)),
        "subtype": dot11.subtype,
        "ssid": None,
        "encryption": None,
        "eapol": None,
        "eapol_key": None,
        "reason": None,
    }

    if kind in ("beacon", "probe_resp"):
        info["ssid"] = get_ssid(packet)  # None => hidden SSID
        info["encryption"] = detect_encryption(packet)
    elif kind == "probe_req":
        info["ssid"] = get_ssid(packet) or ""
    elif kind == "deauth":
        deauth = packet[Dot11Deauth]
        info["reason"] = deauth.reason
    elif kind == "auth":
        auth = packet[Dot11Auth]
        info["alg"] = auth.algo  # 0=open, 1=shared key, 3=SAE
    elif kind == "eapol":
        info["eapol"] = eapol_info(packet)
        info["bssid"] = dot11.addr3
        info["eapol_key"] = eapol_key_fields(packet)

    return info
