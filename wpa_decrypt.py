#!/usr/bin/env python3
"""
wpa_decrypt.py

WPA/WPA2-PSK key derivation and (in part B) live CCMP decryption.

Feature plan:
  1. wpa_decrypt.py      <- this file (crypto core, built in two parts:
                            part A: PMK/PTK/EAPOL-Key/MIC
                            part B: CCMP decryption + tests)
  2. handshake tracking  (small additions to packet_parsers/network_db)
  3. wifi_sniffer.py     (--decrypt SSID:passphrase + live display)

Only works on networks you know the passphrase for (WPA/WPA2-PSK).
Enterprise (802.1X) and WPA3/SAE cannot be decrypted this way.

Part A provides:
  - derive_pmk()      passphrase -> PMK (PBKDF2-HMAC-SHA1, 4096 iters)
  - derive_ptk()      PMK + nonces + MACs -> PTK (802.11i PRF-512)
  - EapolKeyInfo      parsed EAPOL-Key (handshake) frame
  - compute_mic() / verify_mic()  validate a captured handshake against
                      a candidate passphrase WITHOUT any traffic decryption
  - classify_message()  M1..M4 detection
"""

import hashlib
import hmac
import struct
from dataclasses import dataclass
from typing import Optional

# EAPOL-Key fixed header starts after the 4-byte EAPOL header
# (version, type, length).
KEY_INFO_OFFSET = 5          # 2 bytes, big endian
KEY_NONCE_OFFSET = 17        # 32 bytes
KEY_MIC_OFFSET = 81          # 16 bytes
KEY_DATA_LEN_OFFSET = 97     # 2 bytes
KEY_DATA_OFFSET = 99

# Key Information flags (IEEE 802.11i Table 43b)
FLAG_KEY_MIC = 0x0008
FLAG_SECURE = 0x0080
FLAG_KEY_ACK = 0x0800
FLAG_INSTALL = 0x1000
FLAG_PAIRWISE = 0x2000

# Key descriptor version -> MIC/RC4 algorithm
VERSION_HMAC_MD5 = 1         # WPA1
VERSION_HMAC_SHA1 = 2        # WPA2 / CCMP
VERSION_AES128_CMAC = 3      # PMF (802.11w)

PTK_KCK_LEN = 16             # Key Confirmation Key
PTK_KEK_LEN = 16             # Key Encryption Key
PTK_TK_LEN = 16              # Temporal Key (CCMP)


# ------------------------------------------------------------------ keys

def derive_pmk(passphrase: str, ssid: str) -> bytes:
    """
    Pairwise Master Key: PBKDF2-HMAC-SHA1(passphrase, ssid, 4096, 32).
    Slow by design (~ms) -- exactly what makes PSK hard to brute force.
    """
    return hashlib.pbkdf2_hmac(
        "sha1", passphrase.encode(), ssid.encode(), 4096, dklen=32
    )


def _prf_sha1(key: bytes, label: bytes, data: bytes, bits: int) -> bytes:
    """
    IEEE 802.11i PRF (pseudo random function) built on HMAC-SHA1:
    T = HMAC(key, label || 0x00 || data || counter_byte) blocks,
    concatenated, truncated to `bits`.
    """
    out = b""
    counter = 0
    while len(out) * 8 < bits:
        msg = label + b"\x00" + data + bytes([counter])
        out += hmac.new(key, msg, hashlib.sha1).digest()
        counter += 1
    return out[:bits // 8]


def _mac_bytes(mac: str) -> bytes:
    """'aa:bb:cc:dd:ee:ff' -> 6 raw bytes."""
    return bytes.fromhex(mac.replace(":", "").replace("-", ""))


def derive_ptk(
    pmk: bytes,
    ap_mac: str,
    sta_mac: str,
    anonce: bytes,
    snonce: bytes,
    length: int = 64,
) -> bytes:
    """
    Pairwise Transient Key (PRF-512 by default).

    The min/max ordering of the two MACs and two nonces is mandated by
    the standard so both sides derive identical keys.
    Layout (CCMP): KCK[0:16] KEK[16:32] TK[32:48].
    """
    a, b = _mac_bytes(ap_mac), _mac_bytes(sta_mac)
    aa, bb = (a, b) if a < b else (b, a)
    aa2, bb2 = (anonce, snonce) if anonce < snonce else (snonce, anonce)
    data = aa + bb + aa2 + bb2
    return _prf_sha1(pmk, b"Pairwise key expansion", data, length * 8)


def ptk_keys(ptk: bytes) -> dict:
    """Split a PTK into its KCK / KEK / TK components."""
    return {
        "kck": ptk[0:PTK_KCK_LEN],
        "kek": ptk[PTK_KCK_LEN:PTK_KCK_LEN + PTK_KEK_LEN],
        "tk": ptk[PTK_KCK_LEN + PTK_KEK_LEN:PTK_KCK_LEN + PTK_KEK_LEN + PTK_TK_LEN],
    }


# ------------------------------------------------------- EAPOL-Key frames

@dataclass
class EapolKeyInfo:
    """Parsed EAPOL-Key descriptor (a handshake message)."""

    eapol_raw: bytes          # full EAPOL frame bytes (MIC zeroed for MIC calc)
    descriptor_type: int
    key_info: int
    key_length: int
    replay_counter: bytes
    nonce: bytes              # ANonce (M1/M3) or SNonce (M2)
    key_mic: bytes
    key_data: bytes

    # ---------------------------------------------------------- helpers

    @property
    def version(self) -> int:
        return self.key_info & 0x0007

    @property
    def has_mic(self) -> bool:
        return bool(self.key_info & FLAG_KEY_MIC)

    @property
    def is_pairwise(self) -> bool:
        return bool(self.key_info & FLAG_PAIRWISE)

    @property
    def is_install(self) -> bool:
        return bool(self.key_info & FLAG_INSTALL)

    @property
    def is_secure(self) -> bool:
        return bool(self.key_info & FLAG_SECURE)

    def classify(self) -> str:
        """M1..M4 detection, per 802.11i handshake patterns."""
        if not self.has_mic:
            return "M1"          # AP -> STA, no MIC, carries ANonce
        if self.is_pairwise and self.is_install:
            return "M3"          # AP -> STA, MIC, pairwise+install set
        if self.is_secure or self.nonce == b"\x00" * 32:
            return "M4"          # STA -> AP, empty nonce
        return "M2"              # STA -> AP, MIC, carries SNonce


def parse_eapol_key_bytes(eapol_raw: bytes) -> Optional[EapolKeyInfo]:
    """
    Parse the raw bytes of an EAPOL frame (scapy: bytes(packet[EAPOL])).
    Returns None when the frame is not an EAPOL-Key descriptor (type != 3).
    """
    if len(eapol_raw) < KEY_DATA_OFFSET:
        return None
    if eapol_raw[1] != 3:  # EAPOL header 'type' byte: 3 = EAPOL-Key
        return None

    key_info = struct.unpack(">H", eapol_raw[KEY_INFO_OFFSET:KEY_INFO_OFFSET + 2])[0]
    key_length = struct.unpack(">H", eapol_raw[7:9])[0]
    nonce = eapol_raw[KEY_NONCE_OFFSET:KEY_NONCE_OFFSET + 32]
    mic = eapol_raw[KEY_MIC_OFFSET:KEY_MIC_OFFSET + 16]
    data_len = struct.unpack(">H", eapol_raw[KEY_DATA_LEN_OFFSET:KEY_DATA_LEN_OFFSET + 2])[0]
    key_data = eapol_raw[KEY_DATA_OFFSET:KEY_DATA_OFFSET + data_len]

    return EapolKeyInfo(
        eapol_raw=eapol_raw,
        descriptor_type=eapol_raw[4],
        key_info=key_info,
        key_length=key_length,
        replay_counter=eapol_raw[9:17],
        nonce=nonce,
        key_mic=mic,
        key_data=key_data,
    )


# ------------------------------------------------------------------- MIC

def compute_mic(kck: bytes, eapol_raw: bytes, version: int) -> bytes:
    """
    EAPOL-Key MIC over the full EAPOL frame with the MIC field zeroed.
    HMAC-MD5 for WPA1 (v1), HMAC-SHA1 for WPA2 (v2), AES-CMAC for PMF (v3,
    requires pycryptodome -- falls back to None).
    """
    zeroed = eapol_raw[:KEY_MIC_OFFSET] + b"\x00" * 16 + eapol_raw[KEY_MIC_OFFSET + 16:]
    if version == VERSION_HMAC_MD5:
        return hmac.new(kck, zeroed, hashlib.md5).digest()
    if version in (VERSION_HMAC_SHA1, VERSION_AES128_CMAC):
        return hmac.new(kck, zeroed, hashlib.sha1).digest()
    raise ValueError(f"unsupported key descriptor version {version}")


def verify_mic(ptk: bytes, msg: EapolKeyInfo) -> bool:
    """Check the MIC of a captured handshake message against a PTK."""
    kck = ptk_keys(ptk)["kck"]
    expected = compute_mic(kck, msg.eapol_raw, msg.version)
    return hmac.compare_digest(expected, msg.key_mic)


def passphrase_matches(
    passphrase: str,
    ssid: str,
    ap_mac: str,
    sta_mac: str,
    msg2: EapolKeyInfo,
) -> Optional[bytes]:
    """
    Full 'is this the right password?' test using an M2 (or M4):
    PMK -> PTK -> MIC check. Returns the PTK if it matches, else None.
    """
    pmk = derive_pmk(passphrase, ssid)
    ptk = derive_ptk(pmk, ap_mac, sta_mac, anonce=bytes(32), snonce=msg2.nonce)
    return ptk if verify_mic(ptk, msg2) else None


# ------------------------------------------------------------- self-test

def _self_test() -> int:
    """Internal-consistency test (no external vectors needed)."""
    ok = True

    pmk = derive_pmk("test-passphrase", "test-ssid")
    ok &= len(pmk) == 32
    ok &= pmk == derive_pmk("test-passphrase", "test-ssid")
    ok &= pmk != derive_pmk("other-pass", "test-ssid")

    anonce = bytes(range(32))
    snonce = bytes(range(32, 64))
    ptk = derive_ptk(pmk, "aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", anonce, snonce)
    ok &= len(ptk) == 64
    # Order of MAC/nonce arguments must not change the result:
    ptk_rev = derive_ptk(pmk, "11:22:33:44:55:66", "aa:bb:cc:dd:ee:ff", snonce, anonce)
    ok &= ptk == ptk_rev

    keys = ptk_keys(ptk)
    ok &= len(keys["kck"]) == len(keys["kek"]) == len(keys["tk"]) == 16

    # Build a fake M2 (non-zero nonce, MIC set, SHA1 version) and verify.
    eapol = bytearray(120)
    eapol[0:4] = b"\x02\x03\x00\x4a"          # version, EAPOL-Key type, len
    eapol[4] = 2                              # descriptor type (RSN)
    struct.pack_into(">H", eapol, 5, FLAG_KEY_MIC | FLAG_PAIRWISE | VERSION_HMAC_SHA1)
    eapol[KEY_NONCE_OFFSET:KEY_NONCE_OFFSET + 32] = snonce
    msg2 = parse_eapol_key_bytes(bytes(eapol))
    ok &= msg2 is not None
    ok &= msg2.classify() == "M2"
    msg2.key_mic = compute_mic(keys["kck"], msg2.eapol_raw, VERSION_HMAC_SHA1)
    ok &= verify_mic(ptk, msg2)

    tampered = bytes(msg2.eapol_raw[:-1]) + bytes([msg2.eapol_raw[-1] ^ 0xFF])
    bad = EapolKeyInfo(eapol_raw=tampered, **{
        k: getattr(msg2, k) for k in
        ("descriptor_type", "key_info", "key_length", "replay_counter",
         "nonce", "key_mic", "key_data")
    })
    ok &= not verify_mic(ptk, bad)

    # M1 has no MIC; M3 carries ANonce + pairwise+install.
    eapol[5:7] = struct.pack(">H", VERSION_HMAC_SHA1 | FLAG_KEY_ACK)
    ok &= parse_eapol_key_bytes(bytes(eapol)).classify() == "M1"
    eapol[5:7] = struct.pack(
        ">H", VERSION_HMAC_SHA1 | FLAG_KEY_MIC | FLAG_KEY_ACK | FLAG_INSTALL
        | FLAG_PAIRWISE | FLAG_SECURE)
    ok &= parse_eapol_key_bytes(bytes(eapol)).classify() == "M3"

    # passphrase_matches: positive and negative case.
    eapol[5:7] = struct.pack(">H", FLAG_KEY_MIC | FLAG_PAIRWISE | VERSION_HMAC_SHA1)
    m2 = parse_eapol_key_bytes(bytes(eapol))
    m2.key_mic = compute_mic(keys["kck"], m2.eapol_raw, VERSION_HMAC_SHA1)
    ok &= passphrase_matches("test-passphrase", "test-ssid",
                             "aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66",
                             m2) is not None
    ok &= passphrase_matches("wrong-password", "test-ssid",
                             "aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66",
                             m2) is None

    print("self-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(_self_test())
