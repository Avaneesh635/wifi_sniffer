#!/usr/bin/env python3
"""
channel_hopper.py

Background thread that hops a monitor-mode wireless interface across
the 2.4 GHz and 5 GHz channels, so the sniffer can discover networks
on every channel instead of only the one the card is parked on.

Part 2 of the wifi_sniffer upgrade:
  1. network_db.py      (AP/client tracking)
  2. channel_hopper.py  <- this file (background channel hopping)
  3. packet_parsers.py  (advanced 802.11 parsing)
  4. wifi_sniffer.py    (rewritten main program)

Requires the `iw` utility (part of iw / wireless-regdb packages):
  sudo apt install iw
"""

import shutil
import subprocess
import threading
import time
from typing import List, Optional

# Standard 2.4 GHz channels
BAND_2GHZ: List[int] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]

# Common 5 GHz channels (UNII-1, UNII-2, UNII-2 Extended, UNII-3).
# DFS channels are included; if the driver refuses them the hopper
# simply skips to the next channel.
BAND_5GHZ: List[int] = [
    36, 40, 44, 48,
    52, 56, 60, 64,
    100, 104, 108, 112, 116, 120, 124, 128,
    132, 136, 140, 144,
    149, 153, 157, 161, 165,
]

# 6 GHz channels (WiFi 6E) - only usable on hardware/drivers that
# support them; failures are tolerated silently.
BAND_6GHZ: List[int] = [
    1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61,
    65, 69, 73, 77, 81, 85, 89, 93, 97, 101, 105, 109, 113, 117,
    121, 125, 129, 133, 137, 141, 145, 149, 153, 157, 161, 165,
    169, 173, 177, 181, 185, 189, 193, 197, 201, 205, 209, 213,
    217, 221, 225, 229, 233,
]


def _iw_path() -> Optional[str]:
    """Locate the `iw` binary, or None if it is not installed."""
    return shutil.which("iw")


def set_channel(interface: str, channel: int) -> bool:
    """
    Try to move `interface` onto `channel` using `iw`.
    Returns True on success, False if the driver refused.
    """
    iw = _iw_path()
    if iw is None:
        return False
    try:
        result = subprocess.run(
            [iw, "dev", interface, "set", "channel", str(channel)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


class ChannelHopper:
    """
    Daemon thread that cycles an interface through a list of channels.

    Usage:
        hopper = ChannelHopper("wlan0mon", interval=0.4)
        hopper.start()
        ...
        hopper.stop()
    """

    def __init__(
        self,
        interface: str,
        channels: Optional[List[int]] = None,
        interval: float = 0.4,
        include_5ghz: bool = True,
        include_6ghz: bool = False,
    ):
        self.interface = interface
        self.interval = max(0.05, interval)
        self.current_channel: Optional[int] = None
        self.hop_count = 0
        self.failed_channels = set()

        if channels is None:
            channels = list(BAND_2GHZ)
            if include_5ghz:
                channels += BAND_5GHZ
            if include_6ghz:
                channels += BAND_6GHZ
        self.channels = channels

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    # ------------------------------------------------------------- control

    def start(self) -> None:
        """Start the hopping thread (no-op if already running)."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="channel-hopper",
            daemon=True,
        )
        self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        """Signal the thread to stop and wait for it to exit."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

    # -------------------------------------------------------------- worker

    def _run(self) -> None:
        """Thread body: cycle through channels until stopped."""
        index = 0
        while not self._stop_event.is_set():
            channel = self.channels[index % len(self.channels)]
            index += 1

            if set_channel(self.interface, channel):
                with self._lock:
                    self.current_channel = channel
                    self.hop_count += 1
            else:
                # Driver refused (DFS, unsupported band, ...).
                # Remember it so we can report, and keep hopping.
                with self._lock:
                    self.failed_channels.add(channel)

            # Sleep in small slices so stop() is responsive even
            # when the interval is long.
            slept = 0.0
            while slept < self.interval and not self._stop_event.is_set():
                self._stop_event.wait(timeout=0.05)
                slept += 0.05

    # -------------------------------------------------------------- status

    def status(self) -> str:
        """One-line status string for the UI."""
        with self._lock:
            ch = self.current_channel if self.current_channel is not None else "?"
            return f"ch={ch} hops={self.hop_count}"
