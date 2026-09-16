#!/usr/bin/env bash
# install.sh
#
# One-shot installer for the WiFi sniffer (wifi_sniffer.py or the
# merged wifi_sniffer_app.py executable build).
#
# Installs:
#   - iw, aircrack-ng      (channel hopping + monitor mode tooling)
#   - python3-pip, scapy   (packet capture/parsing)
#   - pyinstaller          (optional, with --exe, for single-file builds)
#
# Optional flags:
#   --interface wlan0   also prepare that interface for monitor mode
#                       (airmon-ng check kill + airmon-ng start)
#   --exe               also install pyinstaller for executable builds
#
# Run as root:
#   sudo ./install.sh
#   sudo ./install.sh --interface wlan0
#   sudo ./install.sh --interface wlan0 --exe
#
# NOTE: this tool must only be used on networks you own or have
# explicit permission to test.

set -euo pipefail

IFACE=""
WANT_EXE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --interface)
            IFACE="${2:?--interface requires a value, e.g. --interface wlan0}"
            shift 2
            ;;
        --exe)
            WANT_EXE=1
            shift
            ;;
        *)
            echo "Unknown option: $1" >&2
            echo "Usage: sudo ./install.sh [--interface wlan0] [--exe]" >&2
            exit 1
            ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "[!] Please run as root: sudo ./install.sh" >&2
    exit 1
fi

echo "[*] Updating package lists..."
apt-get update

echo "[*] Installing system dependencies (iw, aircrack-ng, pip)..."
apt-get install -y iw aircrack-ng python3-pip

echo "[*] Installing Python dependencies (scapy)..."
# Newer Debian/Ubuntu (PEP 668) requires --break-system-packages;
# older distros don't know the flag, so fall back to a plain install.
pip3 install --break-system-packages scapy 2>/dev/null \
    || pip3 install scapy

if [[ "$WANT_EXE" -eq 1 ]]; then
    echo "[*] Installing pyinstaller (for single-executable builds)..."
    pip3 install --break-system-packages pyinstaller 2>/dev/null \
        || pip3 install pyinstaller
fi

echo "[*] Verifying installation..."
command -v iw        >/dev/null || { echo "[!] iw missing after install" >&2; exit 1; }
command -v airmon-ng >/dev/null || { echo "[!] airmon-ng missing after install" >&2; exit 1; }
python3 -c "import scapy" 2>/dev/null \
    || { echo "[!] scapy not importable" >&2; exit 1; }
echo "[*] All dependencies OK."

if [[ -n "$IFACE" ]]; then
    echo "[*] Killing processes that interfere with monitor mode..."
    # WARNING: this drops your network connection (by design).
    airmon-ng check kill

    echo "[*] Enabling monitor mode on $IFACE..."
    airmon-ng start "$IFACE"

    MON=""
    for cand in "${IFACE}mon" "$IFACE"; do
        if ip link show "$cand" >/dev/null 2>&1; then
            MON="$cand"
            break
        fi
    done

    if [[ -n "$MON" ]]; then
        echo "[*] Monitor interface ready: $MON"
        echo
        echo "[*] Start sniffing with:"
        echo "      sudo python3 wifi_sniffer.py -i $MON"
        echo "  or the merged app / executable:"
        echo "      sudo python3 wifi_sniffer_app.py -i $MON"
        echo "      sudo ./dist/wifi_sniffer -i $MON"
    else
        echo "[!] Could not auto-detect the monitor interface;" >&2
        echo "    run 'iw dev' and look for 'type monitor'." >&2
    fi
else
    echo "[*] Done."
    echo "[*] Next steps (monitor mode setup):"
    echo "      1) sudo airmon-ng check kill"
    echo "      2) sudo airmon-ng start wlan0     # creates wlan0mon"
    echo "      3) sudo python3 wifi_sniffer.py -i wlan0mon"
fi

echo
echo "[*] When finished, restore normal networking with:"
echo "      sudo airmon-ng stop <mon-iface> && sudo systemctl restart NetworkManager"
