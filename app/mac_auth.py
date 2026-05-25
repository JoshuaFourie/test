import re
import subprocess
import logging

logger = logging.getLogger(__name__)

_MAC_RE = re.compile(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$")


def normalize_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    cleaned = re.sub(r"[^a-fA-F0-9]", "", mac)
    if len(cleaned) != 12:
        return None
    return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2)).upper()


def _read_arp_table() -> dict[str, str]:
    """Parse /proc/net/arp — works when container uses host network."""
    table: dict[str, str] = {}
    try:
        with open("/proc/net/arp") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 4:
                    ip, mac = parts[0], parts[3].upper()
                    if mac != "00:00:00:00:00:00":
                        table[ip] = mac
    except OSError:
        logger.warning("Cannot read /proc/net/arp — ARP-based auth unavailable")
    return table


def _ping(ip: str) -> None:
    try:
        subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
            capture_output=True,
            timeout=2,
        )
    except Exception:
        pass


def get_mac_for_ip(ip: str) -> str | None:
    """Resolve a LAN IP to its MAC address via ARP table."""
    table = _read_arp_table()
    if ip not in table:
        _ping(ip)
        table = _read_arp_table()
    mac = table.get(ip)
    if mac:
        logger.debug(f"ARP resolved {ip} -> {mac}")
    else:
        logger.info(f"No ARP entry for {ip}")
    return mac
