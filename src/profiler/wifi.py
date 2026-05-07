"""WiFi monitor mode management for ppcap.

Handles putting a wireless NIC into monitor mode, channel hopping,
and restoring managed mode on exit.

Requires root or CAP_NET_ADMIN / CAP_NET_RAW.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import threading
import time

logger = logging.getLogger(__name__)

# 2.4 GHz channels (1-13) + common 5 GHz channels
_CHANNELS_2_4 = list(range(1, 14))
_CHANNELS_5 = [
    36,
    40,
    44,
    48,
    52,
    56,
    60,
    64,
    100,
    104,
    108,
    112,
    116,
    120,
    124,
    128,
    132,
    136,
    140,
    149,
    153,
    157,
    161,
    165,
]
DEFAULT_CHANNELS = _CHANNELS_2_4 + _CHANNELS_5


def list_wifi_interfaces() -> list[str]:
    """Return wireless interface names visible to `iw dev`."""
    if shutil.which("iw") is None:
        return []
    try:
        out = subprocess.check_output(["iw", "dev"], text=True, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        return []
    ifaces: list[str] = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Interface "):
            ifaces.append(line.split()[1])
    return ifaces


def _nm_set_managed(iface: str, managed: bool) -> None:
    """Tell NetworkManager to manage or unmanage *iface*. No-op if nmcli absent."""
    if shutil.which("nmcli") is None:
        return
    state = "yes" if managed else "no"
    result = subprocess.run(
        ["nmcli", "device", "set", iface, "managed", state],
        capture_output=True,
    )
    if result.returncode != 0:
        logger.warning(
            "nmcli device set %s managed %s failed (code %d): %s",
            iface,
            state,
            result.returncode,
            result.stderr.decode(errors="replace").strip(),
        )
    else:
        logger.debug("NetworkManager: %s managed=%s", iface, state)


def _get_phy(iface: str) -> str:
    """Return the phy name (e.g. 'phy0') for *iface* by parsing `iw dev <iface> info`."""
    out = subprocess.check_output(["iw", "dev", iface, "info"], text=True)
    for line in out.splitlines():
        parts = line.strip().split()
        # Line looks like: "wiphy 0"
        if len(parts) == 2 and parts[0] == "wiphy":
            return f"phy{parts[1]}"
    raise RuntimeError(f"Could not determine phy for interface {iface}")


def enable_monitor_mode(iface: str) -> str:
    """Put *iface* into monitor mode and return the resulting interface name.

    On iwlwifi (and other drivers that reject in-place type changes), creates a
    new virtual monitor interface 'mon0' via `iw phy <phy> interface add`.
    Falls back to `airmon-ng` if `iw` is unavailable.
    Raises RuntimeError if neither tool can do the job.
    """
    if shutil.which("iw"):
        # Unmanage via NetworkManager first so it doesn't fight the mode switch.
        _nm_set_managed(iface, False)
        try:
            phy = _get_phy(iface)
            mon_iface = "mon0"
            subprocess.run(
                ["iw", "phy", phy, "interface", "add", mon_iface, "type", "monitor"],
                check=True,
                capture_output=True,
            )
            up = subprocess.run(["ip", "link", "set", mon_iface, "up"], capture_output=True)
            if up.returncode != 0:
                logger.warning(
                    "ip link set %s up returned %d — proceeding anyway; "
                    "interface may still be usable in monitor mode",
                    mon_iface,
                    up.returncode,
                )
            logger.info(
                "Monitor mode enabled on %s (phy=%s) via iw virtual interface", mon_iface, phy
            )
            return mon_iface
        except subprocess.CalledProcessError as exc:
            logger.warning("iw failed (%s), trying airmon-ng", exc)

    if shutil.which("airmon-ng"):
        try:
            out = subprocess.check_output(
                ["airmon-ng", "start", iface], text=True, stderr=subprocess.DEVNULL
            )
            # airmon-ng prints something like "monitor mode enabled on wlan0mon"
            for line in out.splitlines():
                if "monitor mode" in line.lower() and "on" in line.lower():
                    parts = line.strip().split()
                    mon_iface = parts[-1].rstrip(")")
                    logger.info("Monitor mode enabled on %s via airmon-ng", mon_iface)
                    return mon_iface
            # If we can't parse the output, assume <iface>mon
            return iface + "mon"
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(f"airmon-ng also failed: {exc}") from exc

    raise RuntimeError(
        "Neither `iw` nor `airmon-ng` is available. Install wireless-tools or aircrack-ng."
    )


def disable_monitor_mode(iface: str) -> None:
    """Tear down monitor mode on *iface*. Best-effort — does not raise.

    If *iface* is a virtual interface created by enable_monitor_mode (e.g. 'mon0'),
    it is deleted with `iw dev <iface> del`.  For interfaces managed by airmon-ng,
    `airmon-ng stop` is used instead.
    """
    try:
        if shutil.which("iw"):
            # Delete the virtual monitor interface. This is a no-op if the
            # interface doesn't exist or wasn't created by us.
            result = subprocess.run(["iw", "dev", iface, "del"], capture_output=True, check=False)
            if result.returncode != 0:
                # Fallback: interface may have been put into monitor mode in-place
                # (e.g. via airmon-ng on some drivers) — restore type directly.
                subprocess.run(
                    ["ip", "link", "set", iface, "down"], capture_output=True, check=False
                )
                subprocess.run(
                    ["iw", "dev", iface, "set", "type", "managed"],
                    capture_output=True,
                    check=False,
                )
                subprocess.run(["ip", "link", "set", iface, "up"], capture_output=True, check=False)
        elif shutil.which("airmon-ng"):
            subprocess.run(["airmon-ng", "stop", iface], capture_output=True, check=False)
        # Hand control back to NetworkManager if it was managing the interface before.
        _nm_set_managed(iface, True)
        logger.info("Monitor mode disabled on %s", iface)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not restore managed mode on %s: %s", iface, exc)


def set_channel(iface: str, channel: int) -> None:
    """Set *iface* to *channel*. Silently ignores errors (channel may not be supported)."""
    try:
        subprocess.run(
            ["iw", "dev", iface, "set", "channel", str(channel)],
            capture_output=True,
            check=False,
        )
    except Exception:  # noqa: BLE001
        pass


def channel_hop(
    iface: str,
    channels: list[int] | None = None,
    dwell_ms: int = 200,
    stop_event: threading.Event | None = None,
) -> None:
    """Cycle through *channels* on *iface*, dwelling *dwell_ms* ms each.

    Runs until *stop_event* is set (or indefinitely if None — use as daemon thread).
    """
    chans = channels or DEFAULT_CHANNELS
    dwell = dwell_ms / 1000.0
    while stop_event is None or not stop_event.is_set():
        for ch in chans:
            if stop_event and stop_event.is_set():
                return
            set_channel(iface, ch)
            time.sleep(dwell)


class MonitorContext:
    """Context manager that enables monitor mode on entry and restores it on exit.

    Usage::

        with MonitorContext("wlan0") as mon_iface:
            # mon_iface is the monitor-mode interface name (may differ, e.g. wlan0mon)
            run_capture(cfg)
    """

    def __init__(
        self,
        iface: str,
        channel: int | None = None,
        hop: bool = True,
        dwell_ms: int = 200,
        channels: list[int] | None = None,
    ) -> None:
        self.iface = iface
        self.channel = channel
        self.hop = hop
        self.dwell_ms = dwell_ms
        self.channels = channels
        self._mon_iface: str = iface
        self._stop_event = threading.Event()
        self._hop_thread: threading.Thread | None = None

    def __enter__(self) -> str:
        self._mon_iface = enable_monitor_mode(self.iface)

        if self.channel is not None:
            set_channel(self._mon_iface, self.channel)
        elif self.hop:
            self._stop_event.clear()
            self._hop_thread = threading.Thread(
                target=channel_hop,
                args=(self._mon_iface, self.channels, self.dwell_ms, self._stop_event),
                daemon=True,
                name="ppcap-channel-hop",
            )
            self._hop_thread.start()
            logger.info("Channel hopper started on %s", self._mon_iface)

        return self._mon_iface

    def __exit__(self, *_exc: object) -> None:
        self._stop_event.set()
        if self._hop_thread and self._hop_thread.is_alive():
            self._hop_thread.join(timeout=2)
        disable_monitor_mode(self._mon_iface)
