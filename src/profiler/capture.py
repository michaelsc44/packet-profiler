"""tcpdump wrapper with rotating capture."""

from __future__ import annotations

import shutil
import subprocess
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator


@dataclass
class CaptureConfig:
    interface: str
    output_dir: Path
    rotate_seconds: int = 300
    max_files: int = 288
    snaplen: int = 256
    bpf_filter: str = ""
    # WiFi monitor mode options
    wifi_mode: bool = False
    channel_hop: bool = True
    channel: int | None = None
    channels: list[int] = field(default_factory=list)
    hop_dwell_ms: int = 200


@contextmanager
def _wifi_context(cfg: CaptureConfig) -> Iterator[str]:
    """Enable monitor mode if wifi_mode is set, yield the interface name."""
    if not cfg.wifi_mode:
        yield cfg.interface
        return

    from .wifi import MonitorContext  # noqa: PLC0415

    ctx = MonitorContext(
        iface=cfg.interface,
        channel=cfg.channel,
        hop=cfg.channel_hop and cfg.channel is None,
        dwell_ms=cfg.hop_dwell_ms,
        channels=cfg.channels or None,
    )
    with ctx as mon_iface:
        yield mon_iface


def run_capture(cfg: CaptureConfig) -> None:
    """Invoke tcpdump with rotation. Blocks until killed.

    Uses:
      -i iface       : interface
      -s snaplen     : capture only N bytes per packet (headers are usually enough)
      -G seconds     : rotate every N seconds
      -W count       : keep at most N rotated files (circular)
      -w template    : filename with strftime placeholders

    In WiFi mode (-w / --wifi): puts the NIC into monitor mode first,
    optionally starts a channel hopper, and restores managed mode on exit.
    """
    if shutil.which("tcpdump") is None:
        raise RuntimeError("tcpdump not found in PATH — install it first")

    with _wifi_context(cfg) as active_iface:
        template = str(cfg.output_dir / "capture-%Y%m%d-%H%M%S.pcap")
        argv: list[str] = [
            "tcpdump",
            "-i",
            active_iface,
            "-s",
            str(cfg.snaplen),
            "-G",
            str(cfg.rotate_seconds),
            "-W",
            str(cfg.max_files),
            "-w",
            template,
            "-Z",
            "root",  # don't drop privileges mid-rotation
            "-n",  # no name resolution during capture
        ]
        if cfg.wifi_mode:
            # -e: include link-layer headers (needed for 802.11 MAC addresses)
            # -I: request monitor mode from tcpdump as well (belt-and-suspenders)
            argv += ["-e", "-I"]
        if cfg.bpf_filter:
            argv.append(cfg.bpf_filter)

        # tcpdump runs until SIGINT; Click/main.py handles KeyboardInterrupt.
        try:
            subprocess.run(argv, check=True)
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(
                f"tcpdump exited with code {exc.returncode} — "
                "check interface name, permissions, or BPF filter syntax"
            ) from exc
