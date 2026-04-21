"""tcpdump wrapper with rotating capture."""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class CaptureConfig:
    interface: str
    output_dir: Path
    rotate_seconds: int = 300
    max_files: int = 288
    snaplen: int = 256
    bpf_filter: str = ""


def run_capture(cfg: CaptureConfig) -> None:
    """Invoke tcpdump with rotation. Blocks until killed.

    Uses:
      -i iface       : interface
      -s snaplen     : capture only N bytes per packet (headers are usually enough)
      -G seconds     : rotate every N seconds
      -W count       : keep at most N rotated files (circular)
      -w template    : filename with strftime placeholders
    """
    if shutil.which("tcpdump") is None:
        raise RuntimeError("tcpdump not found in PATH — install it first")

    template = str(cfg.output_dir / "capture-%Y%m%d-%H%M%S.pcap")
    argv: list[str] = [
        "tcpdump",
        "-i", cfg.interface,
        "-s", str(cfg.snaplen),
        "-G", str(cfg.rotate_seconds),
        "-W", str(cfg.max_files),
        "-w", template,
        "-Z", "root",      # don't drop privileges mid-rotation
        "-n",              # no name resolution during capture
    ]
    if cfg.bpf_filter:
        argv.append(cfg.bpf_filter)

    # tcpdump runs until SIGINT; Click/main.py handles KeyboardInterrupt.
    subprocess.run(argv, check=True)
