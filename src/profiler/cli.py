"""Command-line interface for ppcap."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from . import __version__
from .capture import CaptureConfig, run_capture
from .parser import parse_pcap
from .profiler import build_profiles
from .report import format_client_profile, format_top_talkers
from .storage import Storage

console = Console()


@click.group()
@click.version_option(__version__, prog_name="ppcap")
def main() -> None:
    """Network Packet Profiler — capture and profile client traffic."""


@main.command()
@click.option("--iface", "-i", required=True, help="Network interface (e.g., eth0)")
@click.option("--output", "-o", type=click.Path(file_okay=False), default="./captures",
              help="Directory for rotated pcap files")
@click.option("--rotate", type=int, default=300, help="Rotation interval in seconds")
@click.option("--max-files", type=int, default=288, help="Max rotated files to keep")
@click.option("--snaplen", type=int, default=256, help="Bytes to capture per packet")
@click.option("--filter", "bpf", default="", help="Optional BPF filter expression")
def capture(iface: str, output: str, rotate: int, max_files: int, snaplen: int, bpf: str) -> None:
    """Run tcpdump with rotation until Ctrl-C."""
    cfg = CaptureConfig(
        interface=iface,
        output_dir=Path(output),
        rotate_seconds=rotate,
        max_files=max_files,
        snaplen=snaplen,
        bpf_filter=bpf,
    )
    cfg.output_dir.mkdir(parents=True, exist_ok=True)
    console.print(f"[green]▶[/] Starting capture on [bold]{iface}[/] → {output}")
    try:
        run_capture(cfg)
    except KeyboardInterrupt:
        console.print("\n[yellow]⏹[/] Capture stopped.")


@main.command()
@click.argument("pcaps", nargs=-1, required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--db", default="./data/profiles.duckdb", help="DuckDB database path")
def analyze(pcaps: tuple[str, ...], db: str) -> None:
    """Parse pcap files and store flows + profile updates in the database."""
    Path(db).parent.mkdir(parents=True, exist_ok=True)
    store = Storage(Path(db))
    store.init_schema()

    total_flows = 0
    for path in pcaps:
        console.print(f"[cyan]→[/] parsing {path}")
        flows = list(parse_pcap(Path(path)))
        store.insert_flows(flows)
        total_flows += len(flows)
        console.print(f"  [green]✓[/] {len(flows):,} flows")

    console.print("[cyan]→[/] building profiles")
    build_profiles(store)
    console.print(f"[green]✓[/] done — {total_flows:,} flows total")


@main.command()
@click.option("--db", default="./data/profiles.duckdb", help="DuckDB database path")
@click.option("--top", type=int, default=10, help="Show top N talkers")
@click.option("--client", help="Show full profile for a specific client IP")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON instead of tables")
def report(db: str, top: int, client: str | None, as_json: bool) -> None:
    """Print reports from stored profiles."""
    if not Path(db).exists():
        console.print(f"[red]✗[/] database not found: {db}")
        sys.exit(1)
    store = Storage(Path(db))

    if client:
        profile = store.get_profile(client)
        if profile is None:
            console.print(f"[red]✗[/] no profile for {client}")
            sys.exit(1)
        if as_json:
            click.echo(json.dumps(profile, indent=2, default=str))
        else:
            console.print(format_client_profile(profile))
    else:
        talkers = store.top_talkers(limit=top)
        if as_json:
            click.echo(json.dumps(talkers, indent=2, default=str))
        else:
            console.print(format_top_talkers(talkers))


if __name__ == "__main__":
    main()
