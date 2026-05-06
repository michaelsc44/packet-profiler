"""Human-readable formatting for reports."""

from __future__ import annotations

from typing import Any

from rich.table import Table


def _fmt_bytes(n: int | float) -> str:
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:,.1f} {unit}"
        n /= 1024
    return f"{n:,.1f} PB"


def format_top_talkers(rows: list[dict[str, Any]]) -> Table:
    table = Table(title="Top Talkers", show_header=True, header_style="bold cyan")
    table.add_column("Client IP")
    table.add_column("MAC")
    table.add_column("Total Traffic", justify="right")
    table.add_column("Packets", justify="right")
    table.add_column("Unique Dests", justify="right")
    for r in rows:
        table.add_row(
            str(r["client_ip"]),
            str(r["mac"] or "-"),
            _fmt_bytes(r["total_bytes"] or 0),
            f"{(r['total_packets'] or 0):,}",
            f"{(r['unique_destinations'] or 0):,}",
        )
    return table


def format_client_profile(p: dict[str, Any]) -> Table:
    table = Table(title=f"Profile: {p['client_ip']}", show_header=False, box=None)
    table.add_column("field", style="bold")
    table.add_column("value")
    table.add_row("MAC", str(p.get("mac") or "-"))
    table.add_row("First seen", str(p.get("first_seen")))
    table.add_row("Last seen", str(p.get("last_seen")))
    table.add_row("Total traffic", _fmt_bytes(p.get("total_bytes") or 0))
    table.add_row("Unique destinations", f"{p.get('unique_destinations') or 0:,}")
    table.add_row("TCP fraction", f"{(p.get('frac_tcp') or 0):.2%}")
    table.add_row("UDP fraction", f"{(p.get('frac_udp') or 0):.2%}")
    snis = p.get("sni_seen") or []
    if snis:
        table.add_row("Top SNIs", ", ".join(list(snis)[:5]))
    return table
