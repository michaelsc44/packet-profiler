"""AI-powered client profile analysis using Claude.

Sends per-client behavioral profiles to Claude for natural-language
interpretation: device identification, behavioral description, anomaly
flagging, and privacy assessment.

Requires ANTHROPIC_API_KEY environment variable.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

_SYSTEM_PROMPT = """\
You are a network security analyst reviewing per-client behavioral profiles
collected from passive network observation (pcap metadata — no payload decryption).

For each client you receive:
- IP address, MAC address, hardware vendor (from OUI lookup)
- First/last seen timestamps, total traffic volume
- Top DNS queries and TLS SNI hostnames (what the device talks to)
- Protocol mix (% TCP vs UDP), unique destination count, unique port count
- JA3 TLS fingerprints (if available) and signal strength (if WiFi)

Provide a concise, structured analysis covering:

1. **Device type** — What kind of device is this? (smartphone, laptop, smart TV, IoT sensor,
   router, unknown). State your confidence (high/medium/low) and the key signals driving it.

2. **Behavioral profile** — What is this device doing on the network? Describe the services
   and patterns you observe (streaming, web browsing, IoT telemetry, cloud sync, gaming, etc.).

3. **Anomalies / red flags** — Anything unusual: unexpected ports, external scanning behavior,
   high-volume uploads, beaconing to unknown hosts, use of non-standard DNS, Tor exit nodes, etc.
   If nothing looks suspicious, say so clearly.

4. **Privacy & data exposure** — What personal or behavioral data is leaking in cleartext
   metadata? (cleartext DNS queries, non-private SNI, exposed service names, etc.)

Be specific and ground observations in the actual data provided. Avoid speculation beyond
what the metadata supports. Use markdown for formatting.
"""


def _get_client() -> Any:
    """Return an Anthropic client, or raise a helpful error if the key is missing."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError(
            "ANTHROPIC_API_KEY is not set.\n"
            "Get a key at https://console.anthropic.com and set it with:\n"
            "  export ANTHROPIC_API_KEY=sk-ant-..."
        )
    try:
        import anthropic  # noqa: PLC0415
    except ImportError as exc:
        raise RuntimeError("anthropic package not installed. Run: pip install anthropic") from exc
    return anthropic.Anthropic(api_key=api_key)


def _format_profile_prompt(profile: dict[str, Any], flows_sample: list[dict[str, Any]]) -> str:
    """Build the user-turn prompt text from a profile dict and recent flows."""
    lines: list[str] = ["## Client Profile\n"]

    lines.append(f"- **IP:** {profile.get('client_ip', 'unknown')}")
    lines.append(f"- **MAC:** {profile.get('mac', 'unknown')}")

    # Vendor from OUI if present
    vendor = profile.get("vendor") or profile.get("oui_vendor")
    if vendor:
        lines.append(f"- **Hardware vendor:** {vendor}")

    import datetime  # noqa: PLC0415

    for ts_field, label in [("first_seen", "First seen"), ("last_seen", "Last seen")]:
        ts = profile.get(ts_field)
        if ts:
            try:
                dt = datetime.datetime.fromtimestamp(float(ts), tz=datetime.timezone.utc)
                lines.append(f"- **{label}:** {dt.strftime('%Y-%m-%d %H:%M:%S UTC')}")
            except (ValueError, OSError):
                lines.append(f"- **{label}:** {ts}")

    total_bytes = profile.get("total_bytes", 0)
    total_packets = profile.get("total_packets", 0)
    lines.append(f"- **Total traffic:** {total_bytes:,} bytes / {total_packets:,} packets")
    lines.append(f"- **Unique destinations:** {profile.get('unique_destinations', 0)}")
    lines.append(f"- **Unique ports:** {profile.get('unique_dst_ports', 0)}")

    frac_tcp = profile.get("frac_tcp")
    frac_udp = profile.get("frac_udp")
    if frac_tcp is not None and frac_udp is not None:
        lines.append(f"- **Protocol mix:** {frac_tcp * 100:.1f}% TCP / {frac_udp * 100:.1f}% UDP")

    signal = profile.get("signal_dbm")
    if signal is not None:
        lines.append(f"- **WiFi signal:** {signal} dBm")

    sni_seen = profile.get("sni_seen") or []
    if sni_seen:
        shown = sni_seen[:20]
        lines.append(f"\n### TLS SNI hostnames (top {len(shown)})")
        for s in shown:
            lines.append(f"  - {s}")

    dns_seen = profile.get("dns_seen") or []
    if dns_seen:
        shown = dns_seen[:20]
        lines.append(f"\n### DNS queries (top {len(shown)})")
        for d in shown:
            lines.append(f"  - {d}")

    ja3_list = profile.get("ja3_fingerprints") or []
    if ja3_list:
        lines.append("\n### JA3 fingerprints")
        for j in ja3_list[:5]:
            lines.append(f"  - `{j}`")

    if flows_sample:
        lines.append(f"\n### Recent flows sample ({len(flows_sample)} records)")
        lines.append("| src_port | dst_ip | dst_port | proto | bytes | sni/dns |")
        lines.append("|---|---|---|---|---|---|")
        for fl in flows_sample[:30]:
            sni_or_dns = fl.get("tls_sni") or fl.get("dns_query") or ""
            lines.append(
                f"| {fl.get('src_port', '')} | {fl.get('dst_ip', '')} "
                f"| {fl.get('dst_port', '')} | {fl.get('proto', '')} "
                f"| {fl.get('bytes_total', '')} | {sni_or_dns} |"
            )

    return "\n".join(lines)


def analyze_client(
    profile: dict[str, Any],
    flows_sample: list[dict[str, Any]] | None = None,
) -> str:
    """Analyze a single client profile with Claude.

    Args:
        profile: Row from the ``profiles`` table as a dict.
        flows_sample: Up to 50 recent flow records for this client (optional).

    Returns:
        Markdown string containing Claude's analysis.
    """
    client = _get_client()
    prompt = _format_profile_prompt(profile, flows_sample or [])

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1024,
        system=[
            {
                "type": "text",
                "text": _SYSTEM_PROMPT,
                "cache_control": {"type": "ephemeral"},  # cache across batch calls
            }
        ],
        messages=[{"role": "user", "content": prompt}],
    )
    return str(response.content[0].text)


def analyze_all_clients(
    store: Any,
    output_dir: Path | None = None,
) -> dict[str, str]:
    """Analyze every client in the profiles table.

    Args:
        store: A ``Storage`` instance.
        output_dir: If provided, save each analysis as ``<ip>.md`` here.

    Returns:
        Dict mapping ``client_ip`` → analysis markdown.
    """
    profiles = store.get_all_profiles()
    results: dict[str, str] = {}

    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)

    for profile in profiles:
        ip = profile["client_ip"]
        flows = store.get_recent_flows(ip, limit=50)
        analysis = analyze_client(profile, flows)
        results[ip] = analysis

        if output_dir:
            (output_dir / f"{ip.replace(':', '_')}.md").write_text(analysis)

    return results


def summarize_network(profiles: list[dict[str, Any]]) -> str:
    """Generate a network-level summary across all client profiles.

    Args:
        profiles: List of profile dicts (all rows from the profiles table).

    Returns:
        Markdown summary string.
    """
    client = _get_client()

    lines = [f"# Network Summary — {len(profiles)} clients\n"]
    for p in profiles:
        ip = p.get("client_ip", "?")
        mac = p.get("mac", "?")
        vendor = p.get("vendor") or ""
        total_bytes = p.get("total_bytes", 0)
        unique_dst = p.get("unique_destinations", 0)
        sni_count = len(p.get("sni_seen") or [])
        dns_count = len(p.get("dns_seen") or [])
        lines.append(
            f"- **{ip}** ({mac}{', ' + vendor if vendor else ''}) — "
            f"{total_bytes:,} B, {unique_dst} dests, {sni_count} SNIs, {dns_count} DNS queries"
        )

    network_prompt = "\n".join(lines) + (
        "\n\nPlease provide a network-level summary covering:\n"
        "1. **Device inventory** — estimated breakdown by device type\n"
        "2. **Notable devices** — any that stand out as risky, unusual, or worth investigating\n"
        "3. **Network hygiene** — overall observations about DNS privacy, TLS usage, IoT exposure\n"
        "4. **Recommendations** — top 3 actionable steps to improve security or privacy\n"
    )

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=2048,
        system=[
            {
                "type": "text",
                "text": _SYSTEM_PROMPT,
                "cache_control": {"type": "ephemeral"},
            }
        ],
        messages=[{"role": "user", "content": network_prompt}],
    )
    return str(response.content[0].text)
