"""Parse pcap files into flow records using dpkt.

A "flow" here is a 5-tuple aggregation within a short window:
    (src_ip, dst_ip, src_port, dst_port, proto) + first/last timestamps + byte/packet counts.
DNS queries and TLS SNI are extracted as side-channels for enrichment.
"""
from __future__ import annotations

import socket
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import dpkt


@dataclass
class Flow:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str               # "tcp" | "udp" | "icmp" | "other"
    src_mac: str = ""
    dst_mac: str = ""
    first_ts: float = 0.0
    last_ts: float = 0.0
    bytes_total: int = 0
    packets: int = 0
    tls_sni: str | None = None
    dns_query: str | None = None
    extras: dict[str, Any] = field(default_factory=dict)


def _mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def _proto_name(n: int) -> str:
    return {6: "tcp", 17: "udp", 1: "icmp"}.get(n, "other")


def _extract_sni(tcp_payload: bytes) -> str | None:
    """Pull SNI out of a TLS ClientHello. Returns None if not a ClientHello."""
    # Very small hand-rolled parser: TLS record → handshake → client_hello → extensions → SNI.
    # In production, use a library; this is intentionally compact for the starter.
    try:
        if len(tcp_payload) < 43 or tcp_payload[0] != 0x16:  # not TLS handshake
            return None
        # Skip record header (5) + handshake header (4) + version (2) + random (32)
        idx = 5 + 4 + 2 + 32
        sid_len = tcp_payload[idx]; idx += 1 + sid_len
        cs_len = int.from_bytes(tcp_payload[idx:idx + 2], "big"); idx += 2 + cs_len
        cm_len = tcp_payload[idx]; idx += 1 + cm_len
        ext_total = int.from_bytes(tcp_payload[idx:idx + 2], "big"); idx += 2
        end = idx + ext_total
        while idx + 4 <= end:
            ext_type = int.from_bytes(tcp_payload[idx:idx + 2], "big")
            ext_len = int.from_bytes(tcp_payload[idx + 2:idx + 4], "big")
            idx += 4
            if ext_type == 0x0000:  # server_name
                # list_len(2) + name_type(1) + name_len(2) + name
                name_len = int.from_bytes(tcp_payload[idx + 3:idx + 5], "big")
                return tcp_payload[idx + 5:idx + 5 + name_len].decode("ascii", errors="replace")
            idx += ext_len
    except Exception:
        return None
    return None


def parse_pcap(path: Path) -> Iterator[Flow]:
    """Yield Flow records from a pcap file. One record per packet for now —
    aggregation happens in the profiler layer to keep this module streaming."""
    with path.open("rb") as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except Exception:
                continue
            if not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                continue
            ip = eth.data
            src_ip = socket.inet_ntop(
                socket.AF_INET if isinstance(ip, dpkt.ip.IP) else socket.AF_INET6, ip.src
            )
            dst_ip = socket.inet_ntop(
                socket.AF_INET if isinstance(ip, dpkt.ip.IP) else socket.AF_INET6, ip.dst
            )
            proto_num = ip.p if isinstance(ip, dpkt.ip.IP) else ip.nxt
            proto = _proto_name(proto_num)
            src_port = dst_port = 0
            sni: str | None = None
            dns_query: str | None = None

            if isinstance(ip.data, dpkt.tcp.TCP):
                src_port, dst_port = ip.data.sport, ip.data.dport
                if dst_port == 443 and ip.data.data:
                    sni = _extract_sni(bytes(ip.data.data))
            elif isinstance(ip.data, dpkt.udp.UDP):
                src_port, dst_port = ip.data.sport, ip.data.dport
                if dst_port == 53 and ip.data.data:
                    try:
                        dns = dpkt.dns.DNS(ip.data.data)
                        if dns.qd:
                            qname = dns.qd[0].name
                            dns_query = qname if isinstance(qname, str) else qname.decode()
                    except Exception:
                        pass

            yield Flow(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                proto=proto,
                src_mac=_mac(eth.src),
                dst_mac=_mac(eth.dst),
                first_ts=ts,
                last_ts=ts,
                bytes_total=len(buf),
                packets=1,
                tls_sni=sni,
                dns_query=dns_query,
            )
