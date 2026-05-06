"""Parse pcap files into flow records using dpkt.

Supports two link-layer types:
  - 1  (LINKTYPE_ETHERNET): standard Ethernet frames
  - 127 (LINKTYPE_IEEE802_11_RADIOTAP): 802.11 radiotap frames (WiFi monitor mode)

A "flow" here is a per-packet record; aggregation happens in the profiler layer
to keep this module stateless and streaming.
"""

from __future__ import annotations

import socket
import struct
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
    proto: str  # "tcp" | "udp" | "icmp" | "other"
    src_mac: str = ""
    dst_mac: str = ""
    first_ts: float = 0.0
    last_ts: float = 0.0
    bytes_total: int = 0
    packets: int = 0
    tls_sni: str | None = None
    dns_query: str | None = None
    signal_dbm: int | None = None  # WiFi signal strength (radiotap only)
    extras: dict[str, Any] = field(default_factory=dict)


def _mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def _proto_name(n: int) -> str:
    return {6: "tcp", 17: "udp", 1: "icmp"}.get(n, "other")


def _extract_sni(tcp_payload: bytes) -> str | None:
    """Pull SNI out of a TLS ClientHello. Returns None if not a ClientHello."""
    try:
        if len(tcp_payload) < 43 or tcp_payload[0] != 0x16:  # not TLS handshake
            return None
        # Skip record header (5) + handshake header (4) + version (2) + random (32)
        idx = 5 + 4 + 2 + 32
        sid_len = tcp_payload[idx]
        idx += 1 + sid_len
        cs_len = int.from_bytes(tcp_payload[idx : idx + 2], "big")
        idx += 2 + cs_len
        cm_len = tcp_payload[idx]
        idx += 1 + cm_len
        ext_total = int.from_bytes(tcp_payload[idx : idx + 2], "big")
        idx += 2
        end = idx + ext_total
        while idx + 4 <= end:
            ext_type = int.from_bytes(tcp_payload[idx : idx + 2], "big")
            ext_len = int.from_bytes(tcp_payload[idx + 2 : idx + 4], "big")
            idx += 4
            if ext_type == 0x0000:  # server_name
                name_len = int.from_bytes(tcp_payload[idx + 3 : idx + 5], "big")
                return tcp_payload[idx + 5 : idx + 5 + name_len].decode("ascii", errors="replace")
            idx += ext_len
    except Exception:  # noqa: BLE001
        return None
    return None


# ---------------------------------------------------------------------------
# Radiotap / 802.11 helpers
# ---------------------------------------------------------------------------

_RADIOTAP_SIGNAL_PRESENT_BIT = 5  # bit 5 in present flags = RSSI dBm


def _parse_radiotap(buf: bytes) -> tuple[int, int | None]:
    """Parse a radiotap header.

    Returns (header_length, signal_dbm_or_None).
    signal_dbm is a signed byte (dBm) if the RSSI field is present, else None.
    """
    if len(buf) < 8:
        return 0, None
    # Radiotap header: version(1) + pad(1) + length(2 LE) + present(4 LE)
    hdr_len = struct.unpack_from("<H", buf, 2)[0]
    present = struct.unpack_from("<I", buf, 4)[0]

    signal_dbm: int | None = None
    # Walk the present-field bitmap to find the RSSI byte offset.
    # We only handle the first present word for simplicity.
    if present & (1 << _RADIOTAP_SIGNAL_PRESENT_BIT):
        # Fields before RSSI in the radiotap bitmap (in order):
        #   TSFT(8), Flags(1), Rate(1), Channel(4), FHSS(2)
        # Sum their sizes to locate RSSI:
        offset = 8  # skip fixed 8-byte header
        if present & (1 << 0):  # TSFT: 8 bytes, aligned to 8
            offset = (offset + 7) & ~7
            offset += 8
        if present & (1 << 1):  # Flags: 1 byte
            offset += 1
        if present & (1 << 2):  # Rate: 1 byte
            offset += 1
        if present & (1 << 3):  # Channel: 4 bytes, aligned to 2
            offset = (offset + 1) & ~1
            offset += 4
        if present & (1 << 4):  # FHSS: 2 bytes
            offset += 2
        # Now at bit 5 = dBm Antenna Signal: signed 1 byte
        if offset < hdr_len and offset < len(buf):
            signal_dbm = struct.unpack_from("b", buf, offset)[0]

    return hdr_len, signal_dbm


# 802.11 frame types
_FC_TYPE_DATA = 2


def _parse_80211(buf: bytes) -> tuple[bytes | None, str, str, int | None]:
    """Parse an 802.11 MAC frame (after the radiotap header).

    Returns (ip_payload, src_mac, dst_mac, signal_dbm) or (None, "", "", None)
    if the frame is not a data frame carrying an IP payload.
    """
    if len(buf) < 24:
        return None, "", "", None

    fc = struct.unpack_from("<H", buf, 0)[0]
    frame_type = (fc >> 2) & 0x3
    frame_subtype = (fc >> 4) & 0xF

    # Only process data frames (type=2); skip management/control
    if frame_type != _FC_TYPE_DATA:
        return None, "", "", None

    # DS bits: to-DS (bit 8) and from-DS (bit 9)
    to_ds = (fc >> 8) & 0x1
    from_ds = (fc >> 9) & 0x1

    # 802.11 address layout depends on DS bits:
    # to_ds=0, from_ds=0: addr1=dst, addr2=src, addr3=BSSID
    # to_ds=1, from_ds=0: addr1=BSSID, addr2=src, addr3=dst
    # to_ds=0, from_ds=1: addr1=dst, addr2=BSSID, addr3=src
    # to_ds=1, from_ds=1: addr1=RA, addr2=TA, addr3=dst, addr4=src (WDS)
    addr1 = _mac(buf[4:10])
    addr2 = _mac(buf[10:16])
    addr3 = _mac(buf[16:22])

    # Standard header is 24 bytes; QoS data adds 2 more
    hdr_len = 24
    if frame_subtype & 0x8:  # QoS data
        hdr_len += 2

    if not to_ds and not from_ds:
        dst_mac, src_mac = addr1, addr2
    elif to_ds and not from_ds:
        dst_mac, src_mac = addr3, addr2
    elif not to_ds and from_ds:
        dst_mac, src_mac = addr1, addr3
    else:
        # WDS (4-address): addr4 at offset 24 adds 6 bytes to header
        if len(buf) < 30:
            return None, "", "", None
        src_mac = _mac(buf[24:30])
        dst_mac = addr3
        hdr_len += 6

    payload = buf[hdr_len:]

    # LLC/SNAP header (8 bytes): DSAP(1) SSAP(1) Control(1) OUI(3) EtherType(2)
    if len(payload) < 8:
        return None, src_mac, dst_mac, None
    ethertype = struct.unpack_from(">H", payload, 6)[0]
    ip_data = payload[8:]

    # Only handle IPv4 (0x0800) and IPv6 (0x86DD)
    if ethertype not in (0x0800, 0x86DD):
        return None, src_mac, dst_mac, None

    return ip_data, src_mac, dst_mac, None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def parse_pcap(path: Path) -> Iterator[Flow]:
    """Yield Flow records from a pcap file.

    Handles both standard Ethernet (link type 1) and radiotap 802.11
    (link type 127) captures automatically.
    """
    with path.open("rb") as f:
        pcap = dpkt.pcap.Reader(f)
        link_type = pcap.datalink()

        for ts, buf in pcap:
            try:
                if link_type == dpkt.pcap.DLT_EN10MB:  # 1 = Ethernet
                    yield from _parse_ethernet_packet(ts, buf)
                elif link_type == 127:  # LINKTYPE_IEEE802_11_RADIOTAP
                    yield from _parse_radiotap_packet(ts, buf)
                # Other link types silently skipped
            except Exception:  # noqa: BLE001
                continue


def _parse_ethernet_packet(ts: float, buf: bytes) -> Iterator[Flow]:
    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except Exception:  # noqa: BLE001
        return
    if not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
        return
    ip = eth.data
    src_ip, dst_ip = _inet_ntop_pair(ip)
    proto_num = ip.p if isinstance(ip, dpkt.ip.IP) else ip.nxt
    src_mac = _mac(eth.src)
    dst_mac = _mac(eth.dst)

    flow = _ip_to_flow(ts, buf, ip, src_ip, dst_ip, proto_num, src_mac, dst_mac, None)
    if flow:
        yield flow


def _parse_radiotap_packet(ts: float, buf: bytes) -> Iterator[Flow]:
    hdr_len, signal_dbm = _parse_radiotap(buf)
    if hdr_len == 0 or hdr_len >= len(buf):
        return

    ip_payload, src_mac, dst_mac, _ = _parse_80211(buf[hdr_len:])
    if ip_payload is None:
        return

    try:
        if ip_payload and ip_payload[0] >> 4 == 6:
            ip: dpkt.ip.IP | dpkt.ip6.IP6 = dpkt.ip6.IP6(ip_payload)
        else:
            ip = dpkt.ip.IP(ip_payload)
    except Exception:  # noqa: BLE001
        return

    src_ip, dst_ip = _inet_ntop_pair(ip)
    proto_num = ip.p if isinstance(ip, dpkt.ip.IP) else ip.nxt

    flow = _ip_to_flow(ts, buf, ip, src_ip, dst_ip, proto_num, src_mac, dst_mac, signal_dbm)
    if flow:
        yield flow


def _inet_ntop_pair(ip: dpkt.ip.IP | dpkt.ip6.IP6) -> tuple[str, str]:
    af = socket.AF_INET if isinstance(ip, dpkt.ip.IP) else socket.AF_INET6
    return socket.inet_ntop(af, ip.src), socket.inet_ntop(af, ip.dst)


def _ip_to_flow(
    ts: float,
    buf: bytes,
    ip: dpkt.ip.IP | dpkt.ip6.IP6,
    src_ip: str,
    dst_ip: str,
    proto_num: int,
    src_mac: str,
    dst_mac: str,
    signal_dbm: int | None,
) -> Flow | None:
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
            except Exception:  # noqa: BLE001
                pass

    return Flow(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        proto=proto,
        src_mac=src_mac,
        dst_mac=dst_mac,
        first_ts=ts,
        last_ts=ts,
        bytes_total=len(buf),
        packets=1,
        tls_sni=sni,
        dns_query=dns_query,
        signal_dbm=signal_dbm,
    )
