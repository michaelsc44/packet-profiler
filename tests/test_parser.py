"""Tests for profiler.parser — uses dpkt to build synthetic pcap fixtures."""

from __future__ import annotations

import io
import struct
import tempfile
from pathlib import Path

import dpkt
import pytest

from profiler.parser import (
    _extract_sni,
    _mac,
    _parse_80211,
    _parse_radiotap,
    _proto_name,
    parse_pcap,
)


# ---------------------------------------------------------------------------
# Pcap fixture helpers
# ---------------------------------------------------------------------------


def _write_pcap(pkts: list[tuple[bytes, float]], link_type: int = dpkt.pcap.DLT_EN10MB) -> Path:
    """Write packets to a temporary pcap file and return its path."""
    buf = io.BytesIO()
    writer = dpkt.pcap.Writer(buf, linktype=link_type)
    for data, ts in pkts:
        writer.writepkt(data, ts=ts)
    buf.seek(0)

    tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    tmp.write(buf.read())
    tmp.close()
    return Path(tmp.name)


def _eth_tcp(
    src_ip: str = "10.0.0.1",
    dst_ip: str = "1.1.1.1",
    sport: int = 54321,
    dport: int = 80,
    payload: bytes = b"",
    src_mac: bytes = b"\xaa\xbb\xcc\xdd\xee\xff",
    dst_mac: bytes = b"\x11\x22\x33\x44\x55\x66",
) -> bytes:
    import socket

    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, data=payload)
    ip = dpkt.ip.IP(
        src=socket.inet_aton(src_ip),
        dst=socket.inet_aton(dst_ip),
        p=6,
        data=tcp,
    )
    ip.len = len(ip)
    eth = dpkt.ethernet.Ethernet(src=src_mac, dst=dst_mac, data=ip)
    return bytes(eth)


def _eth_udp(
    src_ip: str = "10.0.0.1",
    dst_ip: str = "8.8.8.8",
    sport: int = 12345,
    dport: int = 53,
    payload: bytes = b"",
) -> bytes:
    import socket

    udp = dpkt.udp.UDP(sport=sport, dport=dport, data=payload)
    udp.ulen = 8 + len(payload)
    ip = dpkt.ip.IP(
        src=socket.inet_aton(src_ip),
        dst=socket.inet_aton(dst_ip),
        p=17,
        data=udp,
    )
    ip.len = len(ip)
    eth = dpkt.ethernet.Ethernet(
        src=b"\xaa\xbb\xcc\xdd\xee\xff",
        dst=b"\x11\x22\x33\x44\x55\x66",
        data=ip,
    )
    return bytes(eth)


def _make_tls_client_hello(sni: str) -> bytes:
    """Build a minimal TLS ClientHello record with the given SNI."""
    sni_bytes = sni.encode("ascii")
    sni_len = len(sni_bytes)

    # SNI extension value: ServerNameList
    sni_list = (
        b"\x00"  # name_type: host_name
        + struct.pack(">H", sni_len)
        + sni_bytes
    )
    sni_ext_value = struct.pack(">H", len(sni_list)) + sni_list

    sni_extension = (
        b"\x00\x00"  # extension type: server_name
        + struct.pack(">H", len(sni_ext_value))
        + sni_ext_value
    )

    extensions_block = struct.pack(">H", len(sni_extension)) + sni_extension

    client_hello_body = (
        b"\x03\x03"  # TLS 1.2
        + b"\x00" * 32  # random
        + b"\x00"  # session_id length = 0
        + b"\x00\x02"  # cipher_suites length = 2
        + b"\xc0\x2b"  # one cipher suite
        + b"\x01"  # compression_methods length = 1
        + b"\x00"  # null compression
        + extensions_block
    )

    handshake = (
        b"\x01"  # type: ClientHello
        + struct.pack(">I", len(client_hello_body))[1:]  # 3-byte length
        + client_hello_body
    )

    return (
        b"\x16"  # TLS handshake record type
        + b"\x03\x01"  # TLS 1.0 record version
        + struct.pack(">H", len(handshake))
        + handshake
    )


def _make_dns_query(name: str, qtype: int = 1) -> bytes:
    """Build a minimal DNS query packet payload."""
    labels = b""
    for part in name.split("."):
        enc = part.encode()
        labels += bytes([len(enc)]) + enc
    labels += b"\x00"

    return (
        b"\x00\x01"  # transaction ID
        + b"\x01\x00"  # flags: standard query
        + b"\x00\x01"  # QDCOUNT = 1
        + b"\x00\x00"  # ANCOUNT = 0
        + b"\x00\x00"  # NSCOUNT = 0
        + b"\x00\x00"  # ARCOUNT = 0
        + labels
        + struct.pack(">HH", qtype, 1)  # QTYPE, QCLASS
    )


# ---------------------------------------------------------------------------
# _mac
# ---------------------------------------------------------------------------


def test_mac_formats_correctly() -> None:
    assert _mac(b"\xaa\xbb\xcc\xdd\xee\xff") == "aa:bb:cc:dd:ee:ff"


def test_mac_zero() -> None:
    assert _mac(b"\x00\x00\x00\x00\x00\x00") == "00:00:00:00:00:00"


# ---------------------------------------------------------------------------
# _proto_name
# ---------------------------------------------------------------------------


def test_proto_name_known() -> None:
    assert _proto_name(6) == "tcp"
    assert _proto_name(17) == "udp"
    assert _proto_name(1) == "icmp"


def test_proto_name_unknown() -> None:
    assert _proto_name(999) == "other"


# ---------------------------------------------------------------------------
# _extract_sni
# ---------------------------------------------------------------------------


def test_extract_sni_valid_hello() -> None:
    record = _make_tls_client_hello("example.com")
    assert _extract_sni(record) == "example.com"


def test_extract_sni_longer_hostname() -> None:
    record = _make_tls_client_hello("api.internal.corp.example.com")
    assert _extract_sni(record) == "api.internal.corp.example.com"


def test_extract_sni_not_tls_returns_none() -> None:
    assert _extract_sni(b"GET / HTTP/1.1\r\nHost: example.com\r\n") is None


def test_extract_sni_too_short_returns_none() -> None:
    assert _extract_sni(b"\x16\x03") is None


def test_extract_sni_empty_returns_none() -> None:
    assert _extract_sni(b"") is None


def test_extract_sni_garbage_returns_none() -> None:
    assert _extract_sni(b"\x00" * 100) is None


# ---------------------------------------------------------------------------
# parse_pcap — Ethernet flows
# ---------------------------------------------------------------------------


def test_parse_empty_pcap() -> None:
    path = _write_pcap([])
    assert list(parse_pcap(path)) == []


def test_parse_basic_tcp_flow() -> None:
    pkt = _eth_tcp(src_ip="10.0.0.1", dst_ip="1.1.1.1", sport=54321, dport=80)
    path = _write_pcap([(pkt, 1700000000.0)])
    flows = list(parse_pcap(path))
    assert len(flows) == 1
    f = flows[0]
    assert f.src_ip == "10.0.0.1"
    assert f.dst_ip == "1.1.1.1"
    assert f.src_port == 54321
    assert f.dst_port == 80
    assert f.proto == "tcp"
    assert f.first_ts == pytest.approx(1700000000.0)
    assert f.packets == 1


def test_parse_tcp_flow_macs() -> None:
    pkt = _eth_tcp(
        src_mac=b"\xaa\xbb\xcc\xdd\xee\xff",
        dst_mac=b"\x11\x22\x33\x44\x55\x66",
    )
    path = _write_pcap([(pkt, 1.0)])
    flows = list(parse_pcap(path))
    assert flows[0].src_mac == "aa:bb:cc:dd:ee:ff"
    assert flows[0].dst_mac == "11:22:33:44:55:66"


def test_parse_tls_sni_extracted() -> None:
    tls_hello = _make_tls_client_hello("secure.example.com")
    pkt = _eth_tcp(dport=443, payload=tls_hello)
    path = _write_pcap([(pkt, 1.0)])
    flows = list(parse_pcap(path))
    assert flows[0].tls_sni == "secure.example.com"


def test_parse_no_sni_for_non_443() -> None:
    tls_hello = _make_tls_client_hello("internal.host")
    pkt = _eth_tcp(dport=8443, payload=tls_hello)
    path = _write_pcap([(pkt, 1.0)])
    flows = list(parse_pcap(path))
    assert flows[0].tls_sni is None


def test_parse_dns_query_extracted() -> None:
    dns_payload = _make_dns_query("example.com")
    pkt = _eth_udp(dport=53, payload=dns_payload)
    path = _write_pcap([(pkt, 1.0)])
    flows = list(parse_pcap(path))
    assert len(flows) == 1
    assert flows[0].dns_query == "example.com"
    assert flows[0].proto == "udp"


def test_parse_udp_non_dns_no_query() -> None:
    pkt = _eth_udp(dport=5353, payload=b"\x00" * 20)
    path = _write_pcap([(pkt, 1.0)])
    flows = list(parse_pcap(path))
    assert flows[0].dns_query is None


def test_parse_multiple_packets() -> None:
    pkts = [
        (_eth_tcp(src_ip="10.0.0.1", dport=80), 1.0),
        (_eth_tcp(src_ip="10.0.0.2", dport=443), 2.0),
        (_eth_udp(src_ip="10.0.0.3", dport=53), 3.0),
    ]
    path = _write_pcap(pkts)
    flows = list(parse_pcap(path))
    assert len(flows) == 3
    ips = {f.src_ip for f in flows}
    assert ips == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}


def test_parse_bytes_total_recorded() -> None:
    payload = b"X" * 100
    pkt = _eth_tcp(payload=payload)
    path = _write_pcap([(pkt, 1.0)])
    flows = list(parse_pcap(path))
    assert flows[0].bytes_total == len(pkt)


def test_parse_malformed_packet_skipped() -> None:
    """Garbage bytes in a pcap should be silently dropped."""
    good = _eth_tcp()
    # Build pcap manually with a bad packet injected
    buf = io.BytesIO()
    writer = dpkt.pcap.Writer(buf)
    writer.writepkt(good, ts=1.0)
    writer.writepkt(b"\xff\xff\xff\xff\xff\xff", ts=2.0)  # malformed
    writer.writepkt(good, ts=3.0)
    buf.seek(0)

    tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    tmp.write(buf.read())
    tmp.close()

    flows = list(parse_pcap(Path(tmp.name)))
    # The two good packets parse; the malformed one is dropped
    assert len(flows) == 2


# ---------------------------------------------------------------------------
# _parse_radiotap
# ---------------------------------------------------------------------------


def _make_radiotap(signal_dbm: int | None = None) -> bytes:
    """Build a minimal radiotap header with optional RSSI field."""
    if signal_dbm is None:
        present = 0
        fields = b""
    else:
        # Set bit 5 (dBm Antenna Signal) in present flags.
        # Fields before RSSI (bits 0-4): TSFT, Flags, Rate, Channel, FHSS — all absent.
        present = 1 << 5
        fields = struct.pack("b", signal_dbm)

    hdr_len = 8 + len(fields)
    header = struct.pack("<BBH", 0, 0, hdr_len) + struct.pack("<I", present) + fields
    return header


def test_parse_radiotap_no_signal() -> None:
    hdr = _make_radiotap(signal_dbm=None)
    hdr_len, signal = _parse_radiotap(hdr)
    assert hdr_len == 8
    assert signal is None


def test_parse_radiotap_with_signal() -> None:
    hdr = _make_radiotap(signal_dbm=-70)
    hdr_len, signal = _parse_radiotap(hdr)
    assert hdr_len == 9
    assert signal == -70


def test_parse_radiotap_too_short() -> None:
    hdr_len, signal = _parse_radiotap(b"\x00\x00")
    assert hdr_len == 0
    assert signal is None


# ---------------------------------------------------------------------------
# _parse_80211
# ---------------------------------------------------------------------------


def _make_80211_data_frame(
    to_ds: int,
    from_ds: int,
    src_mac: bytes = b"\xaa\xbb\xcc\xdd\xee\xff",
    dst_mac: bytes = b"\x11\x22\x33\x44\x55\x66",
    bssid: bytes = b"\x00\x11\x22\x33\x44\x55",
    payload: bytes = b"",
    qos: bool = False,
) -> bytes:
    """Build a minimal 802.11 data frame with the given DS bits."""
    frame_subtype = 0x8 if qos else 0x0
    frame_type = 2  # data
    fc = (frame_subtype << 4) | (frame_type << 2)
    # DS bits are in the high byte of FC: to_ds=bit0, from_ds=bit1
    fc_high = (from_ds << 1) | to_ds
    fc_bytes = struct.pack("<BB", fc, fc_high)

    duration = b"\x00\x00"
    seq_ctrl = b"\x00\x00"

    # Address layout per DS bits
    if not to_ds and not from_ds:
        addr1, addr2, addr3 = dst_mac, src_mac, bssid
    elif to_ds and not from_ds:
        addr1, addr2, addr3 = bssid, src_mac, dst_mac
    elif not to_ds and from_ds:
        addr1, addr2, addr3 = dst_mac, bssid, src_mac
    else:
        # WDS: addr1=RA, addr2=TA, addr3=DA, addr4=SA
        addr1, addr2, addr3 = bssid, bssid, dst_mac
        addr4 = src_mac
        hdr = fc_bytes + duration + addr1 + addr2 + addr3 + seq_ctrl + addr4
        if qos:
            hdr += b"\x00\x00"
        return hdr + payload

    hdr = fc_bytes + duration + addr1 + addr2 + addr3 + seq_ctrl
    if qos:
        hdr += b"\x00\x00"
    return hdr + payload


def _llc_ip4(ip_payload: bytes) -> bytes:
    """Wrap IP payload in LLC/SNAP with EtherType 0x0800."""
    return b"\xaa\xaa\x03\x00\x00\x00\x08\x00" + ip_payload


def _minimal_ipv4(src: str = "10.0.0.1", dst: str = "8.8.8.8") -> bytes:
    import socket

    tcp = dpkt.tcp.TCP(sport=12345, dport=80, data=b"")
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst), p=6, data=tcp)
    ip.len = len(ip)
    return bytes(ip)


def test_parse_80211_ibss_frame() -> None:
    """to_ds=0, from_ds=0: IBSS or direct station-to-station."""
    ip = _minimal_ipv4("10.0.0.1", "10.0.0.2")
    llc = _llc_ip4(ip)
    frame = _make_80211_data_frame(
        to_ds=0,
        from_ds=0,
        src_mac=b"\xaa\xbb\xcc\xdd\xee\xff",
        dst_mac=b"\x11\x22\x33\x44\x55\x66",
        payload=llc,
    )
    ip_data, src_mac, dst_mac, _ = _parse_80211(frame)
    assert ip_data is not None
    assert src_mac == "aa:bb:cc:dd:ee:ff"
    assert dst_mac == "11:22:33:44:55:66"


def test_parse_80211_to_ap_frame() -> None:
    """to_ds=1, from_ds=0: station → AP."""
    ip = _minimal_ipv4()
    llc = _llc_ip4(ip)
    frame = _make_80211_data_frame(
        to_ds=1,
        from_ds=0,
        src_mac=b"\xaa\xbb\xcc\xdd\xee\xff",
        dst_mac=b"\x11\x22\x33\x44\x55\x66",
        payload=llc,
    )
    ip_data, src_mac, dst_mac, _ = _parse_80211(frame)
    assert ip_data is not None
    assert src_mac == "aa:bb:cc:dd:ee:ff"
    assert dst_mac == "11:22:33:44:55:66"


def test_parse_80211_from_ap_frame() -> None:
    """to_ds=0, from_ds=1: AP → station."""
    ip = _minimal_ipv4()
    llc = _llc_ip4(ip)
    frame = _make_80211_data_frame(
        to_ds=0,
        from_ds=1,
        src_mac=b"\xaa\xbb\xcc\xdd\xee\xff",
        dst_mac=b"\x11\x22\x33\x44\x55\x66",
        payload=llc,
    )
    ip_data, src_mac, dst_mac, _ = _parse_80211(frame)
    assert ip_data is not None
    assert src_mac == "aa:bb:cc:dd:ee:ff"
    assert dst_mac == "11:22:33:44:55:66"


def test_parse_80211_wds_frame() -> None:
    """to_ds=1, from_ds=1: WDS 4-address frame — tests the bug fix."""
    ip = _minimal_ipv4("10.0.0.5", "10.0.0.6")
    llc = _llc_ip4(ip)
    frame = _make_80211_data_frame(
        to_ds=1,
        from_ds=1,
        src_mac=b"\xaa\xbb\xcc\xdd\xee\xff",
        dst_mac=b"\x11\x22\x33\x44\x55\x66",
        payload=llc,
    )
    ip_data, src_mac, dst_mac, _ = _parse_80211(frame)
    # WDS frames should parse the IP payload correctly
    assert ip_data is not None
    assert len(ip_data) > 0
    # IP version should be 4
    assert ip_data[0] >> 4 == 4


def test_parse_80211_too_short() -> None:
    assert _parse_80211(b"\x00" * 10) == (None, "", "", None)


def test_parse_80211_management_frame_skipped() -> None:
    """Management frames (type != 2) should return None."""
    # FC with frame type = 0 (management)
    fc = struct.pack("<H", 0x0080)  # Beacon frame
    buf = fc + b"\x00" * 30
    ip_data, _, _, _ = _parse_80211(buf)
    assert ip_data is None


def test_parse_80211_non_ip_ethertype_skipped() -> None:
    """Non-IP LLC/SNAP payloads should return None for ip_data."""
    # LLC/SNAP with ARP EtherType 0x0806
    arp_llc = b"\xaa\xaa\x03\x00\x00\x00\x08\x06" + b"\x00" * 20
    frame = _make_80211_data_frame(to_ds=0, from_ds=0, payload=arp_llc)
    ip_data, _, _, _ = _parse_80211(frame)
    assert ip_data is None
