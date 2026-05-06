"""Basic smoke tests. Full integration tests require sample pcaps — see tests/README.md."""

from __future__ import annotations

import io
import tempfile
from pathlib import Path
from unittest.mock import patch

import dpkt
from click.testing import CliRunner

from profiler.cli import main
from profiler.parser import Flow
from profiler.storage import Storage


def test_storage_roundtrip() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        store = Storage(Path(tmp) / "test.duckdb")
        store.init_schema()
        store.insert_flows(
            [
                Flow(
                    src_ip="10.0.0.1",
                    dst_ip="1.1.1.1",
                    src_port=1234,
                    dst_port=443,
                    proto="tcp",
                    first_ts=1.0,
                    last_ts=1.0,
                    bytes_total=500,
                    packets=1,
                    tls_sni="example.com",
                ),
                Flow(
                    src_ip="10.0.0.1",
                    dst_ip="8.8.8.8",
                    src_port=5353,
                    dst_port=53,
                    proto="udp",
                    first_ts=2.0,
                    last_ts=2.0,
                    bytes_total=80,
                    packets=1,
                    dns_query="example.com",
                ),
            ]
        )
        result = store.conn.execute("SELECT count(*) FROM flows").fetchone()
        assert result is not None and result[0] == 2


def test_profile_build() -> None:
    from profiler.profiler import build_profiles

    with tempfile.TemporaryDirectory() as tmp:
        store = Storage(Path(tmp) / "test.duckdb")
        store.init_schema()
        store.insert_flows(
            [
                Flow(
                    src_ip="10.0.0.1",
                    dst_ip="1.1.1.1",
                    src_port=1234,
                    dst_port=443,
                    proto="tcp",
                    first_ts=1.0,
                    last_ts=1.0,
                    bytes_total=500,
                    packets=1,
                ),
            ]
        )
        build_profiles(store)
        talkers = store.top_talkers()
        assert len(talkers) == 1
        assert talkers[0]["client_ip"] == "10.0.0.1"


# ---------------------------------------------------------------------------
# CLI smoke tests
# ---------------------------------------------------------------------------


def _make_test_pcap(tmp: str) -> Path:
    """Write a minimal Ethernet+TCP pcap for CLI testing."""
    import socket

    tcp = dpkt.tcp.TCP(sport=54321, dport=443, data=b"")
    ip = dpkt.ip.IP(
        src=socket.inet_aton("10.0.0.1"), dst=socket.inet_aton("1.1.1.1"), p=6, data=tcp
    )
    ip.len = len(ip)
    eth = dpkt.ethernet.Ethernet(
        src=b"\xaa\xbb\xcc\xdd\xee\xff", dst=b"\x11\x22\x33\x44\x55\x66", data=ip
    )

    buf = io.BytesIO()
    writer = dpkt.pcap.Writer(buf)
    writer.writepkt(bytes(eth), ts=1700000000.0)
    buf.seek(0)

    pcap_path = Path(tmp) / "test.pcap"
    pcap_path.write_bytes(buf.read())
    return pcap_path


def test_cli_version() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output


def test_cli_help() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "capture" in result.output
    assert "analyze" in result.output
    assert "report" in result.output


def test_cli_analyze_creates_db_and_flows() -> None:
    runner = CliRunner()
    with tempfile.TemporaryDirectory() as tmp:
        pcap = _make_test_pcap(tmp)
        db = str(Path(tmp) / "profiles.duckdb")
        result = runner.invoke(main, ["analyze", "--db", db, str(pcap)])
        assert result.exit_code == 0, result.output
        assert "1 flows" in result.output

        store = Storage(Path(db))
        count = store.conn.execute("SELECT count(*) FROM flows").fetchone()
        assert count is not None and count[0] == 1


def test_cli_analyze_builds_profiles() -> None:
    runner = CliRunner()
    with tempfile.TemporaryDirectory() as tmp:
        pcap = _make_test_pcap(tmp)
        db = str(Path(tmp) / "profiles.duckdb")
        runner.invoke(main, ["analyze", "--db", db, str(pcap)])

        store = Storage(Path(db))
        talkers = store.top_talkers()
        assert len(talkers) == 1
        assert talkers[0]["client_ip"] == "10.0.0.1"


def test_cli_report_missing_db_exits_nonzero() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["report", "--db", "/no/such/file.duckdb"])
    assert result.exit_code != 0
    assert "not found" in result.output


def test_cli_report_top_talkers() -> None:
    runner = CliRunner()
    with tempfile.TemporaryDirectory() as tmp:
        pcap = _make_test_pcap(tmp)
        db = str(Path(tmp) / "profiles.duckdb")
        runner.invoke(main, ["analyze", "--db", db, str(pcap)])

        result = runner.invoke(main, ["report", "--db", db])
        assert result.exit_code == 0, result.output
        assert "10.0.0.1" in result.output


def test_cli_report_json_output() -> None:
    runner = CliRunner()
    import json

    with tempfile.TemporaryDirectory() as tmp:
        pcap = _make_test_pcap(tmp)
        db = str(Path(tmp) / "profiles.duckdb")
        runner.invoke(main, ["analyze", "--db", db, str(pcap)])

        result = runner.invoke(main, ["report", "--db", db, "--json"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert data[0]["client_ip"] == "10.0.0.1"


def test_cli_report_client_profile() -> None:
    runner = CliRunner()
    with tempfile.TemporaryDirectory() as tmp:
        pcap = _make_test_pcap(tmp)
        db = str(Path(tmp) / "profiles.duckdb")
        runner.invoke(main, ["analyze", "--db", db, str(pcap)])

        result = runner.invoke(main, ["report", "--db", db, "--client", "10.0.0.1"])
        assert result.exit_code == 0, result.output
        assert "10.0.0.1" in result.output


def test_cli_report_missing_client_exits_nonzero() -> None:
    runner = CliRunner()
    with tempfile.TemporaryDirectory() as tmp:
        pcap = _make_test_pcap(tmp)
        db = str(Path(tmp) / "profiles.duckdb")
        runner.invoke(main, ["analyze", "--db", db, str(pcap)])

        result = runner.invoke(main, ["report", "--db", db, "--client", "99.99.99.99"])
        assert result.exit_code != 0
        assert "no profile" in result.output


def test_cli_wifi_list_interfaces_no_iw() -> None:
    runner = CliRunner()
    with patch("shutil.which", return_value=None):
        result = runner.invoke(main, ["wifi", "list-interfaces"])
    assert result.exit_code == 0
    assert "No wireless interfaces" in result.output


def test_cli_capture_no_tcpdump_exits_nonzero() -> None:
    runner = CliRunner()
    with patch("shutil.which", return_value=None):
        result = runner.invoke(main, ["capture", "-i", "eth0"])
    assert result.exit_code != 0
    assert "tcpdump" in result.output
