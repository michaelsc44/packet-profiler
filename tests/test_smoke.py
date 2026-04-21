"""Basic smoke tests. Full integration tests require sample pcaps — see tests/README.md."""
from __future__ import annotations

import tempfile
from pathlib import Path

from profiler.parser import Flow
from profiler.storage import Storage


def test_storage_roundtrip() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        store = Storage(Path(tmp) / "test.duckdb")
        store.init_schema()
        store.insert_flows([
            Flow(src_ip="10.0.0.1", dst_ip="1.1.1.1", src_port=1234, dst_port=443,
                 proto="tcp", first_ts=1.0, last_ts=1.0, bytes_total=500, packets=1,
                 tls_sni="example.com"),
            Flow(src_ip="10.0.0.1", dst_ip="8.8.8.8", src_port=5353, dst_port=53,
                 proto="udp", first_ts=2.0, last_ts=2.0, bytes_total=80, packets=1,
                 dns_query="example.com"),
        ])
        result = store.conn.execute("SELECT count(*) FROM flows").fetchone()
        assert result is not None and result[0] == 2


def test_profile_build() -> None:
    from profiler.profiler import build_profiles
    with tempfile.TemporaryDirectory() as tmp:
        store = Storage(Path(tmp) / "test.duckdb")
        store.init_schema()
        store.insert_flows([
            Flow(src_ip="10.0.0.1", dst_ip="1.1.1.1", src_port=1234, dst_port=443,
                 proto="tcp", first_ts=1.0, last_ts=1.0, bytes_total=500, packets=1),
        ])
        build_profiles(store)
        talkers = store.top_talkers()
        assert len(talkers) == 1
        assert talkers[0]["client_ip"] == "10.0.0.1"
