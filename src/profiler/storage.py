"""DuckDB-backed storage for flows and profiles."""
from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Any

import duckdb

from .parser import Flow


class Storage:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.conn = duckdb.connect(str(db_path))

    def execute(self, sql: str, params: tuple[Any, ...] | None = None) -> duckdb.DuckDBPyRelation:
        return self.conn.execute(sql, params) if params else self.conn.execute(sql)

    def init_schema(self) -> None:
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS flows (
                src_ip       VARCHAR,
                dst_ip       VARCHAR,
                src_port     INTEGER,
                dst_port     INTEGER,
                proto        VARCHAR,
                src_mac      VARCHAR,
                dst_mac      VARCHAR,
                first_ts     DOUBLE,
                last_ts      DOUBLE,
                bytes_total  BIGINT,
                packets      BIGINT,
                tls_sni      VARCHAR,
                dns_query    VARCHAR
            );
            CREATE INDEX IF NOT EXISTS idx_flows_src ON flows(src_ip);
            CREATE INDEX IF NOT EXISTS idx_flows_ts  ON flows(first_ts);
        """)

    def insert_flows(self, flows: Iterable[Flow]) -> None:
        rows = [
            (f.src_ip, f.dst_ip, f.src_port, f.dst_port, f.proto,
             f.src_mac, f.dst_mac, f.first_ts, f.last_ts,
             f.bytes_total, f.packets, f.tls_sni, f.dns_query)
            for f in flows
        ]
        if not rows:
            return
        self.conn.executemany(
            "INSERT INTO flows VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )

    def top_talkers(self, limit: int = 10) -> list[dict[str, Any]]:
        result = self.conn.execute(f"""
            SELECT client_ip, mac, total_bytes, total_packets, unique_destinations
            FROM profiles
            ORDER BY total_bytes DESC
            LIMIT {int(limit)}
        """).fetchall()
        cols = ["client_ip", "mac", "total_bytes", "total_packets", "unique_destinations"]
        return [dict(zip(cols, row, strict=True)) for row in result]

    def get_profile(self, client_ip: str) -> dict[str, Any] | None:
        result = self.conn.execute(
            "SELECT * FROM profiles WHERE client_ip = ?", (client_ip,)
        ).fetchone()
        if result is None:
            return None
        cols = [d[0] for d in self.conn.description]
        return dict(zip(cols, result, strict=True))
