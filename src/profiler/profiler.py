"""Aggregate stored flows into per-client profiles."""
from __future__ import annotations

from .storage import Storage


def build_profiles(store: Storage) -> None:
    """(Re)build the profiles table from the current flows table.

    Kept simple: one SQL pass per metric. For larger deployments, switch to
    incremental updates keyed on (client_ip, hour_bucket).
    """
    store.execute("""
        CREATE OR REPLACE TABLE profiles AS
        SELECT
            src_ip                                 AS client_ip,
            any_value(src_mac)                     AS mac,
            min(first_ts)                          AS first_seen,
            max(last_ts)                           AS last_seen,
            sum(bytes_total)                       AS total_bytes,
            sum(packets)                           AS total_packets,
            count(DISTINCT dst_ip)                 AS unique_destinations,
            count(DISTINCT dst_port)               AS unique_dst_ports,
            sum(CASE WHEN proto='tcp'   THEN bytes_total ELSE 0 END)::DOUBLE
                / NULLIF(sum(bytes_total), 0)      AS frac_tcp,
            sum(CASE WHEN proto='udp'   THEN bytes_total ELSE 0 END)::DOUBLE
                / NULLIF(sum(bytes_total), 0)      AS frac_udp,
            list(DISTINCT tls_sni) FILTER (WHERE tls_sni IS NOT NULL)
                                                   AS sni_seen,
            list(DISTINCT dns_query) FILTER (WHERE dns_query IS NOT NULL)
                                                   AS dns_seen
        FROM flows
        GROUP BY src_ip
    """)
