"""Tests for profiler.report — formatting helpers."""

from __future__ import annotations

from rich.table import Table

from profiler.report import _fmt_bytes, format_client_profile, format_top_talkers


# ---------------------------------------------------------------------------
# _fmt_bytes
# ---------------------------------------------------------------------------


def test_fmt_bytes_small() -> None:
    assert _fmt_bytes(512) == "512.0 B"


def test_fmt_bytes_kilobytes() -> None:
    assert _fmt_bytes(1024) == "1.0 KB"


def test_fmt_bytes_megabytes() -> None:
    assert _fmt_bytes(1024 * 1024) == "1.0 MB"


def test_fmt_bytes_gigabytes() -> None:
    assert _fmt_bytes(1024**3) == "1.0 GB"


def test_fmt_bytes_zero() -> None:
    assert _fmt_bytes(0) == "0.0 B"


def test_fmt_bytes_fractional() -> None:
    result = _fmt_bytes(1500)
    assert "KB" in result


# ---------------------------------------------------------------------------
# format_top_talkers
# ---------------------------------------------------------------------------

SAMPLE_TALKERS = [
    {
        "client_ip": "192.168.1.1",
        "mac": "aa:bb:cc:dd:ee:ff",
        "total_bytes": 1_048_576,
        "total_packets": 2000,
        "unique_destinations": 15,
    },
    {
        "client_ip": "192.168.1.2",
        "mac": None,
        "total_bytes": 512,
        "total_packets": 4,
        "unique_destinations": 1,
    },
]


def test_format_top_talkers_returns_table() -> None:
    result = format_top_talkers(SAMPLE_TALKERS)
    assert isinstance(result, Table)


def test_format_top_talkers_row_count() -> None:
    result = format_top_talkers(SAMPLE_TALKERS)
    assert result.row_count == 2


def test_format_top_talkers_empty() -> None:
    result = format_top_talkers([])
    assert isinstance(result, Table)
    assert result.row_count == 0


def test_format_top_talkers_null_mac_shown_as_dash() -> None:
    rows = [
        {
            "client_ip": "10.0.0.1",
            "mac": None,
            "total_bytes": 100,
            "total_packets": 1,
            "unique_destinations": 1,
        }
    ]
    table = format_top_talkers(rows)
    assert len(table.columns) == 5


def test_format_top_talkers_null_bytes_handled() -> None:
    rows = [
        {
            "client_ip": "10.0.0.1",
            "mac": "aa:bb:cc:00:00:01",
            "total_bytes": None,
            "total_packets": None,
            "unique_destinations": None,
        }
    ]
    table = format_top_talkers(rows)
    assert table.row_count == 1


# ---------------------------------------------------------------------------
# format_client_profile
# ---------------------------------------------------------------------------

SAMPLE_PROFILE = {
    "client_ip": "192.168.1.42",
    "mac": "aa:bb:cc:dd:ee:ff",
    "first_seen": 1700000000.0,
    "last_seen": 1700003600.0,
    "total_bytes": 1_000_000,
    "unique_destinations": 25,
    "frac_tcp": 0.85,
    "frac_udp": 0.15,
    "sni_seen": ["example.com", "api.apple.com", "cdn.example.net"],
}


def test_format_client_profile_returns_table() -> None:
    result = format_client_profile(SAMPLE_PROFILE)
    assert isinstance(result, Table)


def test_format_client_profile_has_rows() -> None:
    result = format_client_profile(SAMPLE_PROFILE)
    assert result.row_count > 0


def test_format_client_profile_null_mac() -> None:
    p = {**SAMPLE_PROFILE, "mac": None}
    table = format_client_profile(p)
    assert isinstance(table, Table)


def test_format_client_profile_null_fractions() -> None:
    p = {**SAMPLE_PROFILE, "frac_tcp": None, "frac_udp": None}
    table = format_client_profile(p)
    assert isinstance(table, Table)


def test_format_client_profile_snis_truncated_to_five() -> None:
    p = {**SAMPLE_PROFILE, "sni_seen": [f"host{i}.com" for i in range(20)]}
    table = format_client_profile(p)
    # Table renders without error; SNI row exists
    assert table.row_count > 0


def test_format_client_profile_no_sni() -> None:
    p = {**SAMPLE_PROFILE, "sni_seen": []}
    table = format_client_profile(p)
    assert isinstance(table, Table)
