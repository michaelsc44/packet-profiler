"""Tests for profiler.ai_analysis — mocks the Anthropic client."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from profiler.ai_analysis import (
    _format_profile_prompt,
    analyze_client,
    analyze_all_clients,
    summarize_network,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_PROFILE: dict = {
    "client_ip": "192.168.1.42",
    "mac": "aa:bb:cc:dd:ee:ff",
    "vendor": "Apple, Inc.",
    "first_seen": 1700000000.0,
    "last_seen": 1700003600.0,
    "total_bytes": 1_000_000,
    "total_packets": 5000,
    "unique_destinations": 25,
    "unique_dst_ports": 8,
    "frac_tcp": 0.85,
    "frac_udp": 0.15,
    "signal_dbm": -65,
    "sni_seen": ["example.com", "api.apple.com"],
    "dns_seen": ["example.com", "connectivity-check.ubuntu.com"],
    "ja3_fingerprints": ["abc123def456"],
}

SAMPLE_FLOWS: list[dict] = [
    {
        "src_port": 54321,
        "dst_ip": "1.1.1.1",
        "dst_port": 443,
        "proto": "tcp",
        "bytes_total": 2000,
        "tls_sni": "example.com",
        "dns_query": None,
    },
    {
        "src_port": 12345,
        "dst_ip": "8.8.8.8",
        "dst_port": 53,
        "proto": "udp",
        "bytes_total": 100,
        "tls_sni": None,
        "dns_query": "example.com",
    },
]


def _make_mock_client(response_text: str = "## Analysis\n\nLooks fine.") -> MagicMock:
    """Return a mocked anthropic.Anthropic client that returns *response_text*."""
    mock_content = MagicMock()
    mock_content.text = response_text

    mock_response = MagicMock()
    mock_response.content = [mock_content]

    mock_messages = MagicMock()
    mock_messages.create.return_value = mock_response

    mock_client = MagicMock()
    mock_client.messages = mock_messages
    return mock_client


# ---------------------------------------------------------------------------
# _format_profile_prompt
# ---------------------------------------------------------------------------


def test_format_profile_prompt_contains_ip() -> None:
    prompt = _format_profile_prompt(SAMPLE_PROFILE, [])
    assert "192.168.1.42" in prompt


def test_format_profile_prompt_contains_mac() -> None:
    prompt = _format_profile_prompt(SAMPLE_PROFILE, [])
    assert "aa:bb:cc:dd:ee:ff" in prompt


def test_format_profile_prompt_contains_vendor() -> None:
    prompt = _format_profile_prompt(SAMPLE_PROFILE, [])
    assert "Apple, Inc." in prompt


def test_format_profile_prompt_includes_sni() -> None:
    prompt = _format_profile_prompt(SAMPLE_PROFILE, [])
    assert "example.com" in prompt
    assert "api.apple.com" in prompt


def test_format_profile_prompt_includes_dns() -> None:
    prompt = _format_profile_prompt(SAMPLE_PROFILE, [])
    assert "connectivity-check.ubuntu.com" in prompt


def test_format_profile_prompt_includes_signal() -> None:
    prompt = _format_profile_prompt(SAMPLE_PROFILE, [])
    assert "-65" in prompt


def test_format_profile_prompt_flows_table() -> None:
    prompt = _format_profile_prompt(SAMPLE_PROFILE, SAMPLE_FLOWS)
    assert "Recent flows" in prompt
    assert "dst_ip" in prompt
    assert "1.1.1.1" in prompt


def test_format_profile_prompt_empty_profile() -> None:
    prompt = _format_profile_prompt({}, [])
    assert "unknown" in prompt


# ---------------------------------------------------------------------------
# _get_client — error conditions
# ---------------------------------------------------------------------------


def test_get_client_raises_without_api_key() -> None:
    with patch.dict(os.environ, {}, clear=True):
        os.environ.pop("ANTHROPIC_API_KEY", None)
        with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
            from profiler.ai_analysis import _get_client

            _get_client()


# ---------------------------------------------------------------------------
# analyze_client
# ---------------------------------------------------------------------------


def test_analyze_client_returns_string() -> None:
    mock_client = _make_mock_client("## Analysis\n\nThis is a MacBook.")
    with (
        patch("profiler.ai_analysis._get_client", return_value=mock_client),
        patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test-key"}),
    ):
        result = analyze_client(SAMPLE_PROFILE, SAMPLE_FLOWS)
    assert isinstance(result, str)
    assert "MacBook" in result


def test_analyze_client_passes_system_prompt() -> None:
    mock_client = _make_mock_client()
    with (
        patch("profiler.ai_analysis._get_client", return_value=mock_client),
        patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test-key"}),
    ):
        analyze_client(SAMPLE_PROFILE)
    call_kwargs = mock_client.messages.create.call_args
    # system is passed as keyword arg in our implementation
    assert call_kwargs.kwargs["system"][0]["cache_control"] == {"type": "ephemeral"}


def test_analyze_client_uses_correct_model() -> None:
    mock_client = _make_mock_client()
    with (
        patch("profiler.ai_analysis._get_client", return_value=mock_client),
        patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test-key"}),
    ):
        analyze_client(SAMPLE_PROFILE)
    model = mock_client.messages.create.call_args.kwargs["model"]
    assert model.startswith("claude-")


def test_analyze_client_no_flows() -> None:
    mock_client = _make_mock_client("No flows provided.")
    with (
        patch("profiler.ai_analysis._get_client", return_value=mock_client),
        patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test-key"}),
    ):
        result = analyze_client(SAMPLE_PROFILE)
    assert isinstance(result, str)


# ---------------------------------------------------------------------------
# analyze_all_clients
# ---------------------------------------------------------------------------


def _make_storage_mock(profiles: list[dict], flows: list[dict] | None = None) -> MagicMock:
    store = MagicMock()
    store.get_all_profiles.return_value = profiles
    store.get_recent_flows.return_value = flows or []
    return store


def test_analyze_all_clients_returns_dict() -> None:
    store = _make_storage_mock([SAMPLE_PROFILE])
    mock_client = _make_mock_client("Analysis text.")
    with (
        patch("profiler.ai_analysis._get_client", return_value=mock_client),
        patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test-key"}),
    ):
        results = analyze_all_clients(store)
    assert "192.168.1.42" in results
    assert results["192.168.1.42"] == "Analysis text."


def test_analyze_all_clients_saves_files() -> None:
    store = _make_storage_mock([SAMPLE_PROFILE])
    mock_client = _make_mock_client("File content.")
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp)
        with (
            patch("profiler.ai_analysis._get_client", return_value=mock_client),
            patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test-key"}),
        ):
            analyze_all_clients(store, output_dir=out)
        saved = list(out.glob("*.md"))
        assert len(saved) == 1
        assert saved[0].read_text() == "File content."


def test_analyze_all_clients_multiple_clients() -> None:
    profiles = [
        {**SAMPLE_PROFILE, "client_ip": "10.0.0.1"},
        {**SAMPLE_PROFILE, "client_ip": "10.0.0.2"},
    ]
    store = _make_storage_mock(profiles)
    call_count = 0

    def fake_get_client() -> MagicMock:
        nonlocal call_count
        return _make_mock_client(f"Analysis {call_count}")

    with (
        patch("profiler.ai_analysis._get_client", side_effect=fake_get_client),
        patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test-key"}),
    ):
        results = analyze_all_clients(store)
    assert set(results.keys()) == {"10.0.0.1", "10.0.0.2"}


# ---------------------------------------------------------------------------
# summarize_network
# ---------------------------------------------------------------------------


def test_summarize_network_returns_string() -> None:
    mock_client = _make_mock_client("## Network Summary\n\n3 devices found.")
    with (
        patch("profiler.ai_analysis._get_client", return_value=mock_client),
        patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test-key"}),
    ):
        result = summarize_network([SAMPLE_PROFILE])
    assert "Network Summary" in result


def test_summarize_network_all_profiles_in_prompt() -> None:
    profiles = [
        {**SAMPLE_PROFILE, "client_ip": "10.0.0.1"},
        {**SAMPLE_PROFILE, "client_ip": "10.0.0.2"},
    ]
    mock_client = _make_mock_client("Summary.")
    with (
        patch("profiler.ai_analysis._get_client", return_value=mock_client),
        patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test-key"}),
    ):
        summarize_network(profiles)
    user_content = mock_client.messages.create.call_args.kwargs["messages"][0]["content"]
    assert "10.0.0.1" in user_content
    assert "10.0.0.2" in user_content


def test_summarize_network_uses_higher_max_tokens() -> None:
    mock_client = _make_mock_client("Summary.")
    with (
        patch("profiler.ai_analysis._get_client", return_value=mock_client),
        patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test-key"}),
    ):
        summarize_network([SAMPLE_PROFILE])
    max_tokens = mock_client.messages.create.call_args.kwargs["max_tokens"]
    assert max_tokens >= 1024  # network summary should allow more tokens than per-client
