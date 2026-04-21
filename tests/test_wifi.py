"""Tests for profiler.wifi — mocks all subprocess calls."""

from __future__ import annotations

import threading
from unittest.mock import MagicMock, patch

import pytest

from profiler.wifi import (
    MonitorContext,
    channel_hop,
    disable_monitor_mode,
    enable_monitor_mode,
    list_wifi_interfaces,
    set_channel,
)


# ---------------------------------------------------------------------------
# list_wifi_interfaces
# ---------------------------------------------------------------------------


def test_list_wifi_interfaces_no_iw() -> None:
    with patch("shutil.which", return_value=None):
        assert list_wifi_interfaces() == []


def test_list_wifi_interfaces_parses_output() -> None:
    iw_output = (
        "phy#0\n"
        "\tInterface wlan0\n"
        "\t\tifindex 3\n"
        "\t\ttype managed\n"
        "phy#1\n"
        "\tInterface wlan1\n"
        "\t\tifindex 4\n"
        "\t\ttype managed\n"
    )
    with (
        patch("shutil.which", return_value="/usr/bin/iw"),
        patch("subprocess.check_output", return_value=iw_output),
    ):
        result = list_wifi_interfaces()
    assert result == ["wlan0", "wlan1"]


def test_list_wifi_interfaces_subprocess_error() -> None:
    import subprocess

    with (
        patch("shutil.which", return_value="/usr/bin/iw"),
        patch("subprocess.check_output", side_effect=subprocess.CalledProcessError(1, "iw")),
    ):
        assert list_wifi_interfaces() == []


# ---------------------------------------------------------------------------
# enable_monitor_mode — iw path
# ---------------------------------------------------------------------------


def test_enable_monitor_mode_iw_success() -> None:
    with patch("shutil.which", return_value="/usr/bin/iw"), patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        result = enable_monitor_mode("wlan0")
    assert result == "wlan0"
    assert mock_run.call_count == 3  # ip down, iw set monitor, ip up


def test_enable_monitor_mode_iw_falls_back_to_airmon() -> None:
    import subprocess as sp

    def fake_which(cmd: str) -> str | None:
        return f"/usr/bin/{cmd}" if cmd in ("iw", "airmon-ng") else None

    run_calls: list[MagicMock] = []

    def fake_run(argv: list[str], **kwargs: object) -> MagicMock:
        if "iw" in argv and "monitor" in argv:
            raise sp.CalledProcessError(1, argv)
        m = MagicMock(returncode=0)
        run_calls.append(m)
        return m

    airmon_output = "monitor mode enabled on wlan0mon"
    with (
        patch("shutil.which", side_effect=fake_which),
        patch("subprocess.run", side_effect=fake_run),
        patch("subprocess.check_output", return_value=airmon_output),
    ):
        result = enable_monitor_mode("wlan0")
    assert result == "wlan0mon"


def test_enable_monitor_mode_no_tools_raises() -> None:
    with patch("shutil.which", return_value=None):
        with pytest.raises(RuntimeError, match="iw.*airmon-ng"):
            enable_monitor_mode("wlan0")


# ---------------------------------------------------------------------------
# disable_monitor_mode — best-effort, no raise
# ---------------------------------------------------------------------------


def test_disable_monitor_mode_iw() -> None:
    with patch("shutil.which", return_value="/usr/bin/iw"), patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        disable_monitor_mode("wlan0")  # should not raise
    assert mock_run.call_count == 3  # ip down, iw set managed, ip up


def test_disable_monitor_mode_exception_is_swallowed() -> None:
    with (
        patch("shutil.which", return_value="/usr/bin/iw"),
        patch("subprocess.run", side_effect=Exception("oops")),
    ):
        disable_monitor_mode("wlan0")  # must not propagate


# ---------------------------------------------------------------------------
# set_channel
# ---------------------------------------------------------------------------


def test_set_channel_calls_iw() -> None:
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        set_channel("wlan0", 6)
    mock_run.assert_called_once_with(
        ["iw", "dev", "wlan0", "set", "channel", "6"],
        capture_output=True,
        check=False,
    )


def test_set_channel_swallows_exception() -> None:
    with patch("subprocess.run", side_effect=OSError("no such device")):
        set_channel("wlan0", 6)  # must not raise


# ---------------------------------------------------------------------------
# channel_hop
# ---------------------------------------------------------------------------


def test_channel_hop_stops_via_event() -> None:
    stop = threading.Event()
    hopped: list[int] = []

    def fake_set_channel(iface: str, ch: int) -> None:
        hopped.append(ch)
        if len(hopped) >= 3:
            stop.set()

    with patch("profiler.wifi.set_channel", side_effect=fake_set_channel), patch("time.sleep"):
        channel_hop("wlan0", channels=[1, 6, 11], dwell_ms=0, stop_event=stop)

    assert len(hopped) >= 3


# ---------------------------------------------------------------------------
# MonitorContext
# ---------------------------------------------------------------------------


def test_monitor_context_no_hop() -> None:
    with (
        patch("profiler.wifi.enable_monitor_mode", return_value="wlan0") as mock_en,
        patch("profiler.wifi.disable_monitor_mode") as mock_dis,
        patch("profiler.wifi.set_channel") as mock_ch,
    ):
        with MonitorContext("wlan0", channel=6, hop=False) as iface:
            assert iface == "wlan0"
        mock_en.assert_called_once_with("wlan0")
        mock_ch.assert_called_once_with("wlan0", 6)
        mock_dis.assert_called_once_with("wlan0")


def test_monitor_context_hop_thread_started_and_stopped() -> None:
    started: list[str] = []
    stopped: list[str] = []

    def fake_hop(iface: str, channels: object, dwell_ms: int, stop_event: threading.Event) -> None:
        started.append(iface)
        stop_event.wait()
        stopped.append(iface)

    with (
        patch("profiler.wifi.enable_monitor_mode", return_value="wlan0"),
        patch("profiler.wifi.disable_monitor_mode"),
        patch("profiler.wifi.channel_hop", side_effect=fake_hop),
    ):
        ctx = MonitorContext("wlan0", hop=True)
        with ctx as iface:
            assert iface == "wlan0"

    assert started == ["wlan0"]
    assert stopped == ["wlan0"]


def test_monitor_context_exit_restores_on_exception() -> None:
    with (
        patch("profiler.wifi.enable_monitor_mode", return_value="wlan0"),
        patch("profiler.wifi.disable_monitor_mode") as mock_dis,
    ):
        try:
            with MonitorContext("wlan0", hop=False):
                raise ValueError("something went wrong")
        except ValueError:
            pass
        mock_dis.assert_called_once_with("wlan0")
