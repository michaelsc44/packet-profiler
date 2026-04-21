"""Fingerprinting helpers: MAC OUI → vendor, JA3, DHCP signatures, UA parsing.

Most of these are stubs that point at real libraries you can plug in via the
`enrich` optional dependency group. Kept separate so the core parser stays lean.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class DeviceGuess:
    os_family: str | None = None       # "linux" | "macos" | "windows" | "ios" | "android" | ...
    device_type: str | None = None     # "laptop" | "phone" | "iot" | "router" | ...
    vendor: str | None = None          # from OUI
    confidence: str = "low"            # "low" | "medium" | "high"


def vendor_from_mac(mac: str) -> str | None:
    """Look up vendor via OUI prefix. Requires `manuf` (install with [enrich])."""
    try:
        from manuf import manuf  # type: ignore[import-not-found]
    except ImportError:
        return None
    p = manuf.MacParser()
    return p.get_manuf(mac)


def ja3_from_client_hello(client_hello: bytes) -> str | None:
    """Compute a JA3 hash from a TLS ClientHello record.

    Stub — implement using the reference JA3 spec:
        SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
    then MD5-hash the comma-joined string. See https://github.com/salesforce/ja3
    """
    raise NotImplementedError


def dhcp_fingerprint(options: list[int]) -> str | None:
    """Produce a fingerprint from the DHCP option list (Option 55 parameter request list).

    Stub — match against the fingerbank database or a local signature file.
    """
    raise NotImplementedError


def guess_device(
    vendor: str | None,
    ja3: str | None,
    user_agents: list[str],
    dhcp_fp: str | None,
) -> DeviceGuess:
    """Combine the cheap signals into a low-confidence device guess.

    Intentionally conservative — this is a starter heuristic, not a classifier.
    """
    guess = DeviceGuess(vendor=vendor)
    ua_blob = " ".join(user_agents).lower()
    if "iphone" in ua_blob or "ios" in ua_blob:
        guess.os_family, guess.device_type, guess.confidence = "ios", "phone", "medium"
    elif "android" in ua_blob:
        guess.os_family, guess.device_type, guess.confidence = "android", "phone", "medium"
    elif "mac os x" in ua_blob or "macintosh" in ua_blob:
        guess.os_family, guess.device_type, guess.confidence = "macos", "laptop", "medium"
    elif "windows nt" in ua_blob:
        guess.os_family, guess.device_type, guess.confidence = "windows", "laptop", "medium"
    elif vendor:
        guess.confidence = "low"
    return guess
