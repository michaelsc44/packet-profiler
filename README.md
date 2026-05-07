# Network Packet Profiler

A tool for capturing network traffic and generating behavioral profiles of clients on a network. Combines `tcpdump`-based packet capture with offline `.pcap` analysis to answer questions like *"what devices are on my network, what do they talk to, and how do they behave over time?"*

> ⚠️ **Legal notice:** Only capture traffic on networks you own or have explicit, documented authorization to monitor. Packet capture may be restricted by law in your jurisdiction and by the policies of networks you connect to.

---

## Features

- **Rotating capture** via `tcpdump` with configurable time and file-count limits
- **WiFi monitor mode** — passive 802.11 capture with automatic channel hopping (2.4 GHz + 5 GHz)
- **Flow extraction** from `.pcap` files — Ethernet and radiotap 802.11, all four 802.11 DS-bit configurations
- **Per-client profiling**: traffic volume, destination count, protocol distribution (TCP/UDP), unique ports
- **DNS & SNI visibility** — destination classification even when payloads are encrypted
- **AI analysis** — Claude-powered natural-language interpretation of each client profile
- **DuckDB storage** for fast local queries and JSON export
- **Device fingerprinting stubs** — MAC OUI vendor lookup (requires `[enrich]`), JA3/DHCP placeholders

---

## Quick Start

```bash
# Clone and install
git clone <repo-url> packet-profiler
cd packet-profiler

# Debian/Ubuntu: install python3-venv if not present
# sudo apt install python3.12-venv

python3 -m venv .venv && source .venv/bin/activate
pip install -e .                  # core only
pip install -e ".[ai]"            # + Claude AI analysis
pip install -e ".[dev,ai]"        # + dev tools (pytest, mypy, ruff)

# Capture (requires root or CAP_NET_RAW)
sudo ppcap capture --iface eth0 --rotate 300 --output ./captures/

# Analyze captured files
ppcap analyze ./captures/*.pcap --db ./data/profiles.duckdb

# Report: top talkers table
ppcap report --db ./data/profiles.duckdb --top 20

# Report: single client profile
ppcap report --db ./data/profiles.duckdb --client 192.168.1.42

# Report: JSON export (all clients)
ppcap report --db ./data/profiles.duckdb --json
```

---

## WiFi Monitor Mode Capture

Passive 802.11 capture lets you observe all clients on a wireless network — useful for home network audits and IoT device discovery.

```bash
# List wireless interfaces
ppcap wifi list-interfaces

# Capture on wlan0 with automatic channel hopping (2.4 GHz + 5 GHz)
# Requires root or CAP_NET_ADMIN + CAP_NET_RAW
sudo ppcap capture --iface wlan0 --wifi --output ./wifi-captures/

# Fix to a single channel (e.g. channel 6)
sudo ppcap capture --iface wlan0 --wifi --channel 6 --output ./wifi-captures/

# Disable channel hopping (stay on whatever channel the NIC is on)
sudo ppcap capture --iface wlan0 --wifi --no-hop --output ./wifi-captures/
```

**Requirements:**
- `iw` (preferred) or `airmon-ng` for monitor mode management
- `tcpdump` ≥ 4.x with 802.11 radiotap support
- Root or `CAP_NET_ADMIN` + `CAP_NET_RAW` capabilities

Monitor mode is enabled automatically on entry and restored to managed mode on exit (even if capture is interrupted with Ctrl-C).

**Known limitations:**
- Not all wireless drivers or chipsets support monitor mode — check your driver docs.
- When using `airmon-ng`, the interface may be renamed (e.g., `wlan0` → `wlan0mon`); ppcap handles this automatically.
- Channel hopping means the radio dwells on each channel for ~200 ms by default; short bursts of traffic on other channels may be missed. Use `--channel N` to focus on one channel.
- WPA/WPA2 encrypted payload content is not decrypted; only 802.11 MAC headers and unencrypted management metadata are available.

---

## AI Client Analysis

After running `analyze`, use Claude to interpret each client's behavioral profile:

```bash
# Set your Anthropic API key
export ANTHROPIC_API_KEY=sk-ant-...

# Analyze a single client
ppcap ai-profile --db ./data/profiles.duckdb --client 192.168.1.42

# Analyze all clients, saving reports as markdown files
ppcap ai-profile --db ./data/profiles.duckdb --all --output-dir ./reports/

# Generate a network-level summary across all clients
ppcap ai-profile --db ./data/profiles.duckdb --network-summary
```

Claude provides a structured analysis for each client covering:

1. **Device type** — smartphone, laptop, IoT sensor, etc. with confidence level
2. **Behavioral profile** — streaming, web browsing, cloud sync, IoT telemetry, gaming, etc.
3. **Anomalies / red flags** — unexpected ports, beaconing, non-standard DNS, high-volume uploads
4. **Privacy & data exposure** — cleartext DNS queries, non-private SNI, exposed service names

The system prompt is cached across batch calls for efficiency (Anthropic prompt caching).

---

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐     ┌────────────┐
│  tcpdump    │────▶│  .pcap files │────▶│  Parser      │────▶│  DuckDB    │
│  (Ethernet) │     │  (rotated)   │     │  (dpkt)      │     │  (flows)   │
└─────────────┘     └──────────────┘     │  Ethernet +  │     └─────┬──────┘
                                         │  Radiotap    │           │
┌─────────────┐     ┌──────────────┐     │  802.11      │           ▼
│  tcpdump    │────▶│  .pcap files │────▶└──────────────┘     ┌──────────────┐
│  (WiFi mon) │     │  (rotated)   │                          │  Profiler    │
└─────────────┘     └──────────────┘                          │  (aggregate) │
       ▲                                                       └──────┬───────┘
       │                                                              │
┌─────────────┐                          ┌─────────────┐             ▼
│ MonitorCtx  │                          │  Reports /  │◀───┌──────────────┐
│  (iw/       │                          │  JSON export│    │  Claude AI   │
│  airmon-ng) │                          └─────────────┘    │  (ai-profile)│
└─────────────┘                                             └──────────────┘
```

See [`docs/design.md`](docs/design.md) for the full design document.

---

## Project Layout

```
packet-profiler/
├── src/profiler/
│   ├── __init__.py
│   ├── cli.py            # entry point: ppcap
│   ├── capture.py        # tcpdump wrapper (Ethernet + WiFi)
│   ├── wifi.py           # monitor mode management (iw/airmon-ng)
│   ├── parser.py         # pcap → flow records (Ethernet + radiotap 802.11)
│   ├── fingerprint.py    # OUI vendor lookup; JA3/DHCP stubs
│   ├── profiler.py       # per-client aggregation (SQL)
│   ├── storage.py        # DuckDB schema + queries
│   ├── ai_analysis.py    # Claude AI profile analysis
│   └── report.py         # CLI table / JSON output
├── tests/                # pytest suite (synthetic pcap fixtures via dpkt)
├── captures/             # rotating .pcap output (gitignored)
├── data/                 # DuckDB database (gitignored)
├── docs/
│   └── design.md         # detailed design document
├── pyproject.toml
└── README.md
```

---

## Profile Schema

The `ppcap report --json` command returns a list of client profiles. Each profile contains:

```json
{
  "client_ip": "192.168.1.42",
  "mac": "3c:22:fb:xx:xx:xx",
  "first_seen": 1700000000.0,
  "last_seen": 1700003600.0,
  "total_bytes": 4823194,
  "total_packets": 5000,
  "unique_destinations": 12,
  "unique_dst_ports": 4,
  "frac_tcp": 0.91,
  "frac_udp": 0.09,
  "sni_seen": ["gateway.icloud.com", "api.github.com"],
  "dns_seen": ["gateway.icloud.com", "api.github.com"]
}
```

`first_seen` / `last_seen` are Unix timestamps (float). `sni_seen` and `dns_seen` are lists of distinct hostnames observed; both may be `null` if no TLS/DNS traffic was captured.

---

## Optional Enrichment

Install the `[enrich]` extra for OUI vendor lookup:

```bash
pip install -e ".[enrich]"
```

This adds:
- **MAC → vendor** via `manuf` (e.g., `aa:bb:cc:...` → `Apple, Inc.`), surfaced in `ai-profile` output

JA3 TLS fingerprinting and DHCP OS fingerprinting are stubbed in `fingerprint.py` — pull requests welcome.

---

## Development

```bash
pip install -e ".[dev,ai]"

# Tests (all run without root or network access; WiFi paths are mocked)
pytest

# Linting / type checking
ruff check src/ tests/
mypy src/
```

Tests use synthetic pcap fixtures built with `dpkt` — no external sample files required.

---

## Roadmap

- [x] MVP: capture → parse → top talkers
- [x] WiFi monitor mode capture (802.11 radiotap, channel hopping)
- [x] AI-powered client profiling via Claude
- [x] Parameterized DuckDB queries (SQL injection fix)
- [ ] Enrichment: OUI lookup via `[enrich]`, GeoIP
- [ ] Fingerprinting: JA3 implementation, p0f-style OS guess
- [ ] Behavioral baselines + anomaly flags
- [ ] Web dashboard
- [ ] Alerting hooks (webhook, syslog)

---

## License

MIT — see [`LICENSE`](LICENSE).
