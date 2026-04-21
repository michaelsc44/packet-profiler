# Network Packet Profiler

A tool for capturing network traffic and generating behavioral profiles of clients on a network. Combines `tcpdump`-based packet capture with offline `.pcap` analysis to answer questions like *"what devices are on my network, what do they talk to, and how do they behave over time?"*

> ⚠️ **Legal notice:** Only capture traffic on networks you own or have explicit, documented authorization to monitor. Packet capture may be restricted by law in your jurisdiction and by the policies of networks you connect to.

---

## Features

- **Rotating capture** via `tcpdump` with size and time limits
- **WiFi monitor mode** — passive 802.11 capture with automatic channel hopping
- **Flow extraction** from `.pcap` files (L2 → L7 metadata; Ethernet and radiotap 802.11)
- **Per-client profiling**: traffic volume, destination mix, protocol distribution, active hours
- **Device fingerprinting**: MAC OUI → vendor, DHCP fingerprints, JA3 TLS hashes, User-Agent strings
- **DNS & SNI visibility** for destination classification even when payloads are encrypted
- **AI analysis** — Claude-powered natural-language interpretation of each client profile
- **Storage** in DuckDB with Parquet archival
- **CLI reports** and JSON export; optional dashboard

---

## Quick Start

```bash
# Install
git clone <repo-url> packet-profiler
cd packet-profiler
python -m venv .venv && source .venv/bin/activate
pip install -e .

# Capture (requires root or CAP_NET_RAW)
sudo ppcap capture --iface eth0 --rotate 300 --output ./captures/

# Analyze
ppcap analyze ./captures/*.pcap --db ./data/profiles.duckdb

# Report
ppcap report --db ./data/profiles.duckdb --top 20
ppcap report --db ./data/profiles.duckdb --client 192.168.1.42 --json
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

---

## AI Client Analysis

After running `analyze`, use Claude to interpret each client's behavioral profile:

```bash
# Set your Anthropic API key
export ANTHROPIC_API_KEY=sk-ant-...

# Install the AI extra
pip install -e ".[ai]"

# Analyze a single client
ppcap ai-profile --client 192.168.1.42

# Analyze all clients, saving reports as markdown files
ppcap ai-profile --all --output-dir ./reports/

# Generate a network-level summary across all clients
ppcap ai-profile --network-summary
```

Claude provides a structured analysis for each client covering:

1. **Device type** — smartphone, laptop, IoT sensor, etc. with confidence level
2. **Behavioral profile** — streaming, web browsing, cloud sync, IoT telemetry, gaming, etc.
3. **Anomalies / red flags** — unexpected ports, beaconing, non-standard DNS, high-volume uploads
4. **Privacy & data exposure** — cleartext DNS queries, non-private SNI, exposed service names

The system prompt is cached across batch calls for efficiency (prompt caching via the Anthropic API).

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
│  (iw/      │                          │  JSON export│    │  Claude AI   │
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
│   ├── fingerprint.py    # JA3, OUI, DHCP, UA
│   ├── profiler.py       # per-client aggregation
│   ├── storage.py        # DuckDB schema + queries
│   ├── ai_analysis.py    # Claude AI profile analysis
│   └── report.py         # CLI/JSON output
├── tests/                # pytest suite with sample pcaps
├── captures/             # rotating .pcap output (gitignored)
├── data/                 # DuckDB + Parquet (gitignored)
├── docs/
│   └── design.md         # detailed design document
├── pyproject.toml
└── README.md
```

---

## Configuration

Settings live in `~/.config/ppcap/config.toml` (or `./ppcap.toml` in the project root):

```toml
[capture]
interface = "eth0"
snaplen = 256          # header-only is usually enough
rotate_seconds = 300
max_files = 288        # 24h of 5-min rotations
bpf_filter = "not port 22"

[storage]
db_path = "./data/profiles.duckdb"
archive_parquet = true

[profiling]
client_idle_timeout = 600
flow_timeout = 120
```

---

## Profile Output (example)

```json
{
  "client_ip": "192.168.1.42",
  "mac": "3c:22:fb:xx:xx:xx",
  "vendor": "Apple, Inc.",
  "first_seen": "2026-04-18T09:12:04Z",
  "last_seen": "2026-04-20T08:55:21Z",
  "total_bytes": 4823194821,
  "top_destinations": [
    {"host": "gateway.icloud.com", "bytes": 812334112},
    {"host": "api.github.com",     "bytes":  94820113}
  ],
  "protocol_mix": {"tcp": 0.91, "udp": 0.08, "other": 0.01},
  "active_hours_utc": [8, 9, 10, 11, 13, 14, 15, 16, 17, 20, 21],
  "tls_ja3": ["771,4865-4866-4867,...", "..."],
  "device_guess": "macOS laptop (confidence: medium)"
}
```

---

## Development

```bash
pip install -e ".[dev,ai]"
pytest
ruff check src/ tests/
mypy src/
```

Sample pcaps for tests are pulled from the public Wireshark capture library — see `tests/README.md`.

---

## Roadmap

- [x] MVP: capture → parse → top talkers
- [x] WiFi monitor mode capture (802.11 radiotap, channel hopping)
- [x] AI-powered client profiling via Claude
- [ ] Enrichment: OUI, GeoIP
- [ ] Fingerprinting: JA3, p0f-style OS guess
- [ ] Behavioral baselines + anomaly flags
- [ ] Web dashboard
- [ ] Alerting hooks (webhook, syslog)

---

## License

TBD (MIT recommended for tooling of this type).
