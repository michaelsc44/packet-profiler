# Network Packet Profiler

A tool for capturing network traffic and generating behavioral profiles of clients on a network. Combines `tcpdump`-based packet capture with offline `.pcap` analysis to answer questions like *"what devices are on my network, what do they talk to, and how do they behave over time?"*

> ⚠️ **Legal notice:** Only capture traffic on networks you own or have explicit, documented authorization to monitor. Packet capture may be restricted by law in your jurisdiction and by the policies of networks you connect to.

---

## Features

- **Rotating capture** via `tcpdump` with size and time limits
- **Flow extraction** from `.pcap` files (L2 → L7 metadata)
- **Per-client profiling**: traffic volume, destination mix, protocol distribution, active hours
- **Device fingerprinting**: MAC OUI → vendor, DHCP fingerprints, JA3 TLS hashes, User-Agent strings
- **DNS & SNI visibility** for destination classification even when payloads are encrypted
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

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐     ┌────────────┐
│  tcpdump    │────▶│  .pcap files │────▶│  Parser      │────▶│  DuckDB    │
│  (capture)  │     │  (rotated)   │     │  (dpkt)      │     │  (flows)   │
└─────────────┘     └──────────────┘     └──────────────┘     └─────┬──────┘
                                                                    │
                                          ┌─────────────┐           ▼
                                          │  Reports /  │◀───┌──────────────┐
                                          │  Dashboard  │    │  Profiler    │
                                          └─────────────┘    │  (aggregate) │
                                                             └──────────────┘
```

See [`docs/design.md`](docs/design.md) for the full design document.

---

## Project Layout

```
packet-profiler/
├── src/profiler/
│   ├── __init__.py
│   ├── cli.py            # entry point: ppcap
│   ├── capture.py        # tcpdump wrapper
│   ├── parser.py         # pcap → flow records
│   ├── fingerprint.py    # JA3, OUI, DHCP, UA
│   ├── profiler.py       # per-client aggregation
│   ├── storage.py        # DuckDB schema + queries
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
pip install -e ".[dev]"
pytest
ruff check src/
mypy src/
```

Sample pcaps for tests are pulled from the public Wireshark capture library — see `tests/README.md`.

---

## Roadmap

- [x] MVP: capture → parse → top talkers
- [ ] Enrichment: DNS/SNI, OUI, GeoIP
- [ ] Fingerprinting: JA3, p0f-style OS guess
- [ ] Behavioral baselines + anomaly flags
- [ ] Web dashboard
- [ ] Alerting hooks (webhook, syslog)

---

## License

TBD (MIT recommended for tooling of this type).
