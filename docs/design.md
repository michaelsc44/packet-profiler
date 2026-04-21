# Network Packet Profiler — Design Document

**Status:** Draft v0.1
**Scope:** Technical design for a `tcpdump`-based capture + offline analysis tool that produces per-client behavioral profiles.

---

## 1. Goals & Non-Goals

### Goals
- Passively observe a network and identify which clients are present.
- Build per-client profiles covering: volume, destinations, protocols, active hours, device type.
- Work primarily from **metadata** — the expectation is that most traffic is encrypted.
- Run on commodity hardware (Linux box, Raspberry Pi-class and up) with modest storage.
- Produce structured output (DuckDB + JSON) suitable for downstream dashboards or alerting.

### Non-Goals (v1)
- Real-time IDS / packet-level alerting.
- Payload decryption (no MITM, no TLS keylogging).
- Full DPI across arbitrary L7 protocols — we cover what's cheap (DNS, SNI, HTTP host/UA) and stop there.
- Multi-sensor correlation across segments.

---

## 2. Assumptions & Constraints

- **Vantage point:** sensor sees the traffic either via a SPAN/mirror port, an inline bridge, or by running on the gateway itself. Wireless requires monitor-mode NIC and is out of scope for v1.
- **Authorization:** the operator has legal authority to capture on this network. The tool will surface a capture manifest (`captures/manifest.json`) recording who/what/when/where for audit.
- **Traffic shape:** mixed TCP/UDP with the usual modern ratios — ~90% TLS, plenty of QUIC, DNS, mDNS, ARP, DHCP.
- **Scale target:** up to ~100 Mbps sustained on the capture side with header-only snaplen (`-s 256`). Anything heavier needs PF_RING / AF_PACKET tuning, which we defer.

---

## 3. Architecture

### 3.1 High-Level Flow

```
tcpdump ──► rotated .pcap files ──► parser ──► DuckDB (flows)
                                                    │
                                                    ▼
                                              profiler (SQL)
                                                    │
                                                    ▼
                                        reports / JSON / dashboard
```

Each stage is decoupled so you can replace any one component without touching the others — e.g. swap `tcpdump` for `tshark`, or DuckDB for Postgres/TimescaleDB.

### 3.2 Component Boundaries

| Component | Responsibility | Module |
|---|---|---|
| Capture | Run `tcpdump`, rotate files, enforce retention | `profiler.capture` |
| Parser | Stream `.pcap` → Flow records (dpkt) | `profiler.parser` |
| Fingerprint | OUI, JA3, DHCP, UA → device hints | `profiler.fingerprint` |
| Storage | DuckDB schema, inserts, queries | `profiler.storage` |
| Profiler | Aggregate flows → profile rows | `profiler.profiler` |
| Report | CLI tables, JSON export | `profiler.report` |
| CLI | Orchestration, user-facing entry point | `profiler.cli` |

---

## 4. Capture Layer

### 4.1 Tool Choice

`tcpdump` with libpcap rotation (`-G` / `-W`) is the baseline. It's on every Linux distro, handles SIGHUP cleanly, and writes standard pcap files. Alternatives considered:

| Option | Why we didn't pick it |
|---|---|
| `dumpcap` | Solid, but extra Wireshark dependency for marginal gain. |
| `tshark` | Overkill for capture — does parsing we want elsewhere. |
| `pcapy` / raw sockets | We'd own more code without real upside. |
| eBPF/XDP | Powerful but v2-worthy complexity. |

### 4.2 Rotation Strategy

- **Time-based** (`-G 300`) gives predictable 5-minute chunks — good for incremental analysis.
- **`-W max_files`** makes the directory a fixed-size circular buffer. 288 × 5min ≈ 24h at zero operator intervention.
- **Snaplen 256** captures Ethernet + IP + TCP/UDP + ~190 bytes of payload — enough for DNS, SNI, and most HTTP headers, without the storage cost of full payloads.

### 4.3 Privileges

- Preferred: set `CAP_NET_RAW,CAP_NET_ADMIN` on the `tcpdump` binary, run as unprivileged user.
- Fallback: `sudo ppcap capture ...`.
- `-Z root` keeps `tcpdump` from dropping privileges into a non-existent user during rotation (common pitfall on minimal systems).

---

## 5. Parsing Layer

### 5.1 Library Choice: `dpkt`

Benchmarks from published LLM tooling work and our own prototyping put the three candidates roughly like this on header-only pcaps:

| Library | Throughput | L7 depth | Trade-off |
|---|---|---|---|
| `scapy` | slow (~50k pps single-threaded) | deepest | great for ad-hoc, too slow for pipelines |
| `pyshark` | medium — bounded by tshark subprocess | best L7 (uses Wireshark dissectors) | heavy dependency, IPC overhead |
| `dpkt` | fast (~500k+ pps) | thin, hand-rolled | you write more parsing code |

We pick `dpkt` and hand-roll the few L7 bits we need (SNI, DNS query names). If we ever need broad L7 coverage, we'll slot `pyshark` in behind the same `Flow` dataclass.

### 5.2 Flow Granularity

v1 yields **one `Flow` record per packet**, and aggregation happens in SQL (the profiler layer). This keeps the parser stateless and streaming. v2 can add an in-parser aggregation window (e.g. 60-second 5-tuple bucket) if row counts become painful.

### 5.3 L7 Extraction

- **DNS** (UDP/53): dpkt's DNS parser, take qname from first question.
- **TLS SNI** (TCP/443): hand-rolled ClientHello walker (~30 lines). No crypto needed.
- **HTTP** (TCP/80): v2 — still relevant for IoT but declining.
- **QUIC**: v2 — Initial packets have SNI but require more careful parsing.
- **mDNS / LLMNR / NBNS**: useful for hostname discovery on LAN, v2.

---

## 6. Storage Layer

### 6.1 Why DuckDB

- Embedded, single-file, no server.
- Columnar — fast group-bys over hundreds of millions of flow rows on a laptop.
- Reads and writes Parquet natively, so long-term archive is trivial.
- SQL surface means most profiling logic stays in plain queries, not Python.

Trade-off: single-writer. If we ever need concurrent analyzers, we'd switch to Postgres + TimescaleDB.

### 6.2 Schema

```sql
-- flows: raw per-packet (or per-mini-flow) records, append-only
CREATE TABLE flows (
    src_ip       VARCHAR,
    dst_ip       VARCHAR,
    src_port     INTEGER,
    dst_port     INTEGER,
    proto        VARCHAR,        -- 'tcp' | 'udp' | 'icmp' | 'other'
    src_mac      VARCHAR,
    dst_mac      VARCHAR,
    first_ts     DOUBLE,         -- epoch seconds
    last_ts      DOUBLE,
    bytes_total  BIGINT,
    packets      BIGINT,
    tls_sni      VARCHAR,
    dns_query    VARCHAR
);

-- profiles: rebuilt from flows, one row per client
CREATE TABLE profiles (
    client_ip            VARCHAR PRIMARY KEY,
    mac                  VARCHAR,
    first_seen           DOUBLE,
    last_seen            DOUBLE,
    total_bytes          BIGINT,
    total_packets        BIGINT,
    unique_destinations  BIGINT,
    unique_dst_ports     BIGINT,
    frac_tcp             DOUBLE,
    frac_udp             DOUBLE,
    sni_seen             VARCHAR[],
    dns_seen             VARCHAR[]
);
```

v2 tables: `tls_handshakes` (JA3), `dhcp_events`, `http_events`, `profile_hourly`.

### 6.3 Retention

- Rotating captures: fixed 24h window via `-W`.
- Flow rows: keep 30 days online, archive to Parquet partitioned by date.
- Profiles: keep indefinitely — small and high-value.

---

## 7. Profiling Logic

### 7.1 Per-Client Aggregation (v1)

A single SQL statement rebuilds the `profiles` table from `flows`:

```sql
CREATE OR REPLACE TABLE profiles AS
SELECT
    src_ip                                     AS client_ip,
    any_value(src_mac)                         AS mac,
    min(first_ts)                              AS first_seen,
    max(last_ts)                               AS last_seen,
    sum(bytes_total)                           AS total_bytes,
    sum(packets)                               AS total_packets,
    count(DISTINCT dst_ip)                     AS unique_destinations,
    count(DISTINCT dst_port)                   AS unique_dst_ports,
    sum(...)::DOUBLE / NULLIF(sum(...), 0)     AS frac_tcp,
    list(DISTINCT tls_sni) FILTER (...)        AS sni_seen,
    list(DISTINCT dns_query) FILTER (...)      AS dns_seen
FROM flows
GROUP BY src_ip;
```

Runs in seconds over tens of millions of rows on a laptop. For hour-of-day profiles, a second query bucketing on `date_trunc('hour', to_timestamp(first_ts))` feeds `profile_hourly`.

### 7.2 Device Fingerprinting

Combined low-confidence signals:

| Signal | Source | What it tells you |
|---|---|---|
| OUI | first 24 bits of MAC | vendor — "Apple", "Espressif", etc. |
| JA3 | TLS ClientHello | TLS library / app (browser vs curl vs iOS system) |
| DHCP opt 55 | DHCP parameter request list | OS family (Fingerbank-style) |
| User-Agent | HTTP, mDNS strings | explicit OS & app, when present |
| SNI patterns | destinations hit | service-level behavior (`*.apple.com` → Apple device) |

No single signal is authoritative. The `fingerprint.guess_device` function combines them with conservative confidence labels; classifier-style ML is explicitly v2+.

### 7.3 Behavioral Baselines (v2)

For each client, compute rolling statistics:
- bytes/hour mean + stddev
- destination set (Jaccard similarity day-over-day)
- new-SNI rate

A flag fires when the current window is >3σ from the rolling mean. Simple and enough to catch "fridge suddenly uploading gigabytes to a new AS" without an anomaly-detection PhD.

---

## 8. Privacy & Legal Considerations

This section exists because network profiling is inherently privacy-sensitive.

1. **Authorization manifest.** Every capture run writes a `manifest.json` with operator, purpose, scope, and duration. This is the operator's paper trail.
2. **Snaplen default of 256 bytes.** Full-payload capture is off by default. Turning it on requires an explicit `--full-payload` flag and is logged in the manifest.
3. **PII in profiles.** Hostnames (DNS, SNI) are inherently personal. We do not ship them outside the local database by default; the JSON exporter has a `--redact` mode that hashes destinations.
4. **Retention.** The default 24h rotating capture window is a deliberate soft cap. Longer retention requires operator action.
5. **Jurisdiction.** This tool makes no claim about legality in any specific jurisdiction. The README and CLI `--help` make this explicit.

---

## 9. Performance Targets & Risks

### Targets (v1)
- Capture ~100 Mbps sustained without loss on a modern Linux box with `-s 256`.
- Parse ~300k packets/sec on a single CPU (dpkt).
- Full `build_profiles` pass over 50M flows in <30s on a laptop-class machine (DuckDB).

### Risks
- **Packet loss under load.** tcpdump drops at the kernel ring buffer when overwhelmed. Mitigation: tune `/proc/sys/net/core/rmem_max`, use `--buffer-size`, or move to AF_PACKET v3 ring.
- **Disk fill.** Rotation mitigates, but operator-set `--max-files` can still exceed partition capacity. We add a preflight check.
- **Encrypted DNS (DoH/DoT).** Breaks DNS visibility. SNI and IP reputation partially compensate; noted as an expected degradation, not a bug.
- **IPv6 coverage.** First-class, but home networks still mix v4/v6 inconsistently — profiles key on IP, so a client that flips between addresses shows up twice. v2 joins on MAC.

---

## 10. Milestones

| Phase | Deliverable | Exit criterion |
|---|---|---|
| M1 | MVP capture + parse + top-talkers | `ppcap report` produces correct top-10 on a sample pcap |
| M2 | DNS/SNI enrichment, OUI vendor lookups | Profile JSON includes resolvable destinations and vendors |
| M3 | Fingerprinting (JA3, DHCP, UA) + device guess | ≥80% correct OS family on a labeled test set of 50 devices |
| M4 | Hourly behavioral baselines + anomaly flags | Known anomaly in synthetic pcap is flagged, <5% false positive rate |
| M5 | Web dashboard + alerting hooks | Live view of top talkers + webhook on anomaly |

---

## 11. Open Questions

1. **Single-host vs sensor+collector split.** Do we want to support shipping pcaps or flows to a central collector, or is single-host "good enough" for the target user? Leaning single-host for v1.
2. **QUIC handling.** Worth the parser complexity in v1 or defer? Leaning defer — growing but still minority of traffic on most home/SMB networks.
3. **ML-based device classification.** A `scikit-learn` classifier over (ports, SNIs, packet sizes, DHCP) would beat hand rules but adds a training-data burden. Revisit at M3.
4. **Pcap-less mode.** Some deployments would prefer to skip writing pcaps and parse straight from the capture socket (dpkt can read from pcap live). Faster and lower disk use — but gives up the forensic re-analysis pcaps enable. Optional mode in v2.

---

## Appendix A — References

- tcpdump & libpcap documentation
- dpkt source / examples
- Salesforce JA3 specification
- Fingerbank DHCP fingerprint database
- IEEE OUI registry
- DuckDB documentation
