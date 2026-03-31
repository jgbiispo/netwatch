---
name: architecture-analysis
description: Comprehensive architecture analysis of NetWatch with recommendations
type: project
---

# NetWatch Architecture Analysis

**Date:** 2026-03-29
**Scope:** System architecture, concurrency, data pipelines, scalability

---

## 1. Module Interactions

### Current Structure

```
main.py (orchestration)
    ├── collector/devices.py (device discovery)
    ├── collector/bandwidth.py (traffic monitoring)
    ├── collector/spoof.py (ARP MITM)
    ├── collector/history.py (SQLite persistence)
    └── collector/ai.py (DeepSeek integration)
```

### Coupling Analysis

| Module | Coupling Level | Dependencies |
|--------|---------------|--------------|
| `devices.py` | **Low** | psutil, scapy, mac-vendor-lookup, asyncio |
| `bandwidth.py` | **Medium** | scapy, psutil, threading (global state) |
| `spoof.py` | **Low** | scapy, threading (global state) |
| `history.py` | **Low** | sqlite3 only |
| `main.py` | **High** | All collector modules, rich, typer |

**Issues Identified:**

1. **Global state in `bandwidth.py` and `spoof.py`** — Both use module-level globals (`_state`, `_stop_event`) making testing difficult and risking state leakage between tests.

2. **`main.py` is god object** — 700+ lines orchestrating all concerns: CLI parsing, device scanning, AI analysis, history management, live display. Should delegate more to coordinator classes.

3. **Tight coupling between spoofing and display** — The `status -t` command directly manages both `start_spoofing()` and `start_sniff()` with implicit coordination via shared state.

**Recommendations:**

- Extract a `NetworkMonitor` class from `main.py` to encapsulate scanning + spoofing + sniffing orchestration
- Create a `MonitorState` dataclass to hold device list, bandwidth data, and per-device traffic
- Consider dependency injection for testability

---

## 2. Concurrency Strategy

### Threading Model

```
Main Thread (CLI)
    │
    ├── Device Refresh Thread (daemon, 30s interval)
    │       └── scan_devices() → updates 'devices' variable
    │
    ├── Sniff Thread (daemon, started by start_sniff())
    │       └── _packet_handler() → writes to _state.traffic
    │
    └── Spoof Thread (daemon, started by start_spoofing())
            └── spoof loop (2s interval) → sends ARP packets
```

### Thread Safety Assessment

| Component | Thread Safety | Notes |
|-----------|--------------|-------|
| `_BandwidthState.traffic` | ✅ Protected | `threading.Lock` guards all reads/writes |
| `_BandwidthState._last_counters` | ✅ Protected | Same lock as traffic |
| Spoof `_stop_event` | ✅ Protected | `threading.Event` is thread-safe by design |
| `devices` variable in `status -t` | ⚠️ **Unprotected** | Written by refresh thread, read by main loop |
| `ThreadPoolExecutor` in `devices.py` | ✅ Proper | Uses `as_completed()` correctly |

**Critical Issue: Race condition on `devices` list**

In `main.py:239-250`, the `refresh_devices()` thread writes to `devices` while the main `Live` loop reads it:
```python
# Thread 1 (refresh_devices)
devices = new_devices  # Race!

# Main thread (Live loop)
per_device = get_traffic_per_device()
live.update(build_layout(devices, per_device))  # Reads devices during race
```

**Fix Required:**
```python
import threading
_devices_lock = threading.Lock()

# In refresh_devices:
with _devices_lock:
    devices = new_devices

# In build_layout callback:
with _devices_lock:
    devices_copy = list(devices)
```

### CLI Responsiveness

- `get_bandwidth()` previously blocked for 1s via `time.sleep(1)` — **FIXED** in current code using snapshot deltas
- Device scan (`scan_devices()`) can take 5-15s with port scanning — runs in background thread during continuous mode
- AI analysis blocks CLI during API call (~2-5s) — acceptable for now, could use async in future

---

## 3. Data Flow

### Collection → Processing → Storage

```
┌─────────────────────────────────────────────────────────────────────┐
│                        COLLECTION PHASE                             │
├─────────────────────────────────────────────────────────────────────┤
│ 1. get_arp_table()      → Parse "ip neigh" output                   │
│ 2. get_dhcp_leases()    → Parse dnsmasq/ISC DHCP lease files        │
│ 3. ARP scan             → srp(Ether/ARP broadcast)                 │
│ 4. Multi-subnet scan    → Optional scan of COMMON_SUBNETS          │
│ 5. Port scan            → ThreadPoolExecutor per host               │
│                                                                    │
│ Parallel identification via ThreadPoolExecutor(max_workers=16)    │
│   └── identify_device() → MAC lookup + port inference + ICMP ping │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        STORAGE PHASE                                │
├─────────────────────────────────────────────────────────────────────┤
│ save_scan(devices, network, scan_type)                             │
│   ├── INSERT INTO scans (timestamp, network, scan_type, count)     │
│   ├── For each device:                                              │
│   │     INSERT INTO scan_devices (scan_id, ip, mac, vendor)        │
│   │     UPSERT known_devices (mac, ip, vendor, times_seen++)       │
│   └── WAL mode for concurrency                                      │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        AI ANALYSIS                                  │
├─────────────────────────────────────────────────────────────────────┤
│ _enrich_devices_for_ai(devices)                                     │
│   └── For each device: get_device_history(mac) → times_seen        │
│                                                                    │
│ analyze_with_threshold(devices, bandwidth, diff, gateway_ip)       │
│   ├── Build prompt with network context                            │
│   └── Call DeepSeek API                                            │
└─────────────────────────────────────────────────────────────────────┘
```

### Query Patterns (SQLite)

| Query | Frequency | Index Used |
|-------|-----------|-------------|
| `INSERT INTO scans` | Per scan | Primary key |
| `INSERT INTO scan_devices` | N per scan | `idx_scan_devices_scan_id` |
| `UPSERT known_devices` | N per scan | Primary key (mac) |
| `SELECT * FROM scans ORDER BY id DESC LIMIT 1` | Per scan | Primary key |
| `SELECT * FROM known_devices WHERE mac = ?` | Per AI enrichment | Primary key |

**Performance Notes:**
- WAL mode enables concurrent reads during writes
- `idx_known_devices_last_seen` supports `ORDER BY last_seen DESC` queries efficiently
- No complex JOINs — queries are simple single-table lookups

---

## 4. Scalability Analysis

### Current Limits

| Metric | Current Limit | Bottleneck |
|--------|---------------|------------|
| Hosts per scan | ~50 (hardcoded in `ping_scan`) | Line 213: `list(net.hosts())[:50]` |
| Ports per host | ~40 (COMMON_PORTS + priority) | ThreadPoolExecutor per host |
| Concurrent host identification | 16 threads | `max_workers=min(16, len(pending))` |
| Concurrent port checks | ~40 threads | `max_workers=len(ports)` in `scan_ports()` |

### Scaling to 50+ Devices

**Problems:**

1. **Hard limit at 50 hosts** — `ping_scan()` artificially limits network discovery
   ```python
   hosts = list(net.hosts())[:50]  # Arbitrary cutoff
   ```

2. **ARP scan timeout is fixed** — `srp(packet, timeout=3)` doesn't scale with network size

3. **Per-host port scan is serial across hosts** — Port scanning is parallel per-port, but hosts are processed sequentially in `identify()` executor

4. **No batching for MAC lookups** — Each host calls `mac_lookup.lookup()` individually; async lookups could be batched

**Recommendations:**

```python
# Configurable scan limits
MAX_HOSTS_DEFAULT = 256
MAX_HOSTS = os.environ.get("NETWATCH_MAX_HOSTS", MAX_HOSTS_DEFAULT)

# Adaptive timeout based on network size
def scan_devices(..., timeout_per_100_hosts: float = 1.0):
    network_size = net.num_addresses
    timeout = max(3, timeout_per_100_hosts * network_size / 100)
```

### Memory Considerations

- Device list held in memory during continuous mode
- SQLite DB grows linearly with scans; no pruning of old scans
- Per-device traffic dict reset on each `get_traffic_per_device()` call

**Recommendation:** Add `--prune-days` option to clean old scans:
```python
def prune_old_scans(days: int = 30):
    cutoff = (datetime.now() - timedelta(days=days)).isoformat()
    conn.execute("DELETE FROM scans WHERE timestamp < ?", (cutoff,))
```

---

## 5. SQLite Design

### Schema

```sql
-- scans: One row per network scan
CREATE TABLE scans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT NOT NULL,           -- ISO8601 UTC
    network      TEXT,                    -- e.g., "192.168.1.0/24"
    scan_type    TEXT DEFAULT 'normal',   -- fast/normal/full
    device_count INTEGER DEFAULT 0
);

-- scan_devices: Devices found in each scan
CREATE TABLE scan_devices (
    id      INTEGER PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    ip      TEXT NOT NULL,
    mac     TEXT NOT NULL,
    vendor  TEXT,
    source  TEXT           -- local, arp-table, arp-scan, dhcp-lease
);

-- known_devices: Historical tracking per MAC
CREATE TABLE known_devices (
    mac        TEXT PRIMARY KEY,
    ip         TEXT,           -- Last known IP
    vendor     TEXT,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    times_seen INTEGER DEFAULT 1
);
```

### Indexes

| Index | Purpose |
|-------|---------|
| `idx_scan_devices_scan_id` | Fast lookup of devices in a scan |
| `idx_known_devices_last_seen` | `ORDER BY last_seen DESC` for recent devices |

### Write Amplification

Each `save_scan()` performs:
- 1 INSERT to `scans`
- N INSERTs to `scan_devices`
- N UPSERTs to `known_devices`

Total: `1 + 2N` statements per scan (N = device count)

**Optimization Opportunity:** Use `executemany()` for batch inserts:
```python
# Current (N individual inserts)
for device in devices:
    conn.execute("INSERT INTO scan_devices ...")

# Optimized (single batch)
conn.executemany(
    "INSERT INTO scan_devices (scan_id, ip, mac, vendor, source) VALUES (?, ?, ?, ?, ?)",
    [(scan_id, d["ip"], d["mac"], d.get("vendor"), d.get("source")) for d in devices]
)
```

---

## 6. Future Evolution

### Daemon Mode Architecture

**Current:** CLI exits after command or runs foreground loop in continuous mode

**Proposed:**
```
┌─────────────────────────────────────────────────────────────┐
│                     Daemon Architecture                     │
├─────────────────────────────────────────────────────────────┤
│                                                            │
│  netwatch daemon                                            │
│      │                                                      │
│      ├── HTTP Server (port 8080)                           │
│      │     ├── GET /api/devices       → JSON device list   │
│      │     ├── GET /api/bandwidth     → JSON traffic stats │
│      │     ├── GET /api/history       → JSON scan history  │
│      │     └── GET /metrics           → Prometheus format  │
│      │                                                      │
│      ├── Background Scanner (interval-based)               │
│      │     └── scan_devices() every N seconds              │
│      │                                                      │
│      └── State Manager (in-memory + SQLite)                │
│            └── Thread-safe device/bandwidth cache           │
│                                                            │
└─────────────────────────────────────────────────────────────┘
```

### Prometheus/Grafana Integration

**Metrics to Expose:**
```
# HELP netwatch_devices_total Total devices detected
# TYPE netwatch_devices_total gauge
netwatch_devices_total{network="192.168.1.0/24"} 23

# HELP netwatch_device_seen_total Times a specific MAC has been seen
# TYPE netwatch_device_seen_total counter
netwatch_device_seen_total{mac="aa:bb:cc:dd:ee:ff",vendor="Apple"} 15

# HELP netwatch_bandwidth_bytes Bytes per second
# TYPE netwatch_bandwidth_bytes gauge
netwatch_bandwidth_bytes{direction="upload"} 524288
netwatch_bandwidth_bytes{direction="download"} 1048576

# HELP netwatch_new_devices Devices added in last scan
# TYPE netwatch_new_devices gauge
netwatch_new_devices 2

# HELP netwatch_missing_devices Devices removed since last scan
# TYPE netwatch_missing_devices gauge
netwatch_missing_devices 0
```

### Recommended Refactoring for Daemon Mode

1. **Extract `NetworkScanner` class:**
   ```python
   class NetworkScanner:
       def __init__(self, config: ScannerConfig):
           self.config = config
           self._lock = threading.Lock()
           self._devices: list[dict] = []

       def scan(self) -> list[dict]:
           ...

       def start_background_scanner(self, interval: int) -> threading.Thread:
           ...
   ```

2. **Create `StateStore` interface:**
   ```python
   class StateStore(Protocol):
       def get_devices(self) -> list[dict]: ...
       def get_bandwidth(self) -> dict: ...
       def get_last_scan(self) -> dict: ...
   ```

3. **Separate HTTP layer:**
   ```python
   # netwatch/http/server.py
   from fastapi import FastAPI

   app = FastAPI()

   @app.get("/api/devices")
   async def get_devices(store: StateStore = Depends(get_store)):
       return store.get_devices()
   ```

---

## 7. Summary of Critical Recommendations

| Priority | Issue | Fix |
|----------|-------|-----|
| 🔴 P0 | Race condition on `devices` list | Add `threading.Lock` in `status -t` mode |
| 🔴 P0 | 50-host limit in `ping_scan` | Make configurable, default to /24 size |
| 🟡 P1 | Write amplification in SQLite | Use `executemany()` batch inserts |
| 🟡 P1 | No old scan pruning | Add `--prune-days` cleanup |
| 🟡 P1 | Global state in bandwidth/spoof | Encapsulate in classes |
| 🟢 P2 | `main.py` god object | Extract `NetworkMonitor` coordinator |
| 🟢 P2 | No daemon mode | Implement HTTP API + background scanner |
| 🟢 P2 | No Prometheus metrics | Add `/metrics` endpoint for Grafana |

---

## 8. Architectural Diagram

```
┌──────────────────────────────────────────────────────────────────────────┐
│                              NetWatch CLI                                 │
│                              (main.py)                                    │
├──────────────────────────────────────────────────────────────────────────┤
│  Commands: scan | status | monitor | bandwidth | history | ask | chat  │
└─────────────────────────────────────┬────────────────────────────────────┘
                                      │
            ┌─────────────────────────┼─────────────────────────┐
            │                         │                         │
            ▼                         ▼                         ▼
┌───────────────────┐     ┌───────────────────┐     ┌───────────────────┐
│   collector/      │     │   collector/      │     │   collector/      │
│   devices.py      │     │   bandwidth.py    │     │   spoof.py        │
│                   │     │                   │     │                   │
│ • ARP scan        │     │ • Packet sniff    │     │ • ARP spoof       │
│ • Port scan       │     │ • Traffic stats   │     │ • Thread control  │
│ • MAC lookup      │     │ • Lock-protected  │     │ • Event-based     │
│ • ThreadPoolExec  │     │   state           │     │   stop            │
└─────────┬─────────┘     └─────────┬─────────┘     └─────────┬─────────┘
          │                         │                         │
          │                         │                         │
          └─────────────────────────┼─────────────────────────┘
                                    │
                                    ▼
                    ┌───────────────────────────────┐
                    │      collector/history.py     │
                    │                               │
                    │  SQLite (WAL mode)            │
                    │  • scans                      │
                    │  • scan_devices               │
                    │  • known_devices              │
                    └───────────────┬───────────────┘
                                    │
                                    ▼
                    ┌───────────────────────────────┐
                    │        collector/ai.py        │
                    │                               │
                    │  DeepSeek API integration     │
                    │  Context building             │
                    │  Threshold-based analysis     │
                    └───────────────────────────────┘
```