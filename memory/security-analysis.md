# NetWatch Security Analysis

**Date:** 2026-03-29
**Analyst:** Security Agent
**Scope:** ARP spoofing, threat detection, port analysis, device handling

---

## 1. ARP Spoofing Risks (`spoof.py`)

### Thread Safety
**Status:** Adequate with known limitations

The implementation uses a global `_stop_event` and `_spoof_thread` with proper cleanup before starting new threads:

```python
if _spoof_thread and _spoof_thread.is_alive():
    _stop_event.set()
    _spoof_thread.join(timeout=5)
```

**Concerns:**
- Race condition potential: The check-then-set pattern at lines 56-60 is not atomic. A concurrent call could interleave.
- Timeout of 5 seconds may not be sufficient if the spoofing loop is blocked.
- No lock protecting the global state variables.

### ARP Table Restoration
**Status:** Implemented but fragile

```python
def restore(target_ip: str, gateway_ip: str, target_mac: str, gateway_mac: str, interface: str):
    sendp(packet, iface=interface, count=5, verbose=False)
```

**Issues:**
- Restoration packets are sent but there's no verification that ARP tables were actually restored.
- If the program crashes or is killed (SIGKILL), restoration never executes.
- No persistent state tracking - if spoofing was running and the process dies, the network remains poisoned.
- Missing: signal handlers for SIGTERM/SIGINT to trigger cleanup.

### Ethical Considerations
**Critical:** No ethical/legal safeguards present

The code implements full bidirectional ARP spoofing (MITM):
- No warning to users about legality
- No consent mechanism
- No audit logging
- No rate limiting that would prevent service degradation

**Recommendations:**
1. Add explicit user consent dialog before activation
2. Implement audit logging (who enabled it, when, for which targets)
3. Add automatic timeout (max duration)
4. Include prominent warning in CLI help text
5. Consider legal disclaimer in documentation

---

## 2. Detection Strategies (`alerts.py`)

### Current Threat Patterns

The `detect_alerts()` function covers:

| Pattern | Level | Coverage |
|---------|-------|----------|
| New devices | CRITICAL | Good |
| Disappeared devices | WARNING | Good |
| High-risk ports | CRITICAL/WARNING | Partial |
| MAC randomization on gateway | CRITICAL | Good |
| Bandwidth spikes | WARNING | Basic |

### Missing Detection Patterns

**High Priority:**
1. **Port scan detection** - No detection of hosts performing reconnaissance (sequential port access, SYN scans)
2. **DNS tunneling indicators** - Unusual DNS query patterns/lengths
3. **Data exfiltration patterns** - Large outbound transfers to unknown destinations
4. **Lateral movement** - Device accessing multiple internal hosts
5. **ARP spoofing detection** - Gateway MAC appearing from multiple IPs, rapid MAC changes
6. **DHCP starvation** - Many DHCP requests from different MACs
7. **Beaconing/C2 detection** - Periodic connections to external hosts

**Medium Priority:**
1. **Unknown protocol detection** - Traffic on non-standard ports
2. **Timing anomalies** - Unusual activity hours
3. **Failed connection patterns** - Repeated auth failures
4. **IGMP/multicast anomalies** - Unusual multicast group joins

### Implementation Gaps

```python
# Current: Bandwidth detection is simplistic
if upload_kbs > bandwidth_threshold_kbs:
    alerts.append(...)
```

**Issues:**
- No historical baseline comparison
- No per-device traffic profiling
- No direction-aware analysis (inbound vs outbound asymmetry)

---

## 3. Port Analysis (`ai.py`)

### HIGH_RISK_PORTS Review

**Current list (19 ports):**
- Well-known dangerous services covered (Telnet, RDP, VNC, SMB, databases)
- IoT risks included (MQTT 1883, Redis 6379, MongoDB 27017)

**Missing Critical Ports:**

| Port | Service | Risk |
|------|---------|------|
| 139 | NetBIOS | SMB over NetBIOS - ransomware vector |
| 5901-5905 | VNC | Extended VNC range |
| 2049 | NFS | Network file system - data exposure |
| 33060 | MySQL X | MySQL X Protocol |
| 7000-7001 | Cassandra | NoSQL database |
| 9042 | Cassandra | CQL native transport |
| 9200 | Elasticsearch | Data exposure, RCE vectors |
| 5601 | Kibana | Elasticsearch UI |
| 5672 | RabbitMQ | AMQP management |
| 15672 | RabbitMQ | Management UI |
| 9000 | PHP-FPM | Common RCE target |
| 11211 | Memcached | Cache exposure, DDoS amplification |
| 27017-27019 | MongoDB | Already have 27017, need extended range |

### MEDIUM_RISK_PORTS Review

**Current list (5 ports):**
- HTTP/alternative HTTP, RTSP, Home Assistant

**Missing Medium-Risk Ports:**

| Port | Service | Risk |
|------|---------|------|
| 22 | SSH | Common attack target (if exposed externally) |
| 25 | SMTP | Open relay, spam |
| 110/143 | POP3/IMAP | Cleartext mail |
| 161/162 | SNMP | Information disclosure |
| 1900 | SSDP | UPnP exposure |
| 5000 | Flask/Dev | Development servers exposed |
| 8000 | Django | Development servers exposed |

### Port Scoring Logic

```python
# Current scoring
if port in HIGH_RISK_PORTS:
    score += 3
elif port in MEDIUM_RISK_PORTS:
    score += 1
```

**Recommendations:**
1. Add weighted scoring based on context (e.g., database port on non-server device is higher risk)
2. Consider port combinations (SSH + database ports = higher risk)
3. Track port changes over time (newly opened ports)

---

## 4. Traffic Patterns - Undetected Behaviors

### Current State
- Bandwidth monitoring exists but is threshold-based only
- No deep packet inspection
- No flow analysis

### Undetected Threat Patterns

1. **Command & Control (C2):**
   - Periodic beacon to unknown external IPs
   - DNS requests to suspicious domains
   - HTTPS traffic timing patterns

2. **Data Exfiltration:**
   - Large sustained uploads
   - Encrypted tunnels on unusual ports
   - DNS exfil (long TXT records)

3. **Network Reconnaissance:**
   - ARP scans (many ARP requests)
   - Port scan patterns from single host
   - DNS enumeration attempts

4. **MITM Indicators:**
   - Gateway MAC appearing from multiple interfaces
   - ARP responses not matching ARP requests
   - SSL certificate mismatches

5. **IoT Compromise:**
   - IoT device communicating with unexpected external IPs
   - Encrypted traffic from devices that normally don't encrypt
   - Protocol mismatch (HTTP device sending HTTPS)

---

## 5. Unknown Device Handling (`devices.py`)

### Current Approach

```python
# New device detection in ai.py
if times_seen == 0:
    score += 2
    reasons.append("Dispositivo aparece pela primeira vez (sem histórico)")
```

**Positive:**
- History tracking via SQLite (mentioned in git history)
- `times_seen` counter for recurrence detection
- Diff comparison between scans

**Concerns:**

1. **No device classification:**
   - All unknown devices treated equally
   - No distinction between "new IoT device" vs "unknown server"

2. **MAC randomization handling:**
   ```python
   if is_randomized_mac(mac_addr):
       oui_vendor = get_original_oui(mac_addr)
       if oui_vendor:
           return f"{oui_vendor} (MAC priv.)", []
       return "Dispositivo Móvel (MAC priv.)", []
   ```
   - Limited OUI database (only Apple, Samsung, Xiaomi, Google)
   - Mobile devices expected to randomize, but no persistent tracking

3. **Device fingerprinting weakness:**
   - Relies primarily on MAC for identity
   - Port fingerprinting is basic (presence only, not service version)
   - No TLS certificate fingerprinting
   - No mDNS/Bonjour discovery

### Recommendations

1. **Implement device fingerprinting:**
   - Service banner grabbing for port identification
   - SSL certificate pinning for HTTPS services
   - mDNS/LLMNR enumeration for hostname discovery

2. **Enhanced MAC intelligence:**
   - Expand randomized MAC OUI database
   - Track device behavior over time for profiling

3. **Risk-based unknown device handling:**
   - Unknown device + open ports = higher initial score
   - Unknown device + no ports = lower score
   - Unknown device on gateway IP = critical

---

## 6. Ethical/Legal Constraints

### Critical Documentation Gaps

**For MITM Functionality:**

1. **Missing Warning:** No user-facing warning that ARP spoofing is:
   - Illegal in many jurisdictions without authorization
   - Can disrupt network services
   - May be detected by security systems
   - Creates liability for data intercepted

2. **Missing Controls:**
   - No consent acknowledgment
   - No scope limitation (targets entire network)
   - No duration limitation
   - No interception logging transparency

3. **Missing Documentation:**
   ```markdown
   # Required: Legal disclaimer in README/CLI help

   WARNING: ARP spoofing functionality intercepts network traffic.
   - Only use on networks you own or have explicit written authorization
   - Unauthorized use may violate computer crime laws (CFAA, GDPR, etc.)
   - Intercepted data may be subject to privacy regulations
   - Use may be detected and blocked by network security systems
   ```

### Recommendations

1. **Add explicit consent mechanism:**
   ```
   [!] ARP spoofing will intercept ALL traffic between targets and gateway.
   [!] This may be illegal without authorization.
   [!] Type 'I UNDERSTAND AND AUTHORIZE' to continue: _
   ```

2. **Implement audit logging:**
   - Timestamp, user, targets, duration
   - Store logs for accountability

3. **Add automatic timeout:**
   - Maximum spoofing duration (configurable, default 1 hour)
   - Auto-cleanup on timeout

4. **Documentation requirements:**
   - Legal disclaimer in code header
   - Prominent warning in CLI help
   - Recommended use cases (testing, not surveillance)

---

## 7. Safer Alternatives to ARP Spoofing

### Current Approach Issues
ARP spoofing for traffic interception is:
- Detectable by network security tools
- Disruptive to network operations
- Legally problematic
- Ethically questionable for monitoring

### Recommended Alternatives

**1. Port Mirroring / SPAN (Preferred)**
```
Network Switch → Mirror Port → NetWatch Collector
```
- Non-intrusive, invisible to monitored devices
- No traffic disruption
- Legal in most contexts (passive monitoring)
- Requires managed switch with SPAN/mirror capability

**2. TAP Device**
```
Physical TAP → Collector Interface
```
- Hardware-based, completely passive
- Cannot be detected by software
- Enterprise-grade solution

**3. Prometheus/NetFlow Integration**
```
Router/Switch → NetFlow/sFlow → NetWatch
```
- Uses existing network telemetry
- No additional hardware
- Provides flow data without packet capture

**4. DNS Sinkhole Monitoring**
```
DNS Server → Logs → NetWatch
```
- Detect malicious DNS queries
- Identify compromised hosts
- Non-invasive

**5. Passive ARP Monitoring (Current Implementation Already Has This)**
```python
def get_arp_table() -> list:
    # Already implemented - this is safe
```
- Monitor ARP tables for anomalies
- Detect unauthorized ARP spoofing by others
- No active interference

### Hybrid Approach Recommendation

Keep the ARP spoofing code but:
1. Gate it behind explicit authorization
2. Default to passive monitoring
3. Add clear warning prompts
4. Document legal implications
5. Provide alternative monitoring methods as defaults

---

## 8. Summary of Recommendations

### Priority: Critical

| Issue | Action |
|-------|--------|
| Legal documentation | Add disclaimer and consent mechanism for ARP spoofing |
| ARP restoration safety | Add signal handlers and verification |
| Gateway MAC detection | Already implemented - verify alerts are surfaced |

### Priority: High

| Issue | Action |
|-------|--------|
| Missing threat patterns | Add ARP spoofing detection, port scan detection, C2 indicators |
| Port coverage | Add 15+ missing high-risk ports |
| Unknown device handling | Implement device fingerprinting |

### Priority: Medium

| Issue | Action |
|-------|--------|
| Traffic pattern analysis | Add baseline comparison and behavioral profiling |
| Bandwidth monitoring | Add per-device historical baseline |
| Device classification | Categorize devices by behavior profile |

---

## 9. Security Posture Summary

**Strengths:**
- Good foundation for network visibility
- Appropriate use of threat levels (CRITICAL/WARNING/INFO)
- MAC randomization detection for gateway
- Port-based risk scoring with reasonable defaults
- AI integration for pattern analysis

**Weaknesses:**
- MITM functionality lacks ethical safeguards
- Detection patterns incomplete for modern threats
- Port list incomplete
- No traffic behavior analysis
- Limited device fingerprinting

**Overall Assessment:**
The tool provides valuable network monitoring capabilities but the ARP spoofing feature requires significant ethical and operational safeguards before production use. The detection capabilities should be expanded to cover more sophisticated attack patterns. The current focus on passive monitoring (ARP table, port scanning, device discovery) is sound; active interference (ARP spoofing) should be opt-in with clear warnings.