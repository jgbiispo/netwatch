---
name: ai-data-analysis
description: Analysis of AI integration with recommendations for output quality and token efficiency
type: project
---

# AI Integration Analysis — NetWatch

## Executive Summary

The AI integration in NetWatch is well-structured with local heuristics, threshold-based API calls, and multi-turn chat support. However, there are opportunities to improve output consistency, reduce token usage, and better leverage historical data for trend analysis.

---

## 1. Prompt Design Analysis

### SYSTEM_PROMPT (Analysis Mode)

**Strengths:**
- Anti-hallucination rules (lines 313-319) are specific and actionable
- Clear output sections: `CRÍTICO`, `ATENÇÃO`, `NORMAL`
- Word limit (350 words) prevents verbose responses
- Explicit guidance on false positives (rules 4-5 for common scenarios)

**Weaknesses:**
- **No few-shot examples** — Adding 2-3 example input/output pairs would improve consistency
- **Missing edge case handling** — No guidance for empty networks, single device, or all-new networks
- **Implicit JSON expectation** — If structured output is needed downstream, prompt should explicitly request JSON
- **No confidence scoring** — AI doesn't quantify certainty level

**Recommendation:**
```python
# Add example section to SYSTEM_PROMPT
EXEMPLOS = """
Exemplo de entrada:
  [ok] 192.168.1.1  aa:bb:cc:dd:ee:ff  TP-Link        visto 45x  ★ GATEWAY
  [RISCO 3] 192.168.1.53  de:ad:be:ef:00:00  Desconhecido  NOVO
    Portas abertas: 23⚠️
    ⚠ Porta crítica 23/tcp aberta: Telnet (protocolo inseguro)

Resposta esperada:
🔴 **CRÍTICO**
- 192.168.1.53 — Telnet exposto (porta 23). Dispositivo novo com serviço inseguro.

✅ **NORMAL**
- Gateway TP-Link estável (45 scans sem anomalias).
"""
```

### CHAT_SYSTEM_PROMPT (Interactive Mode)

**Strengths:**
- Context injection approach (line 476-478) is clean
- Appropriate token limit (600 max_tokens vs 1500 for analysis)
- Clear rules about citing specific data

**Weaknesses:**
- **Context staleness** — User can ask about `/rescan` but old messages still reference stale context
- **No conversation memory of previous scans** — Cannot compare across scans in same session

---

## 2. Context Building Analysis

### build_context() Function (lines 186-302)

**Current Structure:**
```
=== SNAPSHOT DA REDE ===
Timestamp, Device Count, Gateway
DISPOSITIVOS (per-device details)
TRÁFEGO GERAL
TRÁFEGO POR DISPOSITIVO
Diff section (new/missing/changed)
```

**Issues:**

1. **Redundant Information:**
   - Device line shows ports, then "Portas abertas" line repeats with emoji indicators
   - Risk score displayed, then reasons repeat the same information

2. **Inefficient Token Usage:**
   - Full vendor names (up to 35 chars) for every device
   - MAC addresses included even for known/safe devices
   - All devices shown equally regardless of relevance

3. **Missing Historical Context:**
   - No trend information (device appeared 3 days in a row?)
   - No bandwidth history comparison
   - No port change tracking

**Recommendation — Tiered Context:**

```python
def build_context(devices, bandwidth, diff, per_device, gateway_ip,
                  mode="full"):  # "full" | "compact" | "minimal"
    """
    mode="compact": Only devices with risk > 0 + summary stats
    mode="minimal": Only diff + summary (for stable networks)
    """
    if mode == "compact":
        # Only include risky devices in full detail
        # Summarize safe devices as: "15 dispositivos conhecidos (sem anomalias)"
        pass
```

**Token Savings Estimate:**
- Current: ~500 tokens for 20 devices
- Compact mode: ~150 tokens for 20 devices (only 3-4 risky devices detailed)

---

## 3. Threshold Logic Analysis

### score_device() (lines 91-147)

**Current Scoring:**
| Condition | Score |
|-----------|-------|
| High-risk port open | +3 per port |
| Medium-risk port open | +1 per port |
| New device (times_seen=0) | +2 |
| Unknown vendor + open ports | +2 |
| Randomized MAC on gateway | +4 |

**Issues:**

1. **Cumulative scoring can over-amplify:**
   - A new IoT device with 3 ports: 2 (new) + 6 (3 ports × 2 medium) = 8 → Definitely triggers AI
   - But IoT devices commonly have multiple ports open

2. **No network size normalization:**
   - 50-device network with 2 new devices vs 5-device network with 2 new devices
   - Same threshold applies to both

3. **No time-based decay:**
   - Device seen 100 times vs 5 times — both become "known" equally
   - A device seen once 6 months ago and appearing today should trigger more scrutiny

**Recommendation — Adaptive Threshold:**

```python
def should_call_ai(devices, diff, gateway_ip):
    # Always call for new devices on small networks
    if diff and diff.get("new"):
        new_ratio = len(diff["new"]) / max(len(devices), 1)
        if new_ratio > 0.3:  # >30% new devices = always investigate
            return True, -1

    # Calculate weighted score
    total_score = 0
    for d in devices:
        s, _ = score_device(d, gateway_ip)
        # Decay score for frequently-seen devices
        times_seen = d.get("times_seen", 0)
        if times_seen > 10:
            s = s * 0.5  # Reduce score for well-known devices
        total_score += s

    # Higher threshold for larger networks
    threshold = 3 + (len(devices) // 20)  # +1 for every 20 devices
    return total_score >= threshold, total_score
```

---

## 4. Output Consistency Analysis

### Current State:
- Markdown format used but not validated
- No programmatic parsing of AI response
- Response shown directly to user (no extraction)

**Issue:** If downstream processing needs the analysis results, there's no structured way to parse them.

**Recommendation — Dual Output Mode:**

```python
SYSTEM_PROMPT_JSON = """\
...
FORMATO DE RESPOSTA (JSON):
{
  "status": "critical" | "warning" | "normal",
  "devices_of_interest": [
    {"ip": "...", "reason": "...", "severity": "critical|warning"}
  ],
  "summary": "One-line summary",
  "recommendations": ["action1", "action2"]
}
"""

def analyze_structured(context, question=None):
    """Returns parsed JSON instead of markdown string."""
    response = analyze(context, question)
    try:
        return json.loads(response), True
    except json.JSONDecodeError:
        # Fallback to markdown parsing
        return {"raw": response, "parse_error": True}, False
```

---

## 5. ask Command Design Analysis

### Current Implementation (main.py:344-369)

**Flow:**
1. Run scan
2. Build context
3. Pass question to AI with context

**Issues:**

1. **No query classification:**
   - "What is ARP spoofing?" → requires network knowledge, not scan data
   - "Is my network secure?" → requires full analysis
   - "What's the gateway?" → can be answered locally without AI

2. **Always does full scan:**
   - `--fast` is default but still runs scan
   - Historical data could answer many questions

**Recommendation — Query Router:**

```python
ROUTABLE_QUERIES = {
    "gateway": lambda ctx: f"Gateway: {ctx['gateway_ip']}",
    "device_count": lambda ctx: f"{len(ctx['devices'])} dispositivos ativos",
    "last_scan": lambda ctx: f"Último scan: {ctx['timestamp']}",
}

def ask(question: str):
    # Check if question can be answered locally
    question_lower = question.lower()
    for keyword, handler in ROUTABLE_QUERIES.items():
        if keyword in question_lower:
            # Answer locally, no API call
            console.print(handler(context))
            return

    # Complex question → AI
    _run_ai_analysis(devices, question=question)
```

---

## 6. Historical Insights Potential

### Current SQLite Schema:

```sql
scans: id, timestamp, network, scan_type, device_count
scan_devices: scan_id, ip, mac, vendor, source
known_devices: mac, ip, vendor, first_seen, last_seen, times_seen
```

**Currently Used:**
- `get_device_history()` — Single device lookup (times_seen)
- `get_known_devices()` — List all known devices

**NOT Used — Opportunity for AI Context:**

1. **Device appearance frequency:**
   ```sql
   -- How often does this MAC appear in scans?
   SELECT COUNT(*) FROM scan_devices WHERE mac = ?;
   ```

2. **IP stability:**
   ```sql
   -- Has this MAC used different IPs?
   SELECT DISTINCT ip FROM scan_devices WHERE mac = ?;
   ```

3. **Network growth trend:**
   ```sql
   -- Is network growing/shrinking?
   SELECT timestamp, device_count FROM scans ORDER BY id DESC LIMIT 10;
   ```

4. **Port change history:**
   - Currently NOT tracked! Would require schema change:
   ```sql
   CREATE TABLE device_ports (
       scan_id INTEGER, mac TEXT, port INTEGER,
       FOREIGN KEY (scan_id) REFERENCES scans(id)
   );
   ```

**Recommendation — Enhanced History for AI:**

```python
def build_historical_context(mac: str = None) -> str:
    """Generate trend insights from SQLite for AI context."""
    lines = []

    # Network size trend
    history = get_scan_history(10)
    counts = [h["device_count"] for h in history]
    if len(counts) >= 3:
        trend = "estável" if counts[-1] == counts[-3] else (
            "crescendo" if counts[-1] > counts[-3] else "diminuindo"
        )
        lines.append(f"Tendência da rede: {trend} ({counts[-1]} dispositivos)")

    # Device-specific history (if requested)
    if mac:
        record = get_device_history(mac)
        if record:
            first = record["first_seen"][:10]
            times = record["times_seen"]
            lines.append(f"Dispositivo {mac}: primeira vez {first}, visto {times}x")

    return "\n".join(lines)
```

---

## 7. Token Efficiency Recommendations

### Current Token Estimate (20 devices):

| Section | Tokens |
|---------|--------|
| Header | ~50 |
| Devices (20 × 80 avg) | ~1600 |
| Traffic | ~100 |
| Diff | ~200 |
| **Total** | **~2000** |

### Optimizations:

1. **Compress device representation:**
   ```
   # Current (verbose):
   [ok]         192.168.1.1      aa:bb:cc:dd:ee:ff  TP-Link TL-WR841N          visto 45x            ★ GATEWAY

   # Proposed (compact):
   GATEWAY: 192.168.1.1 (TP-Link, 45x)
   RISK[3]: 192.168.1.53 (NEW, ports:23)
   KNOWN: 15 devices (see /devices for details)
   ```

2. **Summarize known safe devices:**
   - Instead of listing all 20 devices, group them:
   - "15 dispositivos conhecidos sem anomalias (IPs omitidos)"

3. **Only include diff if meaningful:**
   - Empty diff = one line: "Nenhuma mudança desde o último scan."

4. **Use JSON for structured data sections:**
   ```json
   {"devices": [{"ip": "192.168.1.1", "type": "gateway", "seen": 45}, ...]}
   ```
   - More token-efficient than prose for structured data

**Estimated Savings:** 40-60% reduction in context tokens while preserving analysis quality.

---

## Summary of Recommendations

| Priority | Area | Recommendation |
|----------|------|----------------|
| High | Threshold | Implement network-size-normalized threshold |
| High | Context | Add compact mode for stable networks |
| Medium | Prompts | Add few-shot examples to SYSTEM_PROMPT |
| Medium | History | Add trend analysis (device count over time) |
| Medium | ask | Implement query router for local answers |
| Low | Output | Add JSON output mode for programmatic use |
| Low | History | Track port changes over time (schema change) |

---

## Implementation Order

1. **Quick wins (1-2 hours):**
   - Add few-shot examples to prompts
   - Implement compact context mode

2. **Medium effort (2-4 hours):**
   - Query router for `ask` command
   - Network-size-normalized threshold
   - Historical trend context

3. **Larger effort (4+ hours):**
   - JSON output mode with validation
   - Port change tracking schema