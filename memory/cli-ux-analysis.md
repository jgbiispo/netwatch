# CLI/UX Analysis — NetWatch

**Analysis Date:** 2026-03-29
**Analyst:** CLI/UX Agent

---

## Executive Summary

NetWatch is a well-designed network monitoring CLI with Rich-based visual output and AI integration. The codebase shows solid fundamentals but has several opportunities for consistency improvements and UX enhancements.

---

## 1. Command Consistency

### Current State

| Command | `-t`/`--continuous` | `--fast`/`--full` | `--ai` flag | `--diff` flag |
|---------|---------------------|-------------------|-------------|---------------|
| `status` | `-t` (continuous) | `--fast/-f`, `--full/-F` | `--ai/--no-ai` | implicit |
| `scan` | N/A | `--no-port-scan`, `--full/-F` | `--ai/--no-ai` | `--diff/--no-diff` |
| `watch` | N/A (always continuous) | `--fast/--full-scan` | `--ai/--no-ai` | N/A |
| `ask` | N/A | `--fast/--full-scan` | N/A (always AI) | N/A |
| `chat` | N/A | `--fast/--full-scan` | N/A (always AI) | N/A |

### Issues Identified

**Inconsistent fast/full flag naming:**
- `status`: Uses `--fast/-f` and `--full/-F`
- `scan`: Uses `--no-port-scan` and `--full/-F` (inverted logic)
- `watch`/`ask`/`chat`: Use `--fast/--full-scan` (boolean toggle)

**Recommendations:**

1. **Standardize scan speed flags** across all commands:
   ```python
   # Current inconsistency
   fast: bool = typer.Option(True, "--fast/--full-scan")  # watch/ask/chat
   fast: bool = typer.Option(False, "--fast", "-f")       # status
   no_port_scan: bool = typer.Option(False, "--no-port-scan")  # scan

   # Recommended: Use consistent pattern
   fast: bool = typer.Option(True, "--fast/--full", help="Scan rápido (sem portas) ou completo")
   ```

2. **Align AI flag behavior:**
   - `status`, `scan`, `watch`: Have `--ai/--no-ai` toggle (default ON for status/scan, OFF for watch)
   - `ask`, `chat`: AI is mandatory (no flag needed)
   - Document this distinction in `--help`

3. **Add missing help text consistency:**
   - Some commands have detailed help (`watch`), others are minimal (`bandwidth`)

---

## 2. Rich Display Quality

### Strengths

- Clean table formatting with `Table` and `Panel`
- Consistent color scheme: cyan (IP), magenta (MAC), yellow (vendor), green/red (traffic)
- Alert icons (🔴🟡🔵) provide quick visual severity recognition
- Live refresh mode (`status -t`) with 4 FPS refresh rate

### Issues Identified

**main.py:176-208 (build_layout):**
- Bandwidth panel and device table shown side-by-side via `Columns`
- On narrow terminals, this truncates tables awkwardly
- No terminal width detection or responsive layout

**main.py:528-536 (_show_devices):**
- Chat `/devices` table is simplified (no MAC column) but inconsistent with main `scan` output
- Missing bandwidth column that `status -t` shows

**Alerts display (main.py:666-674):**
- Alert formatting is inline text; could benefit from Rich `Panel` for critical alerts
- No visual hierarchy between multiple alerts

### Recommendations

1. **Add terminal width detection for responsive layouts:**
   ```python
   from rich.console import Console
   console = Console()

   # In build_layout
   if console.width < 100:
       # Stack vertically instead of side-by-side
       return Group(table, band_panel)
   else:
       return Columns([table, band_panel])
   ```

2. **Standardize device table columns across commands:**
   - All device tables should show: IP, MAC, Vendor, Source (where available)
   - Consider adding optional bandwidth column when traffic data exists

3. **Enhance alert presentation:**
   ```python
   # For critical alerts, use Panel for emphasis
   if alert.level == AlertLevel.CRITICAL:
       console.print(Panel(
           f"{alert.detail}",
           title=f"{alert.icon} {alert.title}",
           border_style="red",
       ))
   ```

---

## 3. Real-time Updates Behavior

### Current Implementation

**`status -t` (main.py:210-265):**
- Initial scan, then 30-second background refresh thread
- Live display at 4 FPS showing device table + bandwidth
- ARP spoofing activated for per-device traffic monitoring

**`watch` (main.py:613-698):**
- Initial scan, then configurable interval (default 60s)
- No live display — prints timestamped logs
- Desktop notifications optional via `--notify`

**`monitor` (main.py:387-403):**
- Pure bandwidth monitoring at 1 FPS
- Simple panel with interface/upload/download

### Issues Identified

1. **Inconsistent refresh UX:**
   - `status -t`: Live table with devices refreshing every 30s
   - `watch`: Line-by-line timestamp output, not live display
   - Users may expect similar experiences from both

2. **No progress indicator during scans:**
   - Long scans (full mode with port scanning) have no feedback
   - User sees "Escaneando dispositivos..." then nothing until completion

3. **`status -t` exit handling:**
   - Shows "Spoofing encerrado, ARP restaurado" on Ctrl+C
   - No summary of what was observed during session

### Recommendations

1. **Add scan progress spinner to long operations:**
   ```python
   # For port scanning in scan_devices()
   with Status("[bold]Escaneando portas...[/bold]", spinner="dots", console=console):
       devices, network = scan_devices(port_scan=True)
   ```

2. **Consider unified live display pattern:**
   - Both `status -t` and `watch` could use Rich `Live` with periodic table refresh
   - Watch would append alerts to a scrollable log area

3. **Add session summary on exit:**
   ```python
   # In status -t and watch, track session stats
   console.print(Panel.fit(
       f"Sessão: {duration}\n"
       f"Scans: {scan_count}\n"
       f"Dispositivos vistos: {unique_devices}\n"
       f"Alertas: {alert_count}",
       title="Resumo da Sessão",
   ))
   ```

---

## 4. Error Handling Quality

### Current State

**API Key Errors (main.py:114-118, 349-353):**
```python
if not is_configured():
    console.print(
        "[dim]💡 IA não configurada. Execute [bold]netwatch setup[/bold] para ativar análises.[/dim]"
    )
    return
```
- Clear guidance for `setup` command
- Uses `[dim]` for non-critical messages, `[red]` for errors

**Network Errors (devices.py:443-453):**
- ARP scan failures silently caught with `except Exception: pass`
- No user feedback if network scan completely fails

**Root Requirement:**
- Documented in README but not enforced in code
- Commands requiring `sudo` will fail with cryptic socket errors

### Issues Identified

1. **Silent failures during scanning:**
   - If ARP scan fails completely, user sees empty results with no explanation
   - No differentiation between "no devices found" and "scan failed"

2. **No sudo detection:**
   - Commands like `status -t` fail with socket permission errors
   - Should detect and show actionable error message

3. **AI errors shown inline:**
   - `[Erro na IA: {e}]` provides no guidance on resolution
   - Could suggest checking API key, network connectivity, etc.

### Recommendations

1. **Add permission check for privileged operations:**
   ```python
   def require_root():
       if os.geteuid() != 0:
           console.print(Panel(
               "Este comando requer privilégios de root.\n"
               "Execute com: [bold]sudo python main.py <comando>[/bold]",
               title="[bold red]Permissão Negada[/bold red]",
               border_style="red",
           ))
           raise typer.Exit(1)

   # Call at start of commands that need raw sockets
   @app.command()
   def status(...):
       require_root()
       ...
   ```

2. **Improve scan error handling:**
   ```python
   try:
       result = srp(packet, timeout=3, verbose=False)[0]
   except PermissionError:
       console.print("[red]Permissão negada. Execute com sudo.[/red]")
       raise typer.Exit(1)
   except Exception as e:
       console.print(f"[yellow]⚠ Scan ARP falhou: {e}[/yellow]")
       console.print("[dim]Continuando com tabela ARP do sistema...[/dim]")
   ```

3. **Actionable AI error messages:**
   ```python
   except AuthenticationError:
       return "❌ API key inválida. Execute [bold]netwatch setup[/bold] para reconfigurar."
   except RateLimitError:
       return "⏱ Rate limit da API excedido. Aguarde alguns segundos."
   except ConnectionError:
       return "🌐 Falha de conexão. Verifique sua rede."
   except Exception as e:
       return f"❌ Erro na IA: {e}"
   ```

---

## 5. Command Discoverability

### Current State

**Main `--help` output:**
```
NetWatch — Monitor e analisador de rede com IA.
```
- Brief app description
- Commands listed with minimal descriptions

**Individual command help:**
- Most commands have one-line descriptions
- No examples in `--help` output
- No grouped commands by category

### Issues Identified

1. **No command grouping:**
   - All commands appear at the same level
   - User cannot easily discover related commands (e.g., `scan` vs `status`)

2. **Missing usage examples:**
   - `--help` doesn't show common command combinations
   - User must read README for examples

3. **Undocumented keyboard shortcuts:**
   - `chat` mode has `/help` command but it's not discoverable from CLI

### Recommendations

1. **Add command groups to `app = typer.Typer()`:**
   ```python
   app = typer.Typer(help="NetWatch — Monitor e analisador de rede com IA.")

   # Scan commands
   scan_app = typer.Typer(name="scan", help="Comandos de descoberta de dispositivos")
   scan_app.command()(scan)
   scan_app.command()(status)

   # AI commands
   ai_app = typer.Typer(name="ai", help="Comandos de análise com IA")
   ai_app.command()(ask)
   ai_app.command()(chat)

   # History commands
   hist_app = typer.Typer(name="history", help="Comandos de histórico")
   hist_app.command()(history)
   hist_app.command()(known)

   app.add_typer(scan_app, name="scan")
   app.add_typer(ai_app, name="ai")
   app.add_typer(hist_app, name="history")
   ```

2. **Add examples to command help:**
   ```python
   @app.command()
   def scan(
       network: str = None,
       ...
   ):
       """
       Lista todos os dispositivos na rede e analisa com IA.

       \b
       Exemplos:
         sudo python main.py scan              # scan padrão
         sudo python main.py scan --full       # inclui DHCP leases
         sudo python main.py scan --no-port-scan  # mais rápido
       """
   ```

3. **Add `-h` as alias for `--help`:**
   ```python
   # Typer supports this via help option names
   app = typer.Typer(no_args_is_help=True)
   ```

---

## 6. Output Clarity

### Bandwidth Display

**Current format (main.py:177-180):**
```python
f"{up:.2f} KB/s" if up > 0 else "-"
```

**Issues:**
- No unit conversion (shows KB/s even for large values)
- `-` for zero is inconsistent (would expect `0.00 KB/s`)

**Recommendations:**
```python
def format_bandwidth(bytes_per_sec: int) -> str:
    """Format bandwidth with appropriate unit."""
    kbs = bytes_per_sec / 1024
    if kbs < 1000:
        return f"{kbs:.1f} KB/s"
    mbs = kbs / 1024
    return f"{mbs:.1f} MB/s"

# Usage
format_bandwidth(traffic["upload"])  # "1.5 KB/s" or "2.3 MB/s"
```

### AI Analysis Presentation

**Strengths:**
- Uses `Panel` with `Markdown` rendering for AI responses
- Clean border style and padding
- Title distinguishes between analysis types

**Issues:**
- Long AI responses can overflow terminal
- No visual separation for multiple sections in complex responses

**Recommendations:**
```python
# Add max_width constraint to Panel
Panel(
    Markdown(result),
    title=f"[bold cyan]{title}[/bold cyan]",
    border_style="cyan",
    padding=(1, 2),
    width=min(console.width - 4, 100),  # Cap width
)
```

### Diff Visualization

**Current implementation (main.py:57-83):**
- Clean color coding: green for new, red for missing, yellow for changed
- Icons (🟢🔴🟡) provide quick visual scan
- Indentation with prefix symbols (`+`, `-`, `~`)

**Strengths:**
- Clear visual hierarchy
- Consistent with git diff conventions

**Minor improvement:**
```python
# Add timestamp for context
if new:
    console.print(f"[bold green]🟢 {len(new)} novo(s) dispositivo(s) [/bold green] [dim]{timestamp}[/dim]")
```

---

## 7. Additional Observations

### Missing Features (from README vs Code)

1. **No `--threshold` option for `watch` in history table display:**
   - Users cannot see current threshold in output
   - Add to info panel

2. **Chat `/devices` command missing MAC:**
   - Inconsistent with other device displays
   - Shows only IP and Vendor

### Suggested Quality-of-Life Improvements

1. **Add `--json` output flag:**
   ```python
   @app.command()
   def scan(
       json_output: bool = typer.Option(False, "--json", "-j", help="Saída em JSON"),
   ):
       if json_output:
           import json
           print(json.dumps(devices, indent=2))
           return
       # ... normal output
   ```

2. **Add quiet/verbose modes:**
   ```python
   quiet: bool = typer.Option(False, "-q", "--quiet", help="Apenas erros")
   verbose: bool = typer.Option(False, "-v", "--verbose", help="Saída detalhada")
   ```

3. **Color customization:**
   - Consider `NO_COLOR` environment variable support for accessibility
   - Add `--no-color` flag

---

## Summary of Priority Recommendations

| Priority | Area | Recommendation |
|----------|------|----------------|
| **High** | Error Handling | Add sudo detection with actionable error message |
| **High** | Consistency | Standardize `--fast/--full` flags across all commands |
| **Medium** | UX | Add progress spinner during port scans |
| **Medium** | Clarity | Implement bandwidth unit formatting (KB/s → MB/s) |
| **Medium** | Discoverability | Add usage examples to `--help` output |
| **Low** | Display | Add responsive layout for narrow terminals |
| **Low** | Features | Consider `--json` output flag for scripting |

---

## Code References

- Command definitions: `main.py:152-698`
- Alert formatting: `collector/alerts.py:42-56`
- Device scanning: `collector/devices.py:393-503`
- AI context building: `collector/ai.py:186-302`
- Rich table layout: `main.py:176-208`
