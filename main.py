import typer
import time
import socket
import psutil
import threading
from datetime import datetime, timezone

from collector.devices import scan_devices
from collector.bandwidth import get_bandwidth, start_sniff, get_traffic_per_device
from collector.history import (
    save_scan,
    get_scan_history,
    get_scan_devices,
    get_known_devices,
    get_device_history,
    diff_with_last_scan,
)
from collector.ai import (
    analyze_with_threshold,
    save_api_key,
    is_configured,
)
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.console import Console
from rich.columns import Columns
from rich.markdown import Markdown
from rich.spinner import Spinner
from rich.status import Status
from collector.spoof import start_spoofing, stop_spoofing


app = typer.Typer(help="NetWatch — Monitor e analisador de rede com IA.")
console = Console()


def detect_gateway() -> str:
    """Detecta o gateway padrão da rede via tabela de roteamento."""
    try:
        import subprocess
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if "via" in parts:
                return parts[parts.index("via") + 1]
    except Exception:
        pass
    return "192.168.1.1"


def _print_diff(diff: dict) -> None:
    """Exibe o diff vs último scan de forma visual."""
    new = diff["new"]
    missing = diff["missing"]
    changed = diff["changed"]

    if not new and not missing and not changed:
        console.print("[dim]↔ Sem mudanças em relação ao último scan.[/dim]")
        return

    if new:
        console.print(f"\n[bold green]🟢 {len(new)} novo(s) dispositivo(s):[/bold green]")
        for d in new:
            console.print(f"   [green]+[/green] {d['ip']:<16}  {d['mac']}  {d.get('vendor','')}")

    if missing:
        console.print(f"\n[bold red]🔴 {len(missing)} dispositivo(s) desaparecido(s):[/bold red]")
        for d in missing:
            console.print(f"   [red]-[/red] {d['ip']:<16}  {d['mac']}  {d.get('vendor','')}")

    if changed:
        console.print(f"\n[bold yellow]🟡 {len(changed)} dispositivo(s) com IP alterado:[/bold yellow]")
        for c in changed:
            d = c["device"]
            console.print(
                f"   [yellow]~[/yellow] {c['old_ip']:<16} → {d['ip']:<16}  {d['mac']}  {d.get('vendor','')}"
            )


def _enrich_devices_for_ai(devices: list) -> list:
    """
    Enriquece a lista de dispositivos com dados históricos (times_seen)
    para a IA ter contexto de baseline e não alucinar sobre dispositivos comuns.
    """
    enriched = []
    for d in devices:
        record = get_device_history(d.get("mac", ""))
        enriched_d = dict(d)
        if record:
            enriched_d["times_seen"] = record["times_seen"]
            enriched_d["first_seen"] = record["first_seen"]
        else:
            enriched_d["times_seen"] = 0
        enriched.append(enriched_d)
    return enriched


def _run_ai_analysis(
    devices: list,
    bandwidth: dict = None,
    diff: dict = None,
    per_device: dict = None,
    gateway_ip: str = None,
    question: str = None,
    title: str = "🤖 Análise de Segurança — DeepSeek",
) -> None:
    """Executa análise IA com threshold inteligente e exibe painel Rich."""
    if not is_configured():
        console.print(
            "[dim]💡 IA não configurada. Execute [bold]netwatch setup[/bold] para ativar análises.[/dim]"
        )
        return

    enriched = _enrich_devices_for_ai(devices)

    with Status("[bold cyan]Analisando com IA...[/bold cyan]", spinner="dots", console=console):
        result, api_called = analyze_with_threshold(
            devices=enriched,
            bandwidth=bandwidth,
            diff=diff,
            per_device=per_device,
            gateway_ip=gateway_ip,
            question=question,
        )

    if not api_called:
        # Rede estável — exibe resultado local sem painel elaborado
        console.print(f"[dim]{result}[/dim]")
        return

    if result:
        console.print(
            Panel(
                Markdown(result),
                title=f"[bold cyan]{title}[/bold cyan]",
                border_style="cyan",
                padding=(1, 2),
            )
        )


# ---------------------------------------------------------------------------
# Comandos
# ---------------------------------------------------------------------------

@app.command()
def setup(
    key: str = typer.Option(None, "--key", "-k", help="API key do DeepSeek"),
):
    """Configura a API key do DeepSeek para análises com IA."""
    if key is None:
        key = typer.prompt("Cole sua API key do DeepSeek", hide_input=True)
    key = key.strip()
    if not key:
        console.print("[red]API key inválida.[/red]")
        raise typer.Exit(1)
    save_api_key(key)
    console.print("[green]✓ API key salva com segurança em ~/.netwatch/config.json[/green]")


@app.command()
def status(
    t: bool = typer.Option(False, "-t", help="Modo contínuo"),
    fast: bool = typer.Option(False, "--fast", "-f", help="Scan rápido sem portas"),
    full: bool = typer.Option(False, "--full", "-F", help="Inclui tabela ARP + DHCP leases + multi-subnets"),
    ai: bool = typer.Option(True, "--ai/--no-ai", help="Exibe análise de segurança com IA"),
):
    """Exibe status geral da rede."""

    def build_layout(devices: list, per_device: dict = {}):
        data = get_bandwidth()
        upload_kb = data["upload"] / 1024
        download_kb = data["download"] / 1024

        table = Table(title="Dispositivos")
        table.add_column("IP", style="cyan")
        table.add_column("MAC", style="magenta")
        table.add_column("Tipo/Fabricante", style="yellow")
        table.add_column("Upload", style="red")
        table.add_column("Download", style="green")

        for device in devices:
            ip = device["ip"]
            traffic = per_device.get(ip, {"upload": 0, "download": 0})
            up = traffic["upload"] / 1024
            down = traffic["download"] / 1024
            table.add_row(
                ip,
                device["mac"],
                device["vendor"],
                f"{up:.2f} KB/s" if up > 0 else "-",
                f"{down:.2f} KB/s" if down > 0 else "-",
            )

        band_panel = Panel(
            f"Interface: [cyan]{data['interface']}[/cyan]\n"
            f"Upload:    [red]{upload_kb:.2f} KB/s[/red]\n"
            f"Download:  [green]{download_kb:.2f} KB/s[/green]",
            title="[bold]Banda Geral[/bold]",
        )

        return Columns([table, band_panel])

    if t:
        interface = get_bandwidth()["interface"]
        gateway_ip = detect_gateway()

        local_ip = None
        for addr in psutil.net_if_addrs().get(interface, []):
            if addr.family == socket.AF_INET:
                local_ip = addr.address
                break

        console.print("[bold]Escaneando dispositivos...[/bold]")
        devices, network = scan_devices(port_scan=not fast, scan_all_subnets=full, use_dhcp_leases=full)
        scan_type = "full" if full else ("fast" if fast else "normal")
        diff = diff_with_last_scan(devices)
        save_scan(devices, network, scan_type)
        start_spoofing(devices, gateway_ip, interface)
        start_sniff(local_ip, interface)

        # Análise IA antes de entrar no live display
        if ai:
            console.rule("[dim]IA[/dim]")
            _run_ai_analysis(
                devices,
                bandwidth=get_bandwidth(),
                diff=diff,
                gateway_ip=gateway_ip,
                title="🤖 Análise Inicial — DeepSeek",
            )

        def refresh_devices():
            nonlocal devices
            while True:
                time.sleep(30)
                new_devices, new_network = scan_devices(
                    port_scan=not fast,
                    scan_all_subnets=full,
                    use_dhcp_leases=full,
                )
                save_scan(new_devices, new_network, scan_type)
                devices = new_devices
                start_spoofing(devices, gateway_ip, interface)

        thread = threading.Thread(target=refresh_devices, daemon=True)
        thread.start()

        console.print("[bold yellow]⚠ ARP Spoofing ativo[/bold yellow]")
        console.print("[bold]Modo contínuo ativado... (Ctrl+C para sair)[/bold]")

        try:
            with Live(refresh_per_second=4) as live:
                while True:
                    per_device = get_traffic_per_device()
                    live.update(build_layout(devices, per_device))
        except KeyboardInterrupt:
            stop_spoofing()
            console.print("[bold red]Spoofing encerrado, ARP restaurado.[/bold red]")
    else:
        devices, network = scan_devices(port_scan=not fast, scan_all_subnets=full, use_dhcp_leases=full)
        scan_type = "full" if full else ("fast" if fast else "normal")
        diff = diff_with_last_scan(devices)
        save_scan(devices, network, scan_type)
        console.print(build_layout(devices))

        if ai:
            console.rule("[dim]IA[/dim]")
            _run_ai_analysis(
                devices,
                bandwidth=get_bandwidth(),
                diff=diff,
                gateway_ip=detect_gateway(),
                title="🤖 Análise de Segurança — DeepSeek",
            )


@app.command()
def scan(
    network: str = None,
    no_port_scan: bool = typer.Option(False, "--no-port-scan", help="Não faz scan de portas"),
    full: bool = typer.Option(False, "--full", "-F", help="Escaneia múltiplas sub-redes/VLANs + DHCP"),
    diff: bool = typer.Option(True, "--diff/--no-diff", help="Mostra diff vs último scan"),
    ai: bool = typer.Option(True, "--ai/--no-ai", help="Exibe análise de segurança com IA"),
):
    """Lista todos os dispositivos na rede e analisa com IA."""
    devices, detected_network = scan_devices(
        network,
        port_scan=not no_port_scan,
        scan_all_subnets=full,
        use_dhcp_leases=full,
    )

    # Diff ANTES de salvar (compara com o scan anterior)
    changes = diff_with_last_scan(devices) if diff else None

    scan_type = "full" if full else ("normal" if not no_port_scan else "fast")
    save_scan(devices, detected_network, scan_type)

    console.print(f"[bold]Escaneando {detected_network}...[/bold]")
    if full:
        console.print("[bold yellow]Scan completo: ARP + tabela ARP + DHCP leases + multi-subnets[/bold yellow]")

    table = Table(title="Dispositivos na rede")
    table.add_column("IP", style="cyan")
    table.add_column("MAC", style="magenta")
    table.add_column("Fabricante/Tipo", style="yellow")
    table.add_column("Origem", style="blue")

    for device in devices:
        source = device.get("source", "scan")
        source_icon = {
            "local": "[local]",
            "arp-table": "[ARP]",
            "arp-scan": "[scan]",
            "multi-scan": "[multi]",
            "dhcp-lease": "[DHCP]",
        }.get(source, "[?]")
        table.add_row(device["ip"], device["mac"], device["vendor"], source_icon)

    console.print(table)

    if changes is not None:
        console.rule("[dim]Comparação com último scan[/dim]")
        _print_diff(changes)

    if ai:
        console.rule("[dim]IA[/dim]")
        _run_ai_analysis(
            devices,
            diff=changes,
            gateway_ip=detect_gateway(),
            title="🤖 Análise de Segurança — DeepSeek",
        )


@app.command()
def ask(
    question: str = typer.Argument(..., help="Pergunta sobre a rede (ex: 'tem algum dispositivo suspeito?')"),
    fast: bool = typer.Option(True, "--fast/--full-scan", help="Usa scan rápido (padrão) ou completo"),
):
    """Pergunta livre para a IA sobre o estado atual da rede."""
    if not is_configured():
        console.print(
            "[red]IA não configurada.[/red] Execute [bold]netwatch setup[/bold] primeiro."
        )
        raise typer.Exit(1)

    console.print("[bold]Coletando dados da rede...[/bold]")
    devices, network = scan_devices(port_scan=not fast, use_dhcp_leases=True)
    bandwidth = get_bandwidth()
    diff = diff_with_last_scan(devices)
    save_scan(devices, network, "fast" if fast else "normal")

    console.rule("[dim]IA[/dim]")
    _run_ai_analysis(
        devices,
        bandwidth=bandwidth,
        diff=diff,
        gateway_ip=detect_gateway(),
        question=question,
        title=f"🤖 DeepSeek — \"{question[:60]}\"",
    )


@app.command()
def bandwidth():
    """Exibe o uso de banda em tempo real."""
    console.print("[bold]Medindo uso de banda...[/bold]")

    data = get_bandwidth()
    upload_kb = data["upload"] / 1024
    download_kb = data["download"] / 1024

    console.print(f"Interface: [cyan]{data['interface']}[/cyan]")
    console.print(f"Upload:    [red]{upload_kb:.2f} KB/s[/red]")
    console.print(f"Download:  [green]{download_kb:.2f} KB/s[/green]")


@app.command()
def monitor():
    """Modo monitoramento contínuo de banda."""
    console.print("[bold]Iniciando monitoramento... \n(Ctrl+C para sair)[/bold]")

    with Live(refresh_per_second=1) as live:
        while True:
            data = get_bandwidth()
            upload_kb = data["upload"] / 1024
            download_kb = data["download"] / 1024

            panel = Panel(
                f"Interface: [cyan]{data['interface']}[/cyan]\n"
                f"Upload:    [red]{upload_kb:.2f} KB/s[/red]\n"
                f"Download:  [green]{download_kb:.2f} KB/s[/green]",
                title="[bold]Monitoramento de Banda[/bold]",
            )
            live.update(panel)


@app.command()
def history(
    limit: int = typer.Option(20, "-n", help="Número de scans a exibir"),
):
    """Exibe o histórico de scans anteriores."""
    scans = get_scan_history(limit)

    if not scans:
        console.print("[yellow]Nenhum scan salvo ainda. Execute [bold]scan[/bold] primeiro.[/yellow]")
        return

    table = Table(title=f"Histórico de Scans (últimos {limit})")
    table.add_column("#", style="dim", justify="right")
    table.add_column("Data/Hora", style="cyan")
    table.add_column("Rede", style="magenta")
    table.add_column("Tipo", style="yellow")
    table.add_column("Dispositivos", justify="right", style="green")

    for s in scans:
        try:
            ts = datetime.fromisoformat(s["timestamp"]).astimezone().strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            ts = s["timestamp"]

        table.add_row(
            str(s["id"]),
            ts,
            s["network"] or "-",
            s["scan_type"] or "normal",
            str(s["device_count"]),
        )

    console.print(table)


@app.command()
def known(
    limit: int = typer.Option(100, "-n", help="Número máximo de dispositivos"),
):
    """Lista todos os dispositivos já detectados em scans anteriores."""
    devices = get_known_devices(limit)

    if not devices:
        console.print("[yellow]Nenhum dispositivo salvo ainda. Execute [bold]scan[/bold] primeiro.[/yellow]")
        return

    table = Table(title=f"Dispositivos Conhecidos ({len(devices)})")
    table.add_column("MAC", style="magenta")
    table.add_column("Último IP", style="cyan")
    table.add_column("Fabricante/Tipo", style="yellow")
    table.add_column("1ª vez visto", style="dim")
    table.add_column("Última vez", style="dim")
    table.add_column("Vezes", justify="right", style="green")

    def fmt_ts(ts: str) -> str:
        try:
            return datetime.fromisoformat(ts).astimezone().strftime("%Y-%m-%d %H:%M")
        except Exception:
            return ts

    for d in devices:
        table.add_row(
            d["mac"],
            d["ip"] or "-",
            d["vendor"] or "Desconhecido",
            fmt_ts(d["first_seen"]),
            fmt_ts(d["last_seen"]),
            str(d["times_seen"]),
        )

    console.print(table)


if __name__ == "__main__":
    app()