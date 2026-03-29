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
    diff_with_last_scan,
)
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.console import Console
from rich.columns import Columns
from rich.text import Text
from collector.spoof import start_spoofing, stop_spoofing


app = typer.Typer()
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


@app.command()
def status(
    t: bool = typer.Option(False, "-t", help="Modo contínuo"),
    fast: bool = typer.Option(False, "--fast", "-f", help="Scan rápido sem portas"),
    full: bool = typer.Option(False, "--full", "-F", help="Inclui tabela ARP + DHCP leases + multi-subnets"),
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
        save_scan(devices, network, scan_type)
        start_spoofing(devices, gateway_ip, interface)
        start_sniff(local_ip, interface)

        def refresh_devices():
            nonlocal devices
            use_port_scan = not fast
            use_full = full
            while True:
                time.sleep(30)
                new_devices, new_network = scan_devices(
                    port_scan=use_port_scan,
                    scan_all_subnets=use_full,
                    use_dhcp_leases=use_full,
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
        save_scan(devices, network, scan_type)
        console.print(build_layout(devices))


@app.command()
def scan(
    network: str = None,
    no_port_scan: bool = typer.Option(False, "--no-port-scan", help="Não faz scan de portas"),
    full: bool = typer.Option(False, "--full", "-F", help="Escaneia múltiplas sub-redes/VLANs + DHCP"),
    diff: bool = typer.Option(True, "--diff/--no-diff", help="Mostra diff vs último scan"),
):
    """Lista todos os dispositivos na rede e compara com o scan anterior."""
    devices, detected_network = scan_devices(
        network,
        port_scan=not no_port_scan,
        scan_all_subnets=full,
        use_dhcp_leases=full,
    )

    # Diff ANTES de salvar (compara com o scan anterior, não consigo mesmo)
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

    # Exibe diff após a tabela principal
    if changes is not None:
        console.rule("[dim]Comparação com último scan[/dim]")
        _print_diff(changes)


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
        # Converte ISO timestamp para formato local legível
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

    for d in devices:
        def fmt_ts(ts: str) -> str:
            try:
                return datetime.fromisoformat(ts).astimezone().strftime("%Y-%m-%d %H:%M")
            except Exception:
                return ts

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