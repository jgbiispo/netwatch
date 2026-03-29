import typer
import time
import psutil
import signal
import threading

from collector.devices import scan_devices
from collector.bandwidth import get_bandwidth, start_sniff, get_traffic_per_device
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.console import Console
from rich.layout import Layout
from rich.columns import Columns
from collector.spoof import start_spoofing, stop_spoofing


app = typer.Typer()
console = Console()

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
        gateway_ip = "192.168.100.1"

        for addr in psutil.net_if_addrs().get(interface, []):
            if addr.family == 2:
                local_ip = addr.address
                break

        console.print("[bold]Escaneando dispositivos...[/bold]")
        devices, _ = scan_devices(port_scan=not fast, scan_all_subnets=full, use_dhcp_leases=full)
        start_spoofing(devices, gateway_ip, interface)
        start_sniff(local_ip, interface)

        # thread que atualiza dispositivos a cada 30s em background
        def refresh_devices():
            nonlocal devices
            use_port_scan = not fast
            use_full = full
            while True:
                time.sleep(10)
                new_devices, _ = scan_devices(port_scan=use_port_scan, scan_all_subnets=use_full, use_dhcp_leases=use_full)
                devices = new_devices
                start_spoofing(devices, gateway_ip, interface)

        thread = threading.Thread(target=refresh_devices, daemon=True)
        thread.start()

        console.print("[bold yellow]⚠ ARP Spoofing ativo[/bold yellow]")
        console.print("[bold]Modo contínuo ativado... (Ctrl+C para sair)[/bold]")
        time.sleep(1)

        try:
            with Live(refresh_per_second=4) as live:
                while True:
                    per_device = get_traffic_per_device()
                    live.update(build_layout(devices, per_device))
        except KeyboardInterrupt:
            stop_spoofing()
            console.print("[bold red]Spoofing encerrado, ARP restaurado.[/bold red]")
    else:
        devices, _ = scan_devices(port_scan=not fast, scan_all_subnets=full, use_dhcp_leases=full)
        console.print(build_layout(devices))

@app.command()
def scan(
    network: str = None,
    no_port_scan: bool = typer.Option(False, "--no-port-scan", help="Não faz scan de portas"),
    full: bool = typer.Option(False, "--full", "-F", help="Escaneia múltiplas sub-redes/VLANs + DHCP"),
):
    """Lista todos os dispositivos na rede."""
    devices, detected_network = scan_devices(
        network,
        port_scan=not no_port_scan,
        scan_all_subnets=full,
        use_dhcp_leases=full,
    )

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

if __name__ == "__main__":
    app()