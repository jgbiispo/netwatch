import typer
import time
from collector.devices import scan_devices
from collector.bandwidth import get_bandwidth
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.console import Console

app = typer.Typer()
console = Console()

@app.command()

def status():
    """Exibe o status geral da rede."""
    console.print("[bold green]netwatch[/bold green] v1.0.0")
    console.print("[bold green]iniciando monitoramento...[/bold green]")

@app.command()
def scan(network: str = None):
    """Lista todos os dispositivos na rede."""
    devices, detected_network = scan_devices(network)

    console.print(f"[bold]Escaneando {detected_network}...[/bold]")

    table = Table(title="Dispositivos na rede")
    table.add_column("IP", style="cyan")
    table.add_column("MAC", style="magenta")
    table.add_column("Fabricante", style="yellow")

    for device in devices:
        table.add_row(device["ip"], device["mac"], device["vendor"])

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