import typer
from collector.devices import scan_devices
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
def scan(network: str = "192.168.1.0/24"):
    """Lista todos os dispositivos na rede."""
    console.print(f"[bold]Escaneando {network}...[/bold]")
    
    devices = scan_devices(network)

    table = Table(title="Dispositivos na rede")
    table.add_column("IP", style="cyan")
    table.add_column("MAC", style="magenta")

    for device in devices:
        table.add_row(device["ip"], device["mac"])

    console.print(table)

if __name__ == "__main__":
    app()