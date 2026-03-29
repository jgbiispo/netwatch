import psutil
import time

def get_bandwidth(interface: str = None, interval: int = 1) -> dict:
    """Mede o uso de banda em tempo real."""
    if interface is None:
        interface = get_default_interface()

    before = psutil.net_io_counters(pernic=True)[interface]
    time.sleep(interval)
    after = psutil.net_io_counters(pernic=True)[interface]

    upload = (after.bytes_sent - before.bytes_sent) / interval
    download = (after.bytes_recv - before.bytes_recv) / interval

    return {
        "interface": interface,
        "upload": upload,
        "download": download,
    }

def get_default_interface() -> str:
    """Pega a interface de rede ativa."""
    stats = psutil.net_if_stats()
    for interface, stat in stats.items():
        if stat.isup and interface != "lo":
            return interface
    return "eth0"