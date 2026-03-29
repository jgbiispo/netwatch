import psutil
import time
import threading
from scapy.all import sniff, IP
from collections import defaultdict

_traffic = defaultdict(lambda: {"upload": 0, "download": 0})
_local_ip = None

def _packet_handler(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        size = len(packet)
        if src == _local_ip:
            _traffic[dst]["upload"] += size
        elif dst == _local_ip:
            _traffic[src]["download"] += size

def start_sniff(local_ip: str, interface: str):
    """Inicia o sniff em background."""
    global _local_ip
    _local_ip = local_ip
    thread = threading.Thread(
        target=lambda: sniff(iface=interface, prn=_packet_handler, store=False),
        daemon=True
    )
    thread.start()

def get_traffic_per_device() -> dict:
    """Retorna o tráfego acumulado por dispositivo e reseta."""
    global _traffic
    result = dict(_traffic)
    _traffic = defaultdict(lambda: {"upload": 0, "download": 0})
    return result

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