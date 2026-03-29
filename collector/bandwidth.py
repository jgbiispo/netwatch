import psutil
import time
import threading
from scapy.all import sniff, IP
from collections import defaultdict

# Fix #2 / Fix #11: encapsulado em classe com Lock para evitar race condition
class _BandwidthState:
    def __init__(self):
        self.lock = threading.Lock()
        self.traffic: dict = defaultdict(lambda: {"upload": 0, "download": 0})
        self.local_ip: str = None
        # snapshot para get_bandwidth não-bloqueante (Fix #8)
        self._last_counters: dict = {}
        self._last_time: float = 0.0

_state = _BandwidthState()


def _packet_handler(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        size = len(packet)
        with _state.lock:  # Fix #2: protege escrita com lock
            if src == _state.local_ip:
                _state.traffic[dst]["upload"] += size
            elif dst == _state.local_ip:
                _state.traffic[src]["download"] += size


def start_sniff(local_ip: str, interface: str):
    """Inicia o sniff em background."""
    _state.local_ip = local_ip
    # Inicializa snapshot para get_bandwidth não-bloqueante
    _state._last_counters = psutil.net_io_counters(pernic=True)
    _state._last_time = time.monotonic()
    thread = threading.Thread(
        target=lambda: sniff(iface=interface, prn=_packet_handler, store=False),
        daemon=True,
    )
    thread.start()


def get_traffic_per_device() -> dict:
    """Retorna o tráfego acumulado por dispositivo e reseta."""
    with _state.lock:  # Fix #2: leitura e reset atômicos
        result = {k: dict(v) for k, v in _state.traffic.items()}
        _state.traffic = defaultdict(lambda: {"upload": 0, "download": 0})
    return result


def get_bandwidth(interface: str = None, interval: int = 1) -> dict:
    """
    Mede o uso de banda em tempo real.
    Fix #8: não bloqueia com sleep quando sniff já está ativo.
    Usa delta entre snapshots consecutivos; faz sleep(1) apenas na
    primeira chamada ou quando interface muda.
    """
    if interface is None:
        interface = get_default_interface()

    now = time.monotonic()
    current_counters = psutil.net_io_counters(pernic=True)

    if interface in _state._last_counters and _state._last_time > 0:
        elapsed = now - _state._last_time
        if elapsed > 0:
            before = _state._last_counters[interface]
            after = current_counters[interface]
            upload = (after.bytes_sent - before.bytes_sent) / elapsed
            download = (after.bytes_recv - before.bytes_recv) / elapsed
            _state._last_counters = current_counters
            _state._last_time = now
            return {"interface": interface, "upload": upload, "download": download}

    # Primeira chamada ou interface ainda sem snapshot: fallback com sleep mínimo
    before = current_counters[interface]
    time.sleep(interval)
    after = psutil.net_io_counters(pernic=True)[interface]
    _state._last_counters = psutil.net_io_counters(pernic=True)
    _state._last_time = time.monotonic()

    upload = (after.bytes_sent - before.bytes_sent) / interval
    download = (after.bytes_recv - before.bytes_recv) / interval
    return {"interface": interface, "upload": upload, "download": download}


def get_default_interface() -> str:
    """Pega a interface de rede ativa."""
    stats = psutil.net_if_stats()
    for interface, stat in stats.items():
        if stat.isup and interface != "lo":
            return interface
    return "eth0"