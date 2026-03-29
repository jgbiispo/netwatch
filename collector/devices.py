from scapy.all import ARP, Ether, srp

def scan_devices(network: str = "192.168.1.0/24") -> list[dict]:
    """Escaneia a rede e retorna os dispositivos encontrados."""
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
    result = srp(packet, timeout=3, verbose=False)[0]

    devices = []
    for _, received in result:
        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc,
        })

    return devices