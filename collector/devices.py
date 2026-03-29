import psutil
import ipaddress
from mac_vendor_lookup import MacLookup
from scapy.all import ARP, Ether, srp

def get_network_range() -> str:
    """Detecta automaticamente o range da rede."""
    for interface, addresses in psutil.net_if_addrs().items():
        for addr in addresses:
            if addr.family == 2:
                ip = addr.address
                netmask = addr.netmask
                if ip.startswith("192.168") or ip.startswith("10.") or ip.startswith("172."):
                    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                    return str(network)
    return "192.168.1.0/24"

def scan_devices(network: str = None) -> list[dict]:
    """Escaneia a rede e retorna os dispositivos encontrados."""
    if network is None:
        network = get_network_range()

    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
    result = srp(packet, timeout=3, verbose=False)[0]

    mac = MacLookup()

    devices = []
    for _, received in result:
        try:
            vendor = mac.lookup(received.hwsrc)
        except Exception as e:
            vendor = "Desconhecido"

        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc,
            "vendor": vendor,
        })

    return devices, network