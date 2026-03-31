import asyncio
import inspect
import psutil
import ipaddress
import socket
import subprocess
import re
import os
import glob
from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import ARP, Ether, srp, get_if_hwaddr
from mac_vendor_lookup import MacLookup

# Portas comuns e seus serviços/dispositivos associados
COMMON_PORTS = {
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    111: "RPC",
    135: "MSRPC",
    139: "NetBIOS",
    443: "HTTPS",
    445: "SMB",
    515: "Printer",
    548: "AFP",
    631: "CUPS",
    9100: "Printer",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Proxy",
    27017: "MongoDB",
    5228: "GCM",
    5229: "GCM",
    5230: "GCM",
    8008: "Chromecast",
    8060: "Chromecast",
    1883: "MQTT",
    8883: "MQTT",
    8123: "HomeAssistant",
    852: "HomeAssistant",
    873: "rsync",
    554: "RTSP",
    8554: "RTSP",
}

# Padrões de portas para inferir tipo de dispositivo
DEVICE_PATTERNS = {
    "Impressora": [515, 631, 9100],
    "Roteador/Gateway": [53, 80, 443],
    "Windows": [135, 139, 445, 3389],
    "Linux/Server": [22, 80, 443],
    "Mac/iOS": [548, 631],
    "Câmera IP": [80, 443, 554, 8554],
    "Smart TV": [80, 443, 8008, 8060],
    "IoT": [80, 443, 1883, 8883],
    "Android/iOS": [80, 443, 5228, 5229, 5230],
    "Home Assistant": [8123, 852],
    "NAS/Storage": [80, 443, 139, 445, 873],
}

# Sub-redes comuns para scan quando há múltiplas VLANs
COMMON_SUBNETS = [
    "192.168.0.0/24",
    "192.168.1.0/24",
    "192.168.2.0/24",
    "192.168.10.0/24",
    "192.168.100.0/24",
    "192.168.50.0/24",
    "192.168.88.0/24",
    "10.0.0.0/24",
    "10.0.1.0/24",
    "10.0.2.0/24",
]


def get_network_range() -> str:
    """Detecta automaticamente o range da rede principal."""
    for interface, addresses in psutil.net_if_addrs().items():
        for addr in addresses:
            if addr.family == socket.AF_INET:  # Fix #13: magic number
                ip = addr.address
                netmask = addr.netmask
                if ip.startswith("192.168") or ip.startswith("10.") or ip.startswith("172."):
                    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                    return str(network)
    return "192.168.1.0/24"


def get_all_interfaces() -> list:
    """Retorna todas as interfaces de rede ativas com seus IPs."""
    interfaces = []
    for interface, addresses in psutil.net_if_addrs().items():
        for addr in addresses:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):  # Fix #13
                interfaces.append({
                    "name": interface,
                    "ip": addr.address,
                    "netmask": addr.netmask,
                })
    return interfaces


def get_arp_table() -> list:
    """
    Lê a tabela ARP do sistema operacional.
    Isso pode conter entries de múltiplas sub-redes/VLANs.
    """
    arp_entries = []
    try:
        # Linux
        result = subprocess.run(["ip", "neigh"], capture_output=True, text=True, timeout=5)
        lines = result.stdout.strip().split("\n")
        for line in lines:
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 3:
                ip = parts[0]
                if "dev" in parts:
                    dev_idx = parts.index("dev")
                    dev = parts[dev_idx + 1] if dev_idx + 1 < len(parts) else "unknown"
                else:
                    dev = "unknown"
                if "lladdr" in parts:
                    lladdr_idx = parts.index("lladdr")
                    mac = parts[lladdr_idx + 1].lower() if lladdr_idx + 1 < len(parts) else None
                else:
                    # Formato alternativo: procura padrão MAC na linha
                    mac = None
                    for p in parts:
                        if len(p) == 17 and re.match(r"[0-9a-f]{2}:", p, re.IGNORECASE):
                            mac = p.lower()
                            break
                if mac and ip and not ip.startswith("127."):
                    arp_entries.append({"ip": ip, "mac": mac, "interface": dev})
    except Exception:
        pass
    return arp_entries


def get_dhcp_leases() -> list:
    """
    Tenta ler leases DHCP de arquivos comuns do sistema.
    Isso revela TODOS os dispositivos que pegaram IP, mesmo em outras VLANs.
    """
    dhcp_entries = []
    lease_files = [
        "/var/lib/dhcp/dhcpd.leases",
        "/var/lib/dhcpd/dhcpd.leases",
        "/var/lib/misc/dnsmasq.leases",
        "/tmp/dnsmasq.leases",
        "/etc/dhcp/dhcpd.leases",
        "/var/lib/NetworkManager/dhcp-*.leases",
    ]

    for lease_file in lease_files:
        try:
            files = glob.glob(lease_file) if "*" in lease_file else (
                [lease_file] if os.path.exists(lease_file) else []
            )  # Fix #9: removido import glob duplicado interno

            for lf in files:
                with open(lf, "r") as f:
                    content = f.read()

                # Parse formato dnsmasq: timestamp mac ip hostname client_id
                for line in content.split("\n"):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    if len(parts) >= 3:  # Fix #12: removida checagem duplicada interna
                        mac = parts[1].lower() if len(parts[1]) == 17 else None
                        ip = parts[2]
                        hostname = parts[3] if len(parts) > 3 else None
                        if mac and ip and not ip.startswith("127."):
                            dhcp_entries.append({
                                "ip": ip,
                                "mac": mac,
                                "hostname": hostname,
                            })

                # Parse formato ISC DHCP
                lease_pattern = re.compile(
                    r"lease\s+(\d+\.\d+\.\d+\.\d+)\s+\{[^}]*hardware\s+ethernet\s+([0-9a-f:]+)",
                    re.IGNORECASE,
                )
                for match in lease_pattern.finditer(content):
                    ip = match.group(1)
                    mac = match.group(2).lower()
                    if not ip.startswith("127."):
                        dhcp_entries.append({"ip": ip, "mac": mac})
        except Exception:
            pass

    return dhcp_entries


def ping_scan(network: str, timeout: float = 0.5) -> list:
    """
    Scan via ICMP ping para descobrir hosts ativos.
    Paralelizado com ThreadPoolExecutor. Fix #5.
    """
    try:
        net = ipaddress.IPv4Network(network, strict=False)
        hosts = list(net.hosts())[:50]
    except Exception:
        return []

    def check_host(host: str) -> str | None:
        try:
            # ICMP Echo Request válido (type=8, code=0, checksum=0, id=0, seq=0)
            icmp_packet = b"\x08\x00\xf7\xff\x00\x00\x00\x00"
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(timeout)
            sock.sendto(icmp_packet, (str(host), 0))
            sock.recvfrom(1024)
            sock.close()
            return str(host)
        except Exception:
            return None

    alive = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(check_host, str(h)): h for h in hosts}
        for future in as_completed(futures):
            result = future.result()
            if result:
                alive.append(result)
    return alive


def scan_ports(ip: str, ports: list = None, timeout: float = 0.5) -> list:
    """
    Scan de portas TCP paralelizado. Fix #7.
    Retorna lista de portas abertas encontradas.
    """
    priority_ports = [80, 443, 22, 53, 135, 139, 445, 3389, 9100, 631, 554, 8008, 5228]

    if ports is None:
        ports = priority_ports + [p for p in COMMON_PORTS.keys() if p not in priority_ports]

    def check_port(port: int) -> int | None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            if sock.connect_ex((ip, port)) == 0:
                sock.close()
                return port
            sock.close()
        except Exception:
            pass
        return None

    open_ports = []
    with ThreadPoolExecutor(max_workers=len(ports)) as executor:
        futures = {executor.submit(check_port, p): p for p in ports}
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                open_ports.append(result)
    return open_ports


def infer_device_type(open_ports: list) -> str:
    """
    Infere o tipo de dispositivo baseado nas portas abertas.
    Usa matching de padrões para identificar.
    """
    if not open_ports:
        return None

    port_set = set(open_ports)

    scores = {}
    for device_type, pattern_ports in DEVICE_PATTERNS.items():
        score = len(port_set.intersection(set(pattern_ports)))
        if score > 0:
            scores[device_type] = score

    if scores:
        return max(scores, key=scores.get)

    services = [COMMON_PORTS.get(p, f"port:{p}") for p in open_ports[:3]]
    return f"Server ({', '.join(services)})"


def is_randomized_mac(mac: str) -> bool:
    """
    Detecta se um MAC é randomizado (privacidade).
    MACs randomizados têm o segundo nibble como 2, 6, A, ou E.
    """
    if len(mac) < 5:
        return False
    return mac[1].lower() in ('2', '6', 'a', 'e')


def get_original_oui(mac: str) -> str:
    """
    Tenta extrair o OUI original de um MAC randomizado.
    Alguns dispositivos mantêm parte do OUI original nos primeiros bytes.
    """
    oui_prefixes = {
        "de:98:54": "Apple",
        "f6:9c:88": "Apple",
        "9e:1a:6e": "Apple",
        "72:36:76": "Samsung",
        "5e:9e:4d": "Xiaomi",
        "da:9c:88": "Apple",
        "ce:9c:88": "Apple",
        "be:9c:88": "Apple",
        "16:1c:a1": "Google (Pixel)",
        "3a:8f:5c": "Google (Pixel)",
        "5a:fc:73": "Google (Pixel)",
        "7a:6a:08": "Google (Pixel)",
    }
    return oui_prefixes.get(mac[:8].lower(), None)


def ping_host(ip: str, timeout: float = 1.0) -> bool:
    """
    Verifica se host está respondendo a ICMP ping.
    Útil para detectar se dispositivo está ativo ou em standby.
    """
    try:
        # ICMP Echo Request válido
        icmp_packet = b"\x08\x00\xf7\xff\x00\x00\x00\x00"
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(timeout)
        sock.sendto(icmp_packet, (ip, 0))
        sock.recvfrom(1024)
        sock.close()
        return True
    except Exception:
        return False


def identify_device(ip: str, mac_addr: str, mac_lookup: MacLookup) -> tuple:
    """
    Identifica dispositivo combinando múltiplas estratégias:
    1. MAC vendor lookup
    2. Detecção de MAC randomizado + OUI original
    3. Scan de portas (paralelizado)
    4. ICMP ping para detectar se está ativo
    Retorna (vendor, open_ports) — open_ports pode ser reutilizado pelo caller.
    """
    # 1. Tenta identificar pelo MAC
    vendor = "Desconhecido"
    try:
        result = mac_lookup.lookup(mac_addr)
        # Versões novas da lib retornam coroutine (AsyncMacLookup).
        # Criamos um loop isolado para não conflitar com threads do executor.
        if inspect.isawaitable(result):
            loop = asyncio.new_event_loop()
            try:
                result = loop.run_until_complete(result)
            finally:
                loop.close()
        vendor = result
        if vendor and vendor != "Desconhecido":
            return vendor, []
    except Exception:
        pass

    # 2. Detecta MAC randomizado
    if is_randomized_mac(mac_addr):
        oui_vendor = get_original_oui(mac_addr)
        if oui_vendor:
            return f"{oui_vendor} (MAC priv.)", []
        return "Dispositivo Móvel (MAC priv.)", []

    # 3. MAC não identificado — scan de portas (paralelizado via scan_ports)
    open_ports = scan_ports(ip)
    device_type = infer_device_type(open_ports) if open_ports else None

    if device_type:
        return device_type, open_ports

    # 4. Fallback: ping
    if ping_host(ip, timeout=0.5):
        return "Dispositivo Ativo (sem portas abertas)", []

    return vendor, open_ports


def scan_devices(
    network: str = None,
    port_scan: bool = True,
    scan_all_subnets: bool = False,
    use_arp_table: bool = True,
    use_dhcp_leases: bool = True,
) -> tuple:
    """
    Escaneia dispositivos na rede com múltiplas estratégias.

    Args:
        network: Range de rede (ex: 192.168.1.0/24). Auto-detectado se None.
        port_scan: Se True, faz scan de portas para identificar dispositivos.
        scan_all_subnets: Se True, escaneia múltiplas sub-redes comuns.
        use_arp_table: Se True, usa a tabela ARP do sistema como fonte adicional.
        use_dhcp_leases: Se True, lê leases DHCP para encontrar dispositivos.
    """
    mac = MacLookup()
    seen_ips = set()
    seen_macs = set()
    pending = []  # (ip, mac_addr, source, hostname)

    def collect(ip: str, mac_addr: str, source: str = "scan", hostname: str = None):
        """Coleta dispositivo evitando duplicatas (sem identificação ainda)."""
        if ip in seen_ips or mac_addr.lower() in seen_macs:
            return
        seen_ips.add(ip)
        seen_macs.add(mac_addr.lower())
        pending.append((ip, mac_addr, source, hostname))

    # 1. Adiciona a própria máquina
    for interface, addresses in psutil.net_if_addrs().items():
        for addr in addresses:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):  # Fix #13
                try:
                    hw_mac = get_if_hwaddr(interface)
                except Exception:
                    hw_mac = "00:00:00:00:00:00"
                collect(addr.address, hw_mac, "local")

    # 2. Lê a tabela ARP do sistema
    if use_arp_table:
        for entry in get_arp_table():
            collect(entry["ip"], entry["mac"], "arp-table")

    # 3. Lê DHCP leases
    if use_dhcp_leases:
        for entry in get_dhcp_leases():
            collect(entry["ip"], entry["mac"], "dhcp-lease", entry.get("hostname"))

    # 4. Scan ARP tradicional na rede principal
    if network is None:
        network = get_network_range()

    try:
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
        result = srp(packet, timeout=3, verbose=False)[0]
        for _, received in result:
            collect(received.psrc, received.hwsrc, "arp-scan")
    except Exception:
        pass

    # 5. Scan de múltiplas sub-redes (se habilitado)
    if scan_all_subnets:
        for subnet in COMMON_SUBNETS:
            if subnet != network:
                try:
                    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
                    result = srp(packet, timeout=2, verbose=False)[0]
                    for _, received in result:
                        collect(received.psrc, received.hwsrc, "multi-scan")
                except Exception:
                    pass

    # 6. Identifica todos os dispositivos em paralelo. Fix #6
    def identify(args):
        ip, mac_addr, source, hostname = args

        if port_scan:
            vendor, open_ports = identify_device(ip, mac_addr, mac)
        else:
            vendor, open_ports = "Desconhecido", []

        # Fix #1: removido double scan — open_ports já vem de identify_device
        if vendor == "Desconhecido" and open_ports:
            services = [COMMON_PORTS.get(p, f"port:{p}") for p in open_ports[:3]]
            vendor = f"({', '.join(services)})"

        final_vendor = vendor if vendor != "Desconhecido" else "Desconhecido"
        if hostname and hostname != "-":
            final_vendor = f"{final_vendor} [{hostname}]"

        return {
            "ip": ip,
            "mac": mac_addr,
            "vendor": final_vendor,
            "source": source,
        }

    devices = []
    with ThreadPoolExecutor(max_workers=min(16, len(pending) or 1)) as executor:
        futures = [executor.submit(identify, args) for args in pending]
        for future in as_completed(futures):
            try:
                devices.append(future.result())
            except Exception:
                pass

    # Ordena por IP para exibição consistente
    devices.sort(key=lambda d: tuple(int(x) for x in d["ip"].split(".")))
    return devices, network
