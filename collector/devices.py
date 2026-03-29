import psutil
import ipaddress
import nmap
import socket
import subprocess
import re
import os
import glob
from scapy.all import ARP, Ether, srp, get_if_hwaddr, ICMP, IP
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
            if addr.family == 2:
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
            if addr.family == 2 and not addr.address.startswith("127."):
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
                    if dev_idx + 1 < len(parts):
                        dev = parts[dev_idx + 1]
                    else:
                        dev = "unknown"
                else:
                    dev = "unknown"
                if "lladdr" in parts:
                    lladdr_idx = parts.index("lladdr")
                    if lladdr_idx + 1 < len(parts):
                        mac = parts[lladdr_idx + 1].lower()
                    else:
                        mac = None
                elif len(parts) >= 5:
                    # Formato alternativo
                    for i, p in enumerate(parts):
                        if len(p) == 17 and re.match(r"[0-9a-f]{2}:", p, re.IGNORECASE):
                            mac = p.lower()
                            break
                    else:
                        mac = None
                else:
                    mac = None
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
            if "*" in lease_file:
                # Glob pattern
                import glob
                files = glob.glob(lease_file)
            else:
                files = [lease_file] if os.path.exists(lease_file) else []

            for lf in files:
                with open(lf, "r") as f:
                    content = f.read()

                # Parse formato dnsmasq: timestamp mac ip hostname client_id
                for line in content.split("\n"):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    if len(parts) >= 3:
                        # dnsmasq format
                        if len(parts) >= 3:
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
                lease_pattern = re.compile(r"lease\s+(\d+\.\d+\.\d+\.\d+)\s+\{[^}]*hardware\s+ethernet\s+([0-9a-f:]+)", re.IGNORECASE)
                for match in lease_pattern.finditer(content):
                    ip = match.group(1)
                    mac = match.group(2).lower()
                    if not ip.startswith("127."):
                        dhcp_entries.append({"ip": ip, "mac": mac})
        except Exception:
            pass

    return dhcp_entries


def ping_scan(network: str, timeout: float = 1.0) -> list:
    """
    Scan via ICMP ping para descobrir hosts ativos.
    Funciona através de routers (diferente do ARP).
    """
    try:
        net = ipaddress.IPv4Network(network, strict=False)
        # Scan apenas IPs utilizáveis (exclui network e broadcast)
        hosts = list(net.hosts())[:50]  # Limita a 50 hosts para não demorar
    except Exception:
        return []

    alive_hosts = []
    for host in hosts:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(timeout)
            sock.sendto(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", (str(host), 0))
            sock.recvfrom(1024)
            alive_hosts.append(str(host))
            sock.close()
        except Exception:
            pass
    return alive_hosts


def scan_ports(ip: str, ports: list = None, timeout: float = 0.5) -> list:
    """
    Scan rápido de portas TCP para inferir tipo de dispositivo.
    Retorna lista de portas abertas encontradas.

    Prioriza portas mais comuns para identificar tipo de dispositivo.
    """
    # Portas prioritárias para identificação rápida
    priority_ports = [80, 443, 22, 53, 135, 139, 445, 3389, 9100, 631, 554, 8008, 5228]

    if ports is None:
        ports = priority_ports + [p for p in COMMON_PORTS.keys() if p not in priority_ports]

    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except Exception:
            pass
    return open_ports


def infer_device_type(open_ports: list) -> str:
    """
    Infere o tipo de dispositivo baseado nas portas abertas.
    Usa matching de padrões para identificar.
    """
    if not open_ports:
        return None

    port_set = set(open_ports)

    # scoring por tipo de dispositivo
    scores = {}
    for device_type, pattern_ports in DEVICE_PATTERNS.items():
        score = len(port_set.intersection(set(pattern_ports)))
        if score > 0:
            scores[device_type] = score

    if scores:
        # retorna o tipo com maior score
        return max(scores, key=scores.get)

    # fallback: descreve pelos serviços
    services = [COMMON_PORTS.get(p, f"port:{p}") for p in open_ports[:3]]
    return f"Server ({', '.join(services)})"


def get_os(ip: str, open_ports: list = None) -> str:
    """
    Tenta identificar o SO/dispositivo via nmap ou scan de portas.
    Usa scan de portas como fallback quando nmap falha.
    """
    # Tenta nmap primeiro (mais preciso quando funciona)
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, arguments="-O --osscan-guess -T4", timeout=3000)
        if ip in nm and nm[ip].get("osmatch"):
            matches = nm[ip]["osmatch"]
            if matches:
                return matches[0]["name"]
    except Exception:
        pass

    # Fallback: scan de portas
    if open_ports is None:
        open_ports = scan_ports(ip)

    if open_ports:
        device_type = infer_device_type(open_ports)
        if device_type:
            return device_type

    return "Desconhecido"


def is_randomized_mac(mac: str) -> bool:
    """
    Detecta se um MAC é randomizado (privacidade).
    MACs randomizados têm o segundo nibble como 2, 6, A, ou E.
    """
    if len(mac) < 5:
        return False
    second_char = mac[1].lower()
    return second_char in ['2', '6', 'a', 'e']


def get_original_oui(mac: str) -> str:
    """
    Tenta extrair o OUI original de um MAC randomizado.
    Alguns dispositivos mantêm parte do OUI original nos primeiros bytes.
    """
    # Para MACs randomizados, tenta identificar pelo prefixo estendido
    # Alguns fabricantes têm padrões conhecidos mesmo em MACs randomizados
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
    mac_prefix = mac[:8].lower()
    return oui_prefixes.get(mac_prefix, None)


def ping_host(ip: str, timeout: float = 1.0) -> bool:
    """
    Verifica se host está respondendo a ICMP ping.
    Útil para detectar se dispositivo está ativo ou em standby.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(timeout)
        # Pacote ICMP Echo Request simples
        packet = b"\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        sock.sendto(packet, (ip, 0))
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
    3. Scan de portas
    4. ICMP ping para detectar se está ativo
    Retorna (vendor, device_type) tuple.
    """
    # 1. Tenta identificar pelo MAC primeiro
    vendor = "Desconhecido"
    try:
        vendor = mac_lookup.lookup(mac_addr)
        # MAC identificado com sucesso - vendor já é suficiente
        if vendor and vendor != "Desconhecido":
            return vendor, None
    except Exception:
        pass

    # 2. Detecta MAC randomizado e tenta inferir fabricante
    if is_randomized_mac(mac_addr):
        oui_vendor = get_original_oui(mac_addr)
        if oui_vendor:
            return f"{oui_vendor} (MAC priv.)", None
        # É um MAC randomizado - indica que é dispositivo móvel moderno
        return "Dispositivo Móvel (MAC priv.)", None

    # 3. MAC não identificado (não randomizado) - usa scan de portas
    open_ports = scan_ports(ip)
    device_type = infer_device_type(open_ports) if open_ports else None

    if device_type:
        return device_type, None

    # 4. Fallback: verifica se está respondendo ping
    if ping_host(ip, timeout=0.5):
        return "Dispositivo Ativo (sem portas abertas)", None

    return vendor, device_type


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
    devices = []
    seen_ips = set()
    seen_macs = set()

    def add_device(ip: str, mac_addr: str, source: str = "scan", hostname: str = None):
        """Adiciona dispositivo evitando duplicatas."""
        if ip in seen_ips or mac_addr.lower() in seen_macs:
            return
        seen_ips.add(ip)
        seen_macs.add(mac_addr.lower())

        # Tenta identificar o dispositivo
        if port_scan:
            vendor, device_type = identify_device(ip, mac_addr, mac)
        else:
            vendor, device_type = "Desconhecido", None

        # Fallback para dispositivos não identificados
        if vendor == "Desconhecido" and device_type is None:
            if port_scan:
                open_ports = scan_ports(ip)
                if open_ports:
                    services = [COMMON_PORTS.get(p, f"port:{p}") for p in open_ports[:3]]
                    device_type = f"({', '.join(services)})"

        # Usa hostname se disponível (do DHCP)
        final_vendor = vendor if vendor != "Desconhecido" else device_type or "Desconhecido"
        if hostname and hostname != "-":
            final_vendor = f"{final_vendor} [{hostname}]"

        devices.append({
            "ip": ip,
            "mac": mac_addr,
            "vendor": final_vendor,
            "os": device_type if device_type and vendor != "Desconhecido" else "-",
            "source": source,
        })

    # 1. Adiciona a própria máquina
    for interface, addresses in psutil.net_if_addrs().items():
        for addr in addresses:
            if addr.family == 2 and not addr.address.startswith("127."):
                try:
                    hw_mac = get_if_hwaddr(interface)
                    vendor = mac.lookup(hw_mac)
                except Exception:
                    vendor = "Desconhecido"
                    hw_mac = "00:00:00:00:00:00"
                add_device(addr.address, hw_mac, "local")

    # 2. Lê a tabela ARP do sistema (pode ter entries de outras VLANs)
    if use_arp_table:
        arp_entries = get_arp_table()
        for entry in arp_entries:
            add_device(entry["ip"], entry["mac"], "arp-table")

    # 3. Lê DHCP leases (revela dispositivos em outras VLANs/sub-redes)
    if use_dhcp_leases:
        dhcp_entries = get_dhcp_leases()
        for entry in dhcp_entries:
            add_device(entry["ip"], entry["mac"], "dhcp-lease", entry.get("hostname"))

    # 4. Scan ARP tradicional na rede principal
    if network is None:
        network = get_network_range()

    try:
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
        result = srp(packet, timeout=3, verbose=False)[0]
        for _, received in result:
            add_device(received.psrc, received.hwsrc, "arp-scan")
    except Exception:
        pass

    # 5. Scan de múltiplas sub-redes comuns (se habilitado)
    if scan_all_subnets:
        for subnet in COMMON_SUBNETS:
            if subnet != network:
                try:
                    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
                    result = srp(packet, timeout=2, verbose=False)[0]
                    for _, received in result:
                        add_device(received.psrc, received.hwsrc, "multi-scan")
                except Exception:
                    pass

    return devices, network
