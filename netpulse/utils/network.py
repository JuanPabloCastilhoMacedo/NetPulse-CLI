"""
Utilitários de rede: validação de IPs, resolução DNS, detecção de interfaces.
"""

import ipaddress
import socket
from typing import Optional


def validate_ip(address: str) -> bool:
    """Valida se o endereço é um IP válido (v4 ou v6)."""
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def validate_network(network: str) -> bool:
    """Valida se o endereço é uma rede válida (ex: 192.168.1.0/24)."""
    try:
        ipaddress.ip_network(network, strict=False)
        return True
    except ValueError:
        return False


def get_network_hosts(network: str) -> list[str]:
    """Retorna a lista de IPs de hosts em uma rede (exclui network e broadcast)."""
    try:
        net = ipaddress.ip_network(network, strict=False)
        return [str(host) for host in net.hosts()]
    except ValueError:
        return []


def resolve_hostname(address: str) -> Optional[str]:
    """Resolve um endereço IP para hostname ou hostname para IP."""
    try:
        if validate_ip(address):
            hostname, _, _ = socket.gethostbyaddr(address)
            return hostname
        else:
            ip = socket.gethostbyname(address)
            return ip
    except (socket.herror, socket.gaierror, OSError):
        return None


def resolve_to_ip(address: str) -> Optional[str]:
    """Resolve qualquer endereço (hostname ou IP) para IP."""
    if validate_ip(address):
        return address
    try:
        return socket.gethostbyname(address)
    except (socket.gaierror, OSError):
        return None


def get_local_ip() -> Optional[str]:
    """
    Obtém o IP local da máquina na interface de rede ativa.
    Tenta primeiro via conexão UDP e, se falhar, via resolução do hostname local.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and ip != "127.0.0.1":
            return ip
    except OSError:
        pass

    try:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        if ip and not ip.startswith("127."):
            return ip
    except OSError:
        pass

    return "127.0.0.1"


def get_network_info(ip: str, prefix: int = 24) -> dict:
    """Retorna informações sobre a rede de um IP."""
    try:
        interface = ipaddress.ip_interface(f"{ip}/{prefix}")
        network = interface.network
        return {
            "ip": ip,
            "network": str(network),
            "netmask": str(network.netmask),
            "broadcast": str(network.broadcast_address),
            "total_hosts": network.num_addresses - 2,
            "prefix_length": network.prefixlen,
        }
    except ValueError:
        return {}
