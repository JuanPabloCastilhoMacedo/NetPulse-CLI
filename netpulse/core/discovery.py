"""
Módulo de descoberta de hosts em sub-redes.
Utiliza ICMP ping concorrente para identificar hosts ativos.
Inclui fallbacks via tabela ARP e TCP connect scan.
Suporte a port scan de infraestrutura e VoIP.
"""

import time
import socket
import platform
import subprocess
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from icmplib import ping as icmp_ping
from icmplib import ICMPLibError

try:
    from icmplib import multiping as icmp_multiping
except ImportError:
    icmp_multiping = None

try:
    from icmplib import SocketPermissionError
except ImportError:
    SocketPermissionError = PermissionError

from netpulse.config import (
    DEFAULT_DISCOVERY_TIMEOUT,
    DEFAULT_DISCOVERY_WORKERS,
    DEFAULT_PORT_SCAN_TIMEOUT,
    INFRA_PORTS,
)
from netpulse.models.results import DiscoveryResult, HostInfo, PortResult
from netpulse.utils.network import (
    validate_network,
    get_network_hosts,
    resolve_hostname,
    get_local_ip,
)
from netpulse.utils.formatting import console, get_progress_bar, print_info, print_warning


# Portas comuns para TCP connect scan (fallback de descoberta)
COMMON_PORTS = [80, 443, 22, 53, 5060, 3389, 8080, 135, 139, 445]


def detect_local_network() -> Optional[str]:
    """
    Detecta automaticamente a rede local do usuário.
    Obtém o IP local e assume máscara /24.

    Returns:
        Endereço de rede CIDR (ex: 192.168.1.0/24) ou None se falhar.
    """
    local_ip = get_local_ip()
    if local_ip and local_ip != "127.0.0.1":
        parts = local_ip.split(".")
        if len(parts) == 4:
            network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            return network
    return None


def _probe_host(
    ip: str,
    timeout: float = DEFAULT_DISCOVERY_TIMEOUT,
    privileged: bool = True,
) -> HostInfo:
    """
    Sonda um único host via ICMP para verificar se está ativo.

    Args:
        ip: Endereço IP do host.
        timeout: Timeout em segundos.
        privileged: Se True, usa raw socket.

    Returns:
        HostInfo com resultado da sonda.
    """
    host_info = HostInfo(ip_address=ip)

    try:
        response = icmp_ping(
            address=ip,
            count=1,
            timeout=timeout,
            privileged=privileged,
        )

        if response.is_alive:
            host_info.is_alive = True
            host_info.latency_ms = response.avg_rtt

            try:
                host_info.hostname = resolve_hostname(ip)
            except Exception:
                host_info.hostname = None

    except (ICMPLibError, SocketPermissionError, PermissionError, OSError):
        host_info.is_alive = False

    return host_info


def _tcp_connect_probe(
    ip: str,
    ports: list[int] = None,
    timeout: float = 0.5,
) -> HostInfo:
    """
    Sonda um host via TCP connect em portas comuns.
    Útil quando ICMP está bloqueado pelo firewall.

    Args:
        ip: Endereço IP do host.
        ports: Lista de portas para tentar.
        timeout: Timeout de conexão em segundos.

    Returns:
        HostInfo com resultado da sonda.
    """
    if ports is None:
        ports = COMMON_PORTS

    host_info = HostInfo(ip_address=ip)

    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            start = time.time()
            result = sock.connect_ex((ip, port))
            elapsed = (time.time() - start) * 1000  # ms
            sock.close()

            if result == 0:
                host_info.is_alive = True
                host_info.latency_ms = round(elapsed, 2)

                try:
                    host_info.hostname = resolve_hostname(ip)
                except Exception:
                    host_info.hostname = None

                return host_info

        except (socket.timeout, OSError):
            continue

    return host_info


def _scan_port(
    ip: str,
    port: int,
    service: str,
    timeout: float = DEFAULT_PORT_SCAN_TIMEOUT,
) -> PortResult:
    """
    Verifica se uma porta TCP está aberta em um host.

    Args:
        ip: Endereço IP do host.
        port: Número da porta.
        service: Nome do serviço associado.
        timeout: Timeout de conexão em segundos.

    Returns:
        PortResult com o resultado.
    """
    port_result = PortResult(port=port, service=service, is_open=False)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()

        if result == 0:
            port_result.is_open = True

    except (socket.timeout, OSError):
        pass

    return port_result


def _scan_host_ports(
    host: HostInfo,
    ports: dict[int, str] = None,
    timeout: float = DEFAULT_PORT_SCAN_TIMEOUT,
    workers: int = 10,
) -> HostInfo:
    """
    Escaneia portas de infraestrutura/VoIP em um host.

    Args:
        host: HostInfo do host ativo.
        ports: Dicionário {porta: nome_serviço}.
        timeout: Timeout por porta.
        workers: Threads para scan paralelo.

    Returns:
        HostInfo atualizado com open_ports.
    """
    if ports is None:
        ports = INFRA_PORTS

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(_scan_port, host.ip_address, port, service, timeout): port
            for port, service in ports.items()
        }

        for future in as_completed(futures):
            try:
                port_result = future.result()
                if port_result.is_open:
                    host.open_ports.append(port_result)
            except Exception:
                pass

    # Ordenar portas
    host.open_ports.sort(key=lambda p: p.port)

    return host


def _parse_arp_table() -> dict[str, Optional[str]]:
    """
    Lê a tabela ARP do sistema operacional e retorna os IPs encontrados.

    Returns:
        Dicionário {ip: mac_address} dos hosts na tabela ARP.
    """
    arp_entries = {}
    system = platform.system().lower()

    try:
        if system == "windows":
            cmd = ["arp", "-a"]
        else:
            cmd = ["arp", "-a"]

        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
        )

        output = process.stdout

        for line in output.splitlines():
            if system == "windows":
                match = re.search(
                    r'(\d+\.\d+\.\d+\.\d+)\s+([\w-]{17})\s+',
                    line,
                )
            else:
                match = re.search(
                    r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([\w:]{17})',
                    line,
                )

            if match:
                ip = match.group(1)
                mac = match.group(2)
                if mac.lower() not in ("ff-ff-ff-ff-ff-ff", "ff:ff:ff:ff:ff:ff",
                                        "00-00-00-00-00-00", "00:00:00:00:00:00"):
                    arp_entries[ip] = mac

    except FileNotFoundError:
        pass
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass

    return arp_entries


def _discovery_icmp(
    hosts: list[str],
    timeout: float,
    workers: int,
    privileged: bool,
) -> list[HostInfo]:
    """
    Descoberta via ICMP ping concorrente.

    Args:
        hosts: Lista de IPs para escanear.
        timeout: Timeout por host.
        workers: Número de threads.
        privileged: Se True, usa raw socket.

    Returns:
        Lista de HostInfo dos hosts ativos.
    """
    alive_hosts: list[HostInfo] = []

    with get_progress_bar() as progress:
        task = progress.add_task(
            "Escaneando via ICMP...",
            total=len(hosts),
        )

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(_probe_host, ip, timeout, privileged): ip
                for ip in hosts
            }

            for future in as_completed(futures):
                try:
                    host_info = future.result()
                    if host_info.is_alive:
                        alive_hosts.append(host_info)
                except Exception:
                    pass

                progress.update(task, advance=1)

    return alive_hosts


def _discovery_icmp_unprivileged(
    hosts: list[str],
    timeout: float,
    workers: int,
) -> list[HostInfo]:
    """
    Descoberta via ICMP com privileged=False.

    Args:
        hosts: Lista de IPs para escanear.
        timeout: Timeout por host.
        workers: Número de threads.

    Returns:
        Lista de HostInfo dos hosts ativos.
    """
    return _discovery_icmp(hosts, timeout, workers, privileged=False)


def _discovery_arp_tcp(
    hosts: list[str],
    timeout: float,
    workers: int,
) -> list[HostInfo]:
    """
    Descoberta combinando tabela ARP e TCP connect scan.
    Útil como fallback quando ICMP está bloqueado.

    Args:
        hosts: Lista de IPs para escanear.
        timeout: Timeout por host.
        workers: Número de threads.

    Returns:
        Lista de HostInfo dos hosts ativos.
    """
    alive_hosts: list[HostInfo] = []
    found_ips = set()

    # Passo 1: Ler tabela ARP
    print_info("Lendo tabela ARP do sistema...")
    arp_table = _parse_arp_table()
    hosts_set = set(hosts)

    for ip, mac in arp_table.items():
        if ip in hosts_set:
            host_info = HostInfo(ip_address=ip, is_alive=True, mac_address=mac)
            try:
                host_info.hostname = resolve_hostname(ip)
            except Exception:
                pass
            alive_hosts.append(host_info)
            found_ips.add(ip)

    if alive_hosts:
        print_info(f"Encontrados {len(alive_hosts)} host(s) na tabela ARP.")

    # Passo 2: TCP connect scan nos hosts não encontrados via ARP
    remaining_hosts = [ip for ip in hosts if ip not in found_ips]

    if remaining_hosts:
        print_info(f"Escaneando {len(remaining_hosts)} host(s) via TCP connect...")

        with get_progress_bar() as progress:
            task = progress.add_task(
                "Escaneando via TCP...",
                total=len(remaining_hosts),
            )

            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {
                    executor.submit(_tcp_connect_probe, ip, COMMON_PORTS, timeout): ip
                    for ip in remaining_hosts
                }

                for future in as_completed(futures):
                    try:
                        host_info = future.result()
                        if host_info.is_alive:
                            alive_hosts.append(host_info)
                    except Exception:
                        pass

                    progress.update(task, advance=1)

    return alive_hosts


def run_discovery(
    network: Optional[str] = None,
    timeout: float = DEFAULT_DISCOVERY_TIMEOUT,
    workers: int = DEFAULT_DISCOVERY_WORKERS,
    privileged: bool = True,
    port_scan: bool = False,
) -> DiscoveryResult:
    """
    Descobre hosts ativos em uma sub-rede.
    Tenta múltiplas estratégias:
    1. ICMP ping privilegiado (raw socket)
    2. ICMP ping não privilegiado
    3. Tabela ARP + TCP connect scan

    Se network não for informado, detecta a rede local automaticamente.
    Se port_scan=True, escaneia portas de infraestrutura/VoIP em cada host ativo.

    Args:
        network: Endereço de rede CIDR (ex: 192.168.1.0/24). Opcional.
        timeout: Timeout por host em segundos.
        workers: Número de threads simultâneas.
        privileged: Se True, tenta raw socket primeiro.
        port_scan: Se True, escaneia portas nos hosts encontrados.

    Returns:
        DiscoveryResult com lista de hosts encontrados.
    """
    # Auto-detectar rede se não informada
    if not network:
        network = detect_local_network()
        if network:
            print_info(f"Rede local detectada automaticamente: [bold]{network}[/bold]")
        else:
            console.print(
                "  [red]Erro:[/red] Não foi possível detectar a rede local. "
                "Informe a rede manualmente (ex: 192.168.1.0/24)."
            )
            return DiscoveryResult(network="desconhecida")

    result = DiscoveryResult(network=network)
    result.port_scan_enabled = port_scan

    if not validate_network(network):
        console.print(f"  [red]Erro:[/red] Rede inválida: {network}")
        return result

    hosts = get_network_hosts(network)
    result.total_hosts_scanned = len(hosts)

    if not hosts:
        console.print(f"  [yellow]Nenhum host para escanear em {network}[/yellow]")
        return result

    start_time = time.time()
    alive_hosts: list[HostInfo] = []

    # === ESTRATÉGIA 1: ICMP privilegiado ===
    if privileged:
        try:
            print_info("Tentando descoberta via ICMP (privilegiado)...")
            alive_hosts = _discovery_icmp(hosts, timeout, workers, privileged=True)
        except (SocketPermissionError, PermissionError):
            print_warning("Sem permissão para raw socket ICMP.")
            alive_hosts = []
        except Exception as e:
            print_warning(f"Erro no ICMP privilegiado: {e}")
            alive_hosts = []

    # === ESTRATÉGIA 2: ICMP não privilegiado (se estratégia 1 falhou) ===
    if not alive_hosts:
        try:
            print_info("Tentando descoberta via ICMP (não privilegiado)...")
            alive_hosts = _discovery_icmp_unprivileged(hosts, timeout, workers)
        except Exception as e:
            print_warning(f"Erro no ICMP não privilegiado: {e}")
            alive_hosts = []

    # === ESTRATÉGIA 3: ARP + TCP connect (se ICMP não encontrou nada) ===
    if not alive_hosts:
        print_warning("ICMP não encontrou hosts. Usando fallback ARP + TCP...")
        try:
            alive_hosts = _discovery_arp_tcp(hosts, timeout, workers)
        except Exception as e:
            print_warning(f"Erro no fallback ARP/TCP: {e}")
            alive_hosts = []

    # Ordenar por IP
    alive_hosts.sort(key=lambda h: tuple(int(p) for p in h.ip_address.split(".")))

    # Remover duplicatas
    seen_ips = set()
    unique_hosts = []
    for host in alive_hosts:
        if host.ip_address not in seen_ips:
            seen_ips.add(host.ip_address)
            unique_hosts.append(host)

    # === PORT SCAN (se habilitado) ===
    if port_scan and unique_hosts:
        print_info(f"Escaneando portas de infraestrutura/VoIP em {len(unique_hosts)} host(s)...")
        port_list_str = ", ".join(f"{p}/{s}" for p, s in sorted(INFRA_PORTS.items()))
        print_info(f"Portas: {port_list_str}")

        with get_progress_bar() as progress:
            task = progress.add_task(
                "Port scan...",
                total=len(unique_hosts),
            )

            with ThreadPoolExecutor(max_workers=min(workers, len(unique_hosts))) as executor:
                futures = {
                    executor.submit(
                        _scan_host_ports, host, INFRA_PORTS, DEFAULT_PORT_SCAN_TIMEOUT
                    ): host
                    for host in unique_hosts
                }

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception:
                        pass

                    progress.update(task, advance=1)

    result.hosts = unique_hosts
    result.hosts_alive = len(unique_hosts)
    result.scan_duration_sec = time.time() - start_time

    return result
