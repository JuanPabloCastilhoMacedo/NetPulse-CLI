"""
Módulo de Traceroute com análise de saltos.
Utiliza icmplib para envio de pacotes ICMP com TTL incrementais.
Inclui fallbacks para ambientes sem raw socket (Windows sem admin, etc).
"""

import sys
import platform
import subprocess
import re

from icmplib import traceroute as icmp_traceroute
from icmplib import ping as icmp_ping
from icmplib import ICMPLibError

try:
    from icmplib import SocketPermissionError, ICMPSocketError
except ImportError:
    SocketPermissionError = PermissionError
    ICMPSocketError = OSError

from netpulse.config import DEFAULT_MAX_HOPS, DEFAULT_TRACE_TIMEOUT
from netpulse.models.results import TracerouteResult, TracerouteHop
from netpulse.utils.network import resolve_hostname, resolve_to_ip
from netpulse.utils.formatting import console, print_info, print_warning


def _traceroute_via_native_command(
    ip: str,
    max_hops: int = DEFAULT_MAX_HOPS,
    timeout: float = DEFAULT_TRACE_TIMEOUT,
) -> list[TracerouteHop]:
    """
    Fallback de traceroute usando o comando nativo do sistema operacional.
    Windows: tracert -d -w <timeout_ms> -h <max_hops> <ip>
    Linux/Mac: traceroute -n -w <timeout> -m <max_hops> <ip>

    Args:
        ip: Endereço IP de destino.
        max_hops: Número máximo de saltos.
        timeout: Timeout por salto (segundos).

    Returns:
        Lista de TracerouteHop.
    """
    hops = []
    system = platform.system().lower()
    timeout_ms = int(timeout * 1000)

    try:
        if system == "windows":
            cmd = [
                "tracert",
                "-d",
                "-w", str(timeout_ms),
                "-h", str(max_hops),
                ip,
            ]
        else:
            cmd = [
                "traceroute",
                "-n",
                "-w", str(int(timeout)),
                "-m", str(max_hops),
                ip,
            ]

        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max_hops * (timeout + 1) + 5,
        )

        output = process.stdout

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            if system == "windows":
                # Padrão Windows com IP no final:
                # "  1     1 ms     1 ms     1 ms  192.168.1.1"
                # "  2    <1 ms    <1 ms    <1 ms  10.0.0.1"
                # "  3     *        *        *     Esgotado o tempo limite do pedido."
                # "  3     *        *        *     Request timed out."

                # Tentar extrair hop com IP no final da linha
                match_ip = re.match(
                    r'^\s*(\d+)\s+(.+?)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*$',
                    line,
                )
                if match_ip:
                    hop_num = int(match_ip.group(1))
                    middle = match_ip.group(2)
                    hop_ip = match_ip.group(3)

                    # Extrair latência (primeiro valor numérico seguido de "ms")
                    latency_match = re.search(r'[<]?(\d+)\s*ms', middle)
                    latency = float(latency_match.group(1)) if latency_match else None

                    hop_hostname = None
                    try:
                        hop_hostname = resolve_hostname(hop_ip)
                    except Exception:
                        pass

                    hops.append(TracerouteHop(
                        hop_number=hop_num,
                        ip_address=hop_ip,
                        hostname=hop_hostname,
                        latency_ms=latency,
                        is_timeout=False,
                    ))
                    continue

                # Verificar timeout (linhas com * e sem IP válido no final)
                timeout_match = re.match(r'^\s*(\d+)\s+', line)
                if timeout_match:
                    has_stars = '*' in line
                    has_timed_out = (
                        'tempo' in line.lower()
                        or 'timed' in line.lower()
                        or 'esgotado' in line.lower()
                    )
                    # Se tem asteriscos ou mensagem de timeout, e não casou com IP
                    if has_stars or has_timed_out:
                        hop_num = int(timeout_match.group(1))
                        hops.append(TracerouteHop(
                            hop_number=hop_num,
                            is_timeout=True,
                        ))

            else:
                # Padrão Linux/Mac: " 1  192.168.1.1  0.567 ms  0.432 ms  0.398 ms"
                match = re.match(
                    r'^\s*(\d+)\s+([\d\.]+)\s+(\d+\.?\d*)\s*ms',
                    line,
                )
                if match:
                    hop_num = int(match.group(1))
                    hop_ip = match.group(2)
                    latency = float(match.group(3))

                    hop_hostname = None
                    try:
                        hop_hostname = resolve_hostname(hop_ip)
                    except Exception:
                        pass

                    hops.append(TracerouteHop(
                        hop_number=hop_num,
                        ip_address=hop_ip,
                        hostname=hop_hostname,
                        latency_ms=latency,
                        is_timeout=False,
                    ))
                    continue

                # Verificar timeout
                timeout_match = re.match(r'^\s*(\d+)\s+\*', line)
                if timeout_match:
                    hop_num = int(timeout_match.group(1))
                    hops.append(TracerouteHop(
                        hop_number=hop_num,
                        is_timeout=True,
                    ))

    except FileNotFoundError:
        print_warning("Comando traceroute/tracert não encontrado no sistema.")
    except subprocess.TimeoutExpired:
        print_warning("Timeout ao executar traceroute nativo.")
    except Exception as e:
        print_warning(f"Erro ao executar traceroute nativo: {e}")

    return hops


def _traceroute_via_ping_ttl(
    ip: str,
    max_hops: int = DEFAULT_MAX_HOPS,
    timeout: float = DEFAULT_TRACE_TIMEOUT,
) -> list[TracerouteHop]:
    """
    Fallback de traceroute usando icmplib.ping() com TTL incremental
    e privileged=False (não requer raw socket).

    Nota: com privileged=False, os saltos intermediários geralmente
    aparecem como timeout porque a API não extrai o IP de origem
    do ICMP Time Exceeded. Útil apenas como último recurso.

    Args:
        ip: Endereço IP de destino.
        max_hops: Número máximo de saltos.
        timeout: Timeout por salto (segundos).

    Returns:
        Lista de TracerouteHop.
    """
    hops = []

    for ttl in range(1, max_hops + 1):
        try:
            response = icmp_ping(
                address=ip,
                count=1,
                timeout=timeout,
                ttl=ttl,
                privileged=False,
            )

            if response.is_alive:
                hop_hostname = None
                try:
                    hop_hostname = resolve_hostname(ip)
                except Exception:
                    pass

                hops.append(TracerouteHop(
                    hop_number=ttl,
                    ip_address=ip,
                    hostname=hop_hostname,
                    latency_ms=response.avg_rtt,
                    is_timeout=False,
                ))
                break
            else:
                hops.append(TracerouteHop(
                    hop_number=ttl,
                    is_timeout=True,
                ))

        except Exception:
            hops.append(TracerouteHop(
                hop_number=ttl,
                is_timeout=True,
            ))

    return hops


def run_traceroute(
    target: str,
    max_hops: int = DEFAULT_MAX_HOPS,
    timeout: float = DEFAULT_TRACE_TIMEOUT,
    privileged: bool = True,
) -> TracerouteResult:
    """
    Executa traceroute para o destino e analisa cada salto.

    Estratégias por plataforma:

    Windows (sem raw socket):
        1. icmplib.traceroute() (raw socket, se privileged=True)
        2. Comando nativo tracert (melhor fallback no Windows)
        3. icmplib.ping() com TTL incremental (último recurso)

    Linux/Mac:
        1. icmplib.traceroute() (raw socket, se privileged=True)
        2. icmplib.ping() com TTL incremental
        3. Comando nativo traceroute

    Args:
        target: IP ou hostname do destino.
        max_hops: Número máximo de saltos.
        timeout: Timeout por salto (segundos).
        privileged: Se True, tenta raw socket primeiro.

    Returns:
        TracerouteResult com informações de cada salto.
    """
    result = TracerouteResult(destination=target, max_hops=max_hops)

    # Resolver alvo
    ip = resolve_to_ip(target)
    if ip is None:
        console.print(f"  [red]Erro:[/red] Não foi possível resolver: {target}")
        return result

    if ip != target:
        result.resolved_name = target
        result.destination = ip
    else:
        result.resolved_name = resolve_hostname(target)

    display_target = result.resolved_name or result.destination
    print_info(f"Traçando rota para {display_target} ({ip}), máximo {max_hops} saltos...")
    console.print()

    is_windows = sys.platform == "win32"

    # === ESTRATÉGIA 1: icmplib.traceroute() (raw socket) ===
    if privileged:
        try:
            hops = icmp_traceroute(
                address=ip,
                count=1,
                interval=0.05,
                timeout=timeout,
                max_hops=max_hops,
            )

            last_hop_number = 0

            for hop in hops:
                hop_number = hop.distance

                for gap_hop in range(last_hop_number + 1, hop_number):
                    result.hops.append(
                        TracerouteHop(
                            hop_number=gap_hop,
                            is_timeout=True,
                        )
                    )

                hop_hostname = None
                try:
                    hop_hostname = resolve_hostname(hop.address)
                except Exception:
                    pass

                trace_hop = TracerouteHop(
                    hop_number=hop_number,
                    ip_address=hop.address,
                    hostname=hop_hostname,
                    latency_ms=hop.avg_rtt,
                    is_timeout=False,
                )
                result.hops.append(trace_hop)
                last_hop_number = hop_number

                if hop.address == ip:
                    result.reached_destination = True
                    break

            result.total_hops = len(result.hops)

            if result.hops:
                return result

        except (SocketPermissionError, PermissionError):
            print_warning(
                "Sem permissão para raw socket. Tentando fallback..."
            )
        except (ICMPSocketError, ICMPLibError, OSError) as e:
            print_warning(f"Erro no traceroute ICMP: {e}. Tentando fallback...")

    # === FALLBACK: ordem depende da plataforma ===
    if is_windows:
        # No Windows, o comando nativo tracert é muito superior ao ping TTL
        # porque o ping não-privilegiado não extrai IPs intermediários

        # Fallback 2 (Windows): comando nativo tracert
        try:
            print_info("Usando tracert nativo do Windows...")
            native_hops = _traceroute_via_native_command(ip, max_hops, timeout)

            if native_hops:
                result.hops = native_hops
                result.total_hops = len(native_hops)

                for hop in native_hops:
                    if not hop.is_timeout and hop.ip_address == ip:
                        result.reached_destination = True
                        break

                # Verificar qualidade: se temos hops com IP, retorna
                hops_with_ip = [h for h in native_hops if not h.is_timeout]
                if hops_with_ip:
                    return result

        except Exception as e:
            print_warning(f"Tracert nativo falhou: {e}")

        # Fallback 3 (Windows): ping TTL (último recurso)
        try:
            print_info("Usando traceroute via ping com TTL incremental...")
            fallback_hops = _traceroute_via_ping_ttl(ip, max_hops, timeout)

            if fallback_hops:
                result.hops = fallback_hops
                result.total_hops = len(fallback_hops)

                for hop in fallback_hops:
                    if not hop.is_timeout and hop.ip_address == ip:
                        result.reached_destination = True
                        break

                return result

        except Exception as e:
            print_warning(f"Fallback TTL falhou: {e}")

    else:
        # Linux/Mac: ping TTL funciona melhor com raw sockets disponíveis

        # Fallback 2 (Linux/Mac): ping TTL
        try:
            print_info("Usando traceroute via ping com TTL incremental...")
            fallback_hops = _traceroute_via_ping_ttl(ip, max_hops, timeout)

            if fallback_hops:
                result.hops = fallback_hops
                result.total_hops = len(fallback_hops)

                for hop in fallback_hops:
                    if not hop.is_timeout and hop.ip_address == ip:
                        result.reached_destination = True
                        break

                hops_with_ip = [h for h in fallback_hops if not h.is_timeout]
                if hops_with_ip:
                    return result

        except Exception as e:
            print_warning(f"Fallback TTL falhou: {e}")

        # Fallback 3 (Linux/Mac): comando nativo traceroute
        try:
            print_info("Usando traceroute nativo do sistema operacional...")
            native_hops = _traceroute_via_native_command(ip, max_hops, timeout)

            if native_hops:
                result.hops = native_hops
                result.total_hops = len(native_hops)

                for hop in native_hops:
                    if not hop.is_timeout and hop.ip_address == ip:
                        result.reached_destination = True
                        break

                return result

        except Exception as e:
            print_warning(f"Traceroute nativo falhou: {e}")

    # Se nenhuma estratégia funcionou
    if not result.hops:
        console.print(
            "  [red]Erro:[/red] Todas as estratégias de traceroute falharam. "
            "Verifique sua conexão e permissões."
        )

    return result
