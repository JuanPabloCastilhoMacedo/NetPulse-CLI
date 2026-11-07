"""
Motor de Ping ICMP com estatísticas detalhadas.
Utiliza a biblioteca icmplib para envio de pacotes ICMP.
"""

import statistics
from typing import Optional

from icmplib import ping as icmp_ping
from icmplib import ICMPLibError

try:
    from icmplib import SocketPermissionError
except ImportError:
    SocketPermissionError = PermissionError

from netpulse.config import (
    DEFAULT_PING_COUNT,
    DEFAULT_PING_INTERVAL,
    DEFAULT_PING_TIMEOUT,
    DEFAULT_PACKET_SIZE,
)
from netpulse.models.results import PingResult
from netpulse.utils.network import resolve_hostname, resolve_to_ip
from netpulse.utils.formatting import console, print_warning


def calculate_jitter(latencies: list[float]) -> float:
    """
    Calcula o jitter (variação de atraso) como a média das diferenças
    absolutas entre latências consecutivas (RFC 3550).
    """
    if len(latencies) < 2:
        return 0.0

    diffs = [abs(latencies[i] - latencies[i - 1]) for i in range(1, len(latencies))]
    return statistics.mean(diffs)


def run_ping(
    target: str,
    count: int = DEFAULT_PING_COUNT,
    interval: float = DEFAULT_PING_INTERVAL,
    timeout: float = DEFAULT_PING_TIMEOUT,
    packet_size: int = DEFAULT_PACKET_SIZE,
    privileged: bool = True,
) -> PingResult:
    """
    Executa ping ICMP para o alvo e retorna estatísticas detalhadas.
    Se privileged=True falhar por permissão, tenta com privileged=False.

    Args:
        target: IP ou hostname do alvo.
        count: Número de pacotes a enviar.
        interval: Intervalo entre pacotes (segundos).
        timeout: Timeout por pacote (segundos).
        packet_size: Tamanho do payload ICMP (bytes).
        privileged: Se True, usa raw socket (requer root).

    Returns:
        PingResult com todas as estatísticas.
    """
    result = PingResult(host=target)

    # Resolver hostname
    ip = resolve_to_ip(target)
    if ip is None:
        result.resolved_name = None
        return result

    if ip != target:
        result.resolved_name = target
        result.host = ip
    else:
        result.resolved_name = resolve_hostname(target)

    def _do_ping(priv: bool):
        """Executa o ping com o nível de privilégio especificado."""
        return icmp_ping(
            address=ip,
            count=count,
            interval=interval,
            timeout=timeout,
            payload_size=packet_size,
            privileged=priv,
        )

    host_response = None

    # Tentar com privilégio solicitado
    try:
        host_response = _do_ping(privileged)
    except (SocketPermissionError, PermissionError):
        if privileged:
            print_warning(
                "Sem permissão para raw socket. Tentando modo não privilegiado..."
            )
            try:
                host_response = _do_ping(False)
            except (ICMPLibError, OSError) as e:
                console.print(f"  [red]Erro ICMP:[/red] {e}")
                return result
        else:
            console.print(
                "  [red]Erro:[/red] Permissão negada. Execute com [bold]sudo[/bold] ou como administrador."
            )
            return result
    except ICMPLibError as e:
        console.print(f"  [red]Erro ICMP:[/red] {e}")
        return result
    except OSError as e:
        console.print(f"  [red]Erro de rede:[/red] {e}")
        return result

    if host_response is None:
        return result

    result.packets_sent = host_response.packets_sent
    result.packets_received = host_response.packets_received
    result.packet_loss_pct = host_response.packet_loss * 100

    if host_response.is_alive:
        result.min_latency_ms = host_response.min_rtt
        result.avg_latency_ms = host_response.avg_rtt
        result.max_latency_ms = host_response.max_rtt

        # Coletar RTTs individuais para cálculo de jitter
        # icmplib >= 3.0 usa rtts como lista
        if hasattr(host_response, 'rtts'):
            result.latencies = list(host_response.rtts)
        else:
            result.latencies = [host_response.avg_rtt] * host_response.packets_received

        result.jitter_ms = calculate_jitter(result.latencies)

    return result
