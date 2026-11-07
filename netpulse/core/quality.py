"""
Módulo de análise de qualidade de link para VoIP/Telefonia.
Calcula MOS Score usando o modelo E simplificado (ITU-T G.107).
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
    DEFAULT_QOS_COUNT,
    DEFAULT_QOS_INTERVAL,
    DEFAULT_PING_TIMEOUT,
    VOIP_CODECS,
    MOS_THRESHOLDS,
    VOIP_LIMITS,
)
from netpulse.models.results import QualityResult
from netpulse.core.ping import calculate_jitter
from netpulse.utils.network import resolve_hostname, resolve_to_ip
from netpulse.utils.formatting import console, print_warning


def calculate_r_factor(
    avg_latency_ms: float,
    jitter_ms: float,
    packet_loss_pct: float,
    codec: str = "g711",
) -> float:
    """
    Calcula o R-Factor baseado no modelo E simplificado (ITU-T G.107).

    O R-Factor varia de 0 a 100, onde:
    - 90-100: Excelente
    - 80-90: Bom
    - 70-80: Razoável
    - 60-70: Ruim
    - < 60: Muito ruim

    Fórmula simplificada:
        R = 93.2 - Id - Ie_eff

    Onde:
        Id = Delay Impairment (impacto da latência)
        Ie_eff = Effective Equipment Impairment (codec + perda de pacotes)

    Args:
        avg_latency_ms: Latência média em ms.
        jitter_ms: Jitter em ms.
        packet_loss_pct: Perda de pacotes em percentual.
        codec: Identificador do codec (g711, g729, g722).

    Returns:
        R-Factor (0-100).
    """
    codec_params = VOIP_CODECS.get(codec, VOIP_CODECS["g711"])
    ie = codec_params["ie"]        # Equipment Impairment Factor
    bpl = codec_params["bpl"]      # Packet Loss Robustness Factor

    # Latência efetiva (one-way delay) incluindo jitter buffer
    # Assumimos jitter buffer = 2 * jitter
    effective_latency = avg_latency_ms + (jitter_ms * 2) + 10  # 10ms de processamento

    # Id - Delay Impairment Factor
    # Modelo simplificado baseado em ITU-T G.107
    if effective_latency < 160:
        id_factor = 0.024 * effective_latency + 0.11 * max(effective_latency - 120, 0)
    else:
        id_factor = 0.024 * effective_latency + 0.11 * (effective_latency - 120)

    # Ie_eff - Effective Equipment Impairment Factor
    # Ie_eff = Ie + (95 - Ie) * Ppl / (Ppl + Bpl)
    if packet_loss_pct > 0:
        ie_eff = ie + (95 - ie) * (packet_loss_pct / (packet_loss_pct + bpl))
    else:
        ie_eff = ie

    # R-Factor
    r_factor = 93.2 - id_factor - ie_eff

    # Limitar entre 0 e 100
    r_factor = max(0.0, min(100.0, r_factor))

    return r_factor


def r_factor_to_mos(r_factor: float) -> float:
    """
    Converte R-Factor para MOS Score.

    Fórmula ITU-T G.107:
        Se R < 0: MOS = 1.0
        Se R > 100: MOS = 4.5
        Caso contrário:
            MOS = 1 + 0.035*R + 7*10^-6 * R * (R-60) * (100-R)

    Args:
        r_factor: Valor do R-Factor (0-100).

    Returns:
        MOS Score (1.0 - 4.5).
    """
    if r_factor < 0:
        return 1.0
    if r_factor > 100:
        return 4.5

    mos = 1 + 0.035 * r_factor + 7e-6 * r_factor * (r_factor - 60) * (100 - r_factor)

    return max(1.0, min(4.5, mos))


def classify_quality(mos: float) -> tuple[str, bool]:
    """
    Classifica a qualidade com base no MOS Score.

    Args:
        mos: MOS Score.

    Returns:
        Tupla (classificação_texto, adequado_para_voip).
    """
    if mos >= MOS_THRESHOLDS["excelente"]:
        return "Excelente", True
    elif mos >= MOS_THRESHOLDS["bom"]:
        return "Bom", True
    elif mos >= MOS_THRESHOLDS["razoavel"]:
        return "Razoável", False
    elif mos >= MOS_THRESHOLDS["ruim"]:
        return "Ruim", False
    else:
        return "Muito Ruim", False


def run_quality_analysis(
    target: str,
    count: int = DEFAULT_QOS_COUNT,
    interval: float = DEFAULT_QOS_INTERVAL,
    timeout: float = DEFAULT_PING_TIMEOUT,
    codec: str = "g711",
    privileged: bool = True,
) -> QualityResult:
    """
    Executa análise de qualidade de link com cálculo de MOS Score.

    Envia pacotes ICMP com intervalo curto para simular tráfego VoIP
    e calcula métricas de qualidade incluindo R-Factor e MOS Score
    baseados no modelo E simplificado (ITU-T G.107).

    Se privileged=True falhar por permissão, tenta com privileged=False.

    Args:
        target: IP ou hostname do alvo.
        count: Número de pacotes a enviar.
        interval: Intervalo entre pacotes (segundos).
        timeout: Timeout por pacote (segundos).
        codec: Codec VoIP para cálculo (g711, g729, g722).
        privileged: Se True, usa raw socket (requer root).

    Returns:
        QualityResult com análise completa incluindo MOS Score.
    """
    result = QualityResult(host=target, codec=codec)

    # Validar codec
    if codec not in VOIP_CODECS:
        console.print(
            f"  [red]Erro:[/red] Codec '{codec}' não suportado. "
            f"Use: {', '.join(VOIP_CODECS.keys())}"
        )
        return result

    # Resolver hostname
    ip = resolve_to_ip(target)
    if ip is None:
        console.print(f"  [red]Erro:[/red] Não foi possível resolver: {target}")
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
            payload_size=160,  # Simula pacote G.711 (20ms @ 64kbps)
            privileged=priv,
        )

    host_response = None

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

        # Coletar RTTs para cálculo de jitter
        if hasattr(host_response, 'rtts'):
            result.latencies = list(host_response.rtts)
        else:
            result.latencies = [host_response.avg_rtt] * host_response.packets_received

        result.jitter_ms = calculate_jitter(result.latencies)

        # Calcular R-Factor e MOS Score (ITU-T G.107)
        result.r_factor = calculate_r_factor(
            avg_latency_ms=result.avg_latency_ms,
            jitter_ms=result.jitter_ms,
            packet_loss_pct=result.packet_loss_pct,
            codec=codec,
        )

        result.mos_score = r_factor_to_mos(result.r_factor)

        # Classificar qualidade
        quality_text, voip_ok = classify_quality(result.mos_score)
        result.quality_rating = quality_text
        result.voip_suitable = voip_ok

        # Verificar limites individuais
        result.latency_ok = result.avg_latency_ms < VOIP_LIMITS["latency_ms"]
        result.jitter_ok = result.jitter_ms < VOIP_LIMITS["jitter_ms"]
        result.loss_ok = result.packet_loss_pct < VOIP_LIMITS["packet_loss_pct"]

    return result
