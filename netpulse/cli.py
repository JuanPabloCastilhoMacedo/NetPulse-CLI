"""
NetPulse CLI - Interface de Linha de Comando.
Ponto de entrada principal usando Click.
"""

import click
import sys

from netpulse import __version__, __app_name__
from netpulse.config import (
    DEFAULT_PING_COUNT,
    DEFAULT_PING_INTERVAL,
    DEFAULT_PING_TIMEOUT,
    DEFAULT_PACKET_SIZE,
    DEFAULT_MAX_HOPS,
    DEFAULT_TRACE_TIMEOUT,
    DEFAULT_QOS_COUNT,
    DEFAULT_QOS_INTERVAL,
    DEFAULT_DISCOVERY_TIMEOUT,
    DEFAULT_DISCOVERY_WORKERS,
    DEFAULT_WATCH_INTERVAL,
    DEFAULT_WATCH_COUNT,
    DEFAULT_MOS_THRESHOLD,
    VOIP_CODECS,
)
from netpulse.core.ping import run_ping
from netpulse.core.discovery import run_discovery, detect_local_network
from netpulse.core.traceroute import run_traceroute
from netpulse.core.quality import run_quality_analysis
from netpulse.core.watch import run_watch
from netpulse.utils.formatting import (
    print_banner,
    print_info,
    print_error,
    print_success,
    print_warning,
    display_ping_result,
    display_discovery_result,
    display_traceroute_result,
    display_quality_result,
    console,
)
from netpulse.utils.export import export_result
from netpulse.utils.network import validate_ip, validate_network, resolve_to_ip


@click.group(invoke_without_command=True)
@click.option("--version", "-v", is_flag=True, help="Exibe a versão do NetPulse CLI.")
@click.pass_context
def cli(ctx, version):
    """
    🌐 NetPulse CLI — Diagnóstico de infraestrutura de redes e telefonia IP.

    Ferramenta para ping avançado, descoberta de hosts, traceroute,
    análise de qualidade de link para VoIP e monitoramento contínuo (Modo NOC).
    """
    if version:
        console.print(f"{__app_name__} v{__version__}")
        sys.exit(0)

    if ctx.invoked_subcommand is None:
        print_banner()
        console.print(ctx.get_help())


@cli.command()
@click.argument("target")
@click.option(
    "--count", "-c",
    default=DEFAULT_PING_COUNT,
    show_default=True,
    help="Número de pacotes ICMP a enviar.",
)
@click.option(
    "--interval", "-i",
    default=DEFAULT_PING_INTERVAL,
    show_default=True,
    help="Intervalo entre pacotes (segundos).",
)
@click.option(
    "--timeout", "-t",
    default=DEFAULT_PING_TIMEOUT,
    show_default=True,
    help="Timeout por pacote (segundos).",
)
@click.option(
    "--size", "-s",
    default=DEFAULT_PACKET_SIZE,
    show_default=True,
    help="Tamanho do payload ICMP (bytes).",
)
@click.option(
    "--unprivileged", "-u",
    is_flag=True,
    default=False,
    help="Usar socket não privilegiado (sem root).",
)
def ping(target, count, interval, timeout, size, unprivileged):
    """🏓 Ping avançado com estatísticas detalhadas.

    Envia pacotes ICMP e calcula latência, jitter e perda de pacotes.

    Exemplos:

        netpulse ping 8.8.8.8

        netpulse ping google.com -c 20 -i 0.2

        netpulse ping 10.0.0.1 --count 50 --size 128
    """
    print_banner()
    print_info(f"Iniciando ping para [bold]{target}[/bold] ({count} pacotes)...")
    console.print()

    privileged = not unprivileged

    result = run_ping(
        target=target,
        count=count,
        interval=interval,
        timeout=timeout,
        packet_size=size,
        privileged=privileged,
    )

    display_ping_result(result)


@cli.command()
@click.argument("network_arg", required=False, default=None, metavar="[NETWORK]")
@click.option(
    "--network", "-n",
    default=None,
    help="Rede CIDR para escanear (ex: 192.168.1.0/24). Se omitido, detecta automaticamente.",
)
@click.option(
    "--timeout", "-t",
    default=DEFAULT_DISCOVERY_TIMEOUT,
    show_default=True,
    help="Timeout por host (segundos).",
)
@click.option(
    "--workers", "-w",
    default=DEFAULT_DISCOVERY_WORKERS,
    show_default=True,
    help="Número de threads simultâneas.",
)
@click.option(
    "--unprivileged", "-u",
    is_flag=True,
    default=False,
    help="Usar socket não privilegiado (sem root).",
)
@click.option(
    "--ports", "-p",
    is_flag=True,
    default=False,
    help="Escanear portas de infraestrutura/VoIP nos hosts encontrados.",
)
@click.option(
    "--output", "-o",
    default=None,
    type=click.Path(),
    help="Exportar resultado para arquivo (.json ou .md).",
)
def discover(network_arg, network, timeout, workers, unprivileged, ports, output):
    """🔍 Descoberta de hosts ativos em uma sub-rede.

    Varre a rede usando ICMP ping concorrente para identificar
    hosts que respondem. Se a rede não for informada, detecta
    a rede local automaticamente.

    Inclui fallback via tabela ARP e TCP connect scan quando
    ICMP está bloqueado.

    Use --ports para escanear portas de infraestrutura e VoIP
    (SSH, HTTP, HTTPS, SIP, SNMP, RDP, etc).

    Exemplos:

        netpulse discover

        netpulse discover 192.168.1.0/24

        netpulse discover --ports

        netpulse discover 192.168.1.0/24 -p

        netpulse discover -n 10.0.0.0/24 -p

        netpulse discover --ports --output relatorio.json

        netpulse discover -p -o laudo.md
    """
    print_banner()

    target_network = network or network_arg

    if target_network and not validate_network(target_network):
        print_error(f"Rede inválida: {target_network}")
        print_info("Use o formato CIDR, ex: 192.168.1.0/24")
        sys.exit(1)

    if target_network:
        print_info(f"Iniciando descoberta na rede [bold]{target_network}[/bold]...")
    else:
        print_info("Nenhuma rede informada. Detectando rede local...")

    if ports:
        print_info("Port scan de infraestrutura/VoIP: [cyan]ativado[/cyan]")

    console.print()

    privileged = not unprivileged

    result = run_discovery(
        network=target_network,
        timeout=timeout,
        workers=workers,
        privileged=privileged,
        port_scan=ports,
    )

    display_discovery_result(result)

    if result.hosts_alive > 0:
        print_success(
            f"{result.hosts_alive} host(s) ativo(s) encontrado(s) "
            f"em {result.scan_duration_sec:.1f}s."
        )
    else:
        print_warning("Nenhum host ativo encontrado na rede.")
        print_info(
            "Dica: Tente executar como administrador/root, ou verifique "
            "se o firewall permite ICMP/TCP na rede."
        )

    if output:
        console.print()
        export_result(result, output)


@cli.command()
@click.argument("target")
@click.option(
    "--max-hops", "-m",
    default=DEFAULT_MAX_HOPS,
    show_default=True,
    help="Número máximo de saltos.",
)
@click.option(
    "--timeout", "-t",
    default=DEFAULT_TRACE_TIMEOUT,
    show_default=True,
    help="Timeout por salto (segundos).",
)
@click.option(
    "--unprivileged", "-u",
    is_flag=True,
    default=False,
    help="Usar socket não privilegiado (sem root).",
)
def trace(target, max_hops, timeout, unprivileged):
    """🛤️  Traceroute com análise de saltos.

    Traça a rota até o destino, mostrando cada salto intermediário
    com latência e hostname.

    Utiliza múltiplas estratégias (ICMP raw, comando nativo, ICMP TTL)
    para funcionar em qualquer ambiente.

    Exemplos:

        netpulse trace 8.8.8.8

        netpulse trace google.com --max-hops 20

        netpulse trace 10.0.0.1 -u
    """
    print_banner()

    ip = resolve_to_ip(target)
    if ip is None:
        print_error(f"Não foi possível resolver o endereço: {target}")
        sys.exit(1)

    privileged = not unprivileged

    result = run_traceroute(
        target=target,
        max_hops=max_hops,
        timeout=timeout,
        privileged=privileged,
    )

    display_traceroute_result(result)


@cli.command()
@click.argument("target")
@click.option(
    "--count", "-c",
    default=DEFAULT_QOS_COUNT,
    show_default=True,
    help="Número de pacotes para análise.",
)
@click.option(
    "--interval", "-i",
    default=DEFAULT_QOS_INTERVAL,
    show_default=True,
    help="Intervalo entre pacotes (segundos).",
)
@click.option(
    "--timeout", "-t",
    default=DEFAULT_PING_TIMEOUT,
    show_default=True,
    help="Timeout por pacote (segundos).",
)
@click.option(
    "--codec",
    type=click.Choice(list(VOIP_CODECS.keys()), case_sensitive=False),
    default="g711",
    show_default=True,
    help="Codec VoIP para cálculo de MOS.",
)
@click.option(
    "--unprivileged", "-u",
    is_flag=True,
    default=False,
    help="Usar socket não privilegiado (sem root).",
)
@click.option(
    "--output", "-o",
    default=None,
    type=click.Path(),
    help="Exportar laudo para arquivo (.json ou .md).",
)
def quality(target, count, interval, timeout, codec, unprivileged, output):
    """📊 Análise de qualidade de link para VoIP/Telefonia.

    Envia pacotes simulando tráfego VoIP e calcula:
    - MOS Score (Mean Opinion Score) — escala 1.0 a 4.5
    - R-Factor (ITU-T G.107)
    - Jitter, latência e perda de pacotes
    - Adequação para telefonia IP

    Use --output para exportar o laudo técnico.

    Exemplos:

        netpulse quality 10.0.0.1

        netpulse quality pbx.empresa.com --codec g729 -c 100

        netpulse quality 192.168.1.1 --codec g722 -o laudo.json

        netpulse quality 10.0.0.1 -o relatorio.md
    """
    print_banner()

    ip = resolve_to_ip(target)
    if ip is None:
        print_error(f"Não foi possível resolver o endereço: {target}")
        sys.exit(1)

    codec_info = VOIP_CODECS[codec]
    print_info(f"Analisando qualidade do link para [bold]{target}[/bold]...")
    print_info(f"Codec: [cyan]{codec_info['name']}[/cyan] ({codec_info['bitrate_kbps']} kbps)")
    print_info(f"Pacotes: {count} | Intervalo: {interval}s")
    console.print()

    privileged = not unprivileged

    result = run_quality_analysis(
        target=target,
        count=count,
        interval=interval,
        timeout=timeout,
        codec=codec,
        privileged=privileged,
    )

    display_quality_result(result)

    if output:
        console.print()
        export_result(result, output)


@cli.command()
@click.argument("target")
@click.option(
    "--interval", "-i",
    default=DEFAULT_WATCH_INTERVAL,
    show_default=True,
    type=float,
    help="Intervalo entre ciclos de medição (segundos).",
)
@click.option(
    "--count", "-c",
    default=DEFAULT_WATCH_COUNT,
    show_default=True,
    type=int,
    help="Número de pacotes por ciclo de medição.",
)
@click.option(
    "--codec",
    type=click.Choice(list(VOIP_CODECS.keys()), case_sensitive=False),
    default="g711",
    show_default=True,
    help="Codec VoIP simulado para cálculo de MOS.",
)
@click.option(
    "--mos-threshold", "-m",
    default=DEFAULT_MOS_THRESHOLD,
    show_default=True,
    type=float,
    help="Nota mínima MOS para disparar alerta de degradação.",
)
@click.option(
    "--telegram-token",
    default=None,
    help="Token da API do Bot do Telegram (ou defina TELEGRAM_TOKEN no .env).",
)
@click.option(
    "--chat-id",
    default=None,
    help="Chat ID de destino no Telegram (ou defina TELEGRAM_CHAT_ID no .env).",
)
@click.option(
    "--test-alert",
    is_flag=True,
    default=False,
    help="Envia mensagem de teste ao Telegram antes de iniciar o monitoramento.",
)
@click.option(
    "--unprivileged", "-u",
    is_flag=True,
    default=False,
    help="Usar socket não privilegiado (sem root).",
)
def watch(target, interval, count, codec, mos_threshold, telegram_token, chat_id, test_alert, unprivileged):
    """📡 Monitoramento contínuo (Modo NOC) com alertas no Telegram.

    Executa medições contínuas de latência, jitter, perda de pacotes e MOS.
    Emite alertas instantâneos via Telegram com controle inteligente anti-spam
    quando a conexão cai (OFFLINE) ou o MOS fica abaixo do limite estabelecido.

    Exemplos:

        netpulse watch 10.0.0.1

        netpulse watch pbx.empresa.com --interval 5 --mos-threshold 3.8

        netpulse watch 8.8.8.8 --test-alert

        netpulse watch 192.168.1.1 --telegram-token "..." --chat-id "..."
    """
    privileged = not unprivileged

    run_watch(
        target=target,
        interval=interval,
        count=count,
        codec=codec,
        mos_threshold=mos_threshold,
        telegram_token=telegram_token,
        telegram_chat_id=chat_id,
        test_alert=test_alert,
        privileged=privileged,
    )


def main():
    """Função principal de entrada."""
    cli()


if __name__ == "__main__":
    main()
