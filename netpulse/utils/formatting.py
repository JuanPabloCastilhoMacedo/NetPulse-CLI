"""
Formatação de saída: tabelas, cores e indicadores visuais usando Rich.
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich import box

from netpulse.config import MOS_THRESHOLDS, VOIP_LIMITS, VOIP_CODECS
from netpulse.models.results import (
    PingResult,
    DiscoveryResult,
    TracerouteResult,
    QualityResult,
)

console = Console()


def print_banner():
    """Exibe o banner do NetPulse CLI."""
    banner_text = Text()
    banner_text.append("🌐 NetPulse CLI", style="bold cyan")
    banner_text.append(" — ", style="dim")
    banner_text.append("Diagnóstico de Redes", style="bold white")

    panel = Panel(
        banner_text,
        box=box.DOUBLE_EDGE,
        border_style="cyan",
        padding=(0, 2),
    )
    console.print(panel)
    console.print()


def print_info(message: str):
    """Imprime mensagem informativa."""
    console.print(f"  [cyan]ℹ[/cyan]  {message}")


def print_success(message: str):
    """Imprime mensagem de sucesso."""
    console.print(f"  [green]✔[/green]  {message}")


def print_warning(message: str):
    """Imprime mensagem de aviso."""
    console.print(f"  [yellow]⚠[/yellow]  {message}")


def print_error(message: str):
    """Imprime mensagem de erro."""
    console.print(f"  [red]✖[/red]  {message}")


def get_progress_bar() -> Progress:
    """Retorna uma barra de progresso configurada."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=40),
        TaskProgressColumn(),
        console=console,
    )


def _latency_color(latency_ms: float) -> str:
    """Retorna a cor baseada na latência."""
    if latency_ms < 50:
        return "green"
    elif latency_ms < 100:
        return "yellow"
    elif latency_ms < 200:
        return "dark_orange"
    else:
        return "red"


def _loss_color(loss_pct: float) -> str:
    """Retorna a cor baseada na perda de pacotes."""
    if loss_pct == 0:
        return "green"
    elif loss_pct < 1:
        return "yellow"
    elif loss_pct < 5:
        return "dark_orange"
    else:
        return "red"


def _mos_color(mos: float) -> str:
    """Retorna a cor baseada no MOS Score."""
    if mos >= MOS_THRESHOLDS["excelente"]:
        return "green"
    elif mos >= MOS_THRESHOLDS["bom"]:
        return "cyan"
    elif mos >= MOS_THRESHOLDS["razoavel"]:
        return "yellow"
    elif mos >= MOS_THRESHOLDS["ruim"]:
        return "dark_orange"
    else:
        return "red"


def _bool_indicator(value: bool) -> str:
    """Retorna indicador visual booleano."""
    return "[green]✔ OK[/green]" if value else "[red]✖ FALHA[/red]"


def display_ping_result(result: PingResult):
    """Exibe o resultado do ping formatado."""
    console.print()

    target = result.host
    if result.resolved_name and result.resolved_name != result.host:
        target = f"{result.resolved_name} ({result.host})"

    title = f"🏓 Resultado do Ping — {target}"

    if not result.is_reachable:
        panel = Panel(
            "[red bold]Host inalcançável! Nenhuma resposta recebida.[/red bold]",
            title=title,
            border_style="red",
            box=box.ROUNDED,
        )
        console.print(panel)
        return

    table = Table(
        box=box.SIMPLE_HEAVY,
        show_header=True,
        header_style="bold cyan",
        title=title,
        title_style="bold white",
        padding=(0, 2),
    )

    table.add_column("Métrica", style="bold", min_width=20)
    table.add_column("Valor", justify="right", min_width=15)
    table.add_column("Status", justify="center", min_width=10)

    loss_color = _loss_color(result.packet_loss_pct)
    table.add_row(
        "Pacotes Enviados",
        str(result.packets_sent),
        "",
    )
    table.add_row(
        "Pacotes Recebidos",
        str(result.packets_received),
        "",
    )
    table.add_row(
        "Perda de Pacotes",
        f"[{loss_color}]{result.packet_loss_pct:.1f}%[/{loss_color}]",
        _bool_indicator(result.packet_loss_pct < VOIP_LIMITS["packet_loss_pct"]),
    )

    table.add_row("", "", "")

    lat_color = _latency_color(result.avg_latency_ms)
    table.add_row("Latência Mínima", f"{result.min_latency_ms:.2f} ms", "")
    table.add_row(
        "Latência Média",
        f"[{lat_color}]{result.avg_latency_ms:.2f} ms[/{lat_color}]",
        _bool_indicator(result.avg_latency_ms < VOIP_LIMITS["latency_ms"]),
    )
    table.add_row("Latência Máxima", f"{result.max_latency_ms:.2f} ms", "")

    jitter_color = "green" if result.jitter_ms < VOIP_LIMITS["jitter_ms"] else "red"
    table.add_row(
        "Jitter",
        f"[{jitter_color}]{result.jitter_ms:.2f} ms[/{jitter_color}]",
        _bool_indicator(result.jitter_ms < VOIP_LIMITS["jitter_ms"]),
    )

    console.print(table)
    console.print()


def display_discovery_result(result: DiscoveryResult):
    """Exibe o resultado da descoberta de hosts."""
    console.print()

    title = f"🔍 Descoberta de Hosts — {result.network}"

    if not result.hosts:
        panel = Panel(
            "[yellow]Nenhum host ativo encontrado na rede.[/yellow]",
            title=title,
            border_style="yellow",
            box=box.ROUNDED,
        )
        console.print(panel)
        return

    # Resumo
    summary_parts = [
        f"[bold]Rede:[/bold] {result.network}",
        f"[bold]Hosts escaneados:[/bold] {result.total_hosts_scanned}",
        f"[bold green]Hosts ativos:[/bold green] {result.hosts_alive}",
        f"[bold]Duração:[/bold] {result.scan_duration_sec:.1f}s",
    ]
    if result.port_scan_enabled:
        summary_parts.append("[bold cyan]Port Scan:[/bold cyan] Ativo")

    console.print(
        Panel(
            "  |  ".join(summary_parts),
            title=title,
            border_style="cyan",
            box=box.ROUNDED,
        )
    )

    # Tabela de hosts
    table = Table(
        box=box.SIMPLE_HEAVY,
        show_header=True,
        header_style="bold cyan",
        padding=(0, 1),
    )

    table.add_column("#", style="dim", justify="right", width=4)
    table.add_column("Endereço IP", style="bold", min_width=16)
    table.add_column("Hostname", min_width=20)
    table.add_column("Latência", justify="right", min_width=12)

    if result.port_scan_enabled:
        table.add_column("Portas/Serviços Abertos", min_width=30)

    table.add_column("Status", justify="center", min_width=8)

    for idx, host in enumerate(result.hosts, 1):
        latency_str = ""
        if host.latency_ms is not None:
            color = _latency_color(host.latency_ms)
            latency_str = f"[{color}]{host.latency_ms:.1f} ms[/{color}]"

        status = "[green]● Ativo[/green]" if host.is_alive else "[red]● Inativo[/red]"
        hostname = host.hostname or "—"

        if result.port_scan_enabled:
            ports_str = ""
            if host.open_ports:
                port_parts = []
                for p in sorted(host.open_ports, key=lambda x: x.port):
                    if p.is_open:
                        port_parts.append(f"[cyan]{p.port}[/cyan]/{p.service}")
                ports_str = ", ".join(port_parts) if port_parts else "[dim]—[/dim]"
            else:
                ports_str = "[dim]—[/dim]"

            table.add_row(str(idx), host.ip_address, hostname, latency_str, ports_str, status)
        else:
            table.add_row(str(idx), host.ip_address, hostname, latency_str, status)

    console.print(table)
    console.print()


def display_traceroute_result(result: TracerouteResult):
    """Exibe o resultado do traceroute."""
    console.print()

    target = result.destination
    if result.resolved_name and result.resolved_name != result.destination:
        target = f"{result.resolved_name} ({result.destination})"

    title = f"🛤️  Traceroute — {target}"

    table = Table(
        box=box.SIMPLE_HEAVY,
        show_header=True,
        header_style="bold cyan",
        title=title,
        title_style="bold white",
        padding=(0, 1),
    )

    table.add_column("Hop", style="bold", justify="right", width=5)
    table.add_column("Endereço", min_width=40)
    table.add_column("Latência", justify="right", min_width=12)

    for hop in result.hops:
        if hop.is_timeout:
            table.add_row(
                str(hop.hop_number),
                "[dim]* * * (sem resposta)[/dim]",
                "[dim]—[/dim]",
            )
        else:
            latency_str = ""
            if hop.latency_ms is not None:
                color = _latency_color(hop.latency_ms)
                latency_str = f"[{color}]{hop.latency_ms:.2f} ms[/{color}]"

            table.add_row(
                str(hop.hop_number),
                hop.display_address,
                latency_str,
            )

    console.print(table)

    if result.reached_destination:
        print_success(f"Destino alcançado em {result.total_hops} salto(s).")
    else:
        print_warning(f"Destino NÃO alcançado em {result.max_hops} saltos.")

    console.print()


def display_quality_result(result: QualityResult):
    """Exibe o resultado da análise de qualidade de link."""
    console.print()

    target = result.host
    if result.resolved_name and result.resolved_name != result.host:
        target = f"{result.resolved_name} ({result.host})"

    codec_info = VOIP_CODECS.get(result.codec, {})
    codec_name = codec_info.get("name", result.codec.upper())

    title = f"📊 Análise de Qualidade — {target}"

    # Painel MOS Score
    mos_color = _mos_color(result.mos_score)
    mos_text = Text()
    mos_text.append("MOS Score: ", style="bold white")
    mos_text.append(f"{result.mos_score:.2f}", style=f"bold {mos_color}")
    mos_text.append(f"  ({result.quality_rating})", style=f"{mos_color}")
    mos_text.append("\n")
    mos_text.append("R-Factor: ", style="bold white")
    mos_text.append(f"{result.r_factor:.1f}", style=f"bold {mos_color}")
    mos_text.append("\n")
    mos_text.append("Codec: ", style="bold white")
    mos_text.append(f"{codec_name}", style="bold cyan")
    mos_text.append("\n")
    mos_text.append("Adequado para VoIP: ", style="bold white")
    if result.voip_suitable:
        mos_text.append("✔ SIM", style="bold green")
    else:
        mos_text.append("✖ NÃO", style="bold red")

    console.print(
        Panel(
            mos_text,
            title=title,
            border_style=mos_color,
            box=box.DOUBLE_EDGE,
            padding=(1, 3),
        )
    )

    # Tabela de métricas detalhadas
    table = Table(
        box=box.SIMPLE_HEAVY,
        show_header=True,
        header_style="bold cyan",
        title="Métricas Detalhadas",
        title_style="bold white",
        padding=(0, 2),
    )

    table.add_column("Métrica", style="bold", min_width=22)
    table.add_column("Valor", justify="right", min_width=15)
    table.add_column("Limite VoIP", justify="right", min_width=12)
    table.add_column("Status", justify="center", min_width=10)

    lat_color = _latency_color(result.avg_latency_ms)
    table.add_row(
        "Latência Média",
        f"[{lat_color}]{result.avg_latency_ms:.2f} ms[/{lat_color}]",
        f"< {VOIP_LIMITS['latency_ms']:.0f} ms",
        _bool_indicator(result.latency_ok),
    )
    table.add_row(
        "Latência Mínima",
        f"{result.min_latency_ms:.2f} ms",
        "",
        "",
    )
    table.add_row(
        "Latência Máxima",
        f"{result.max_latency_ms:.2f} ms",
        "",
        "",
    )

    jitter_color = "green" if result.jitter_ok else "red"
    table.add_row(
        "Jitter",
        f"[{jitter_color}]{result.jitter_ms:.2f} ms[/{jitter_color}]",
        f"< {VOIP_LIMITS['jitter_ms']:.0f} ms",
        _bool_indicator(result.jitter_ok),
    )

    loss_color = _loss_color(result.packet_loss_pct)
    table.add_row(
        "Perda de Pacotes",
        f"[{loss_color}]{result.packet_loss_pct:.2f}%[/{loss_color}]",
        f"< {VOIP_LIMITS['packet_loss_pct']:.1f}%",
        _bool_indicator(result.loss_ok),
    )

    table.add_row("", "", "", "")
    table.add_row("Pacotes Enviados", str(result.packets_sent), "", "")
    table.add_row("Pacotes Recebidos", str(result.packets_received), "", "")

    console.print(table)
    console.print()
