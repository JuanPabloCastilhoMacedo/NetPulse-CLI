"""
Módulo de monitoramento contínuo em tempo real (Modo NOC).
Executa ciclos periódicos de análise de qualidade VoIP e dispara alertas
inteligentes com controle anti-spam via Telegram.
"""

import time
from datetime import datetime
from typing import Optional

from rich import box
from rich.panel import Panel
from rich.table import Table

from netpulse.config import (
    DEFAULT_WATCH_INTERVAL,
    DEFAULT_WATCH_COUNT,
    DEFAULT_MOS_THRESHOLD,
    DEFAULT_PING_TIMEOUT,
)
from netpulse.core.quality import run_quality_analysis
from netpulse.utils.formatting import (
    console,
    print_banner,
    print_error,
    print_info,
    print_success,
    print_warning,
    _latency_color,
    _loss_color,
    _mos_color,
)
from netpulse.utils.network import resolve_to_ip
from netpulse.utils.telegram import (
    get_telegram_credentials,
    send_noc_alert,
    send_noc_recovery,
    send_test_alert,
)


def run_watch(
    target: str,
    interval: float = DEFAULT_WATCH_INTERVAL,
    count: int = DEFAULT_WATCH_COUNT,
    codec: str = "g711",
    mos_threshold: float = DEFAULT_MOS_THRESHOLD,
    telegram_token: Optional[str] = None,
    telegram_chat_id: Optional[str] = None,
    test_alert: bool = False,
    privileged: bool = True,
):
    """
    Inicia o loop contínuo de monitoramento VoIP (Modo NOC).

    Args:
        target: Hostname ou endereço IP de destino.
        interval: Segundos entre cada ciclo de teste.
        count: Quantidade de pacotes ICMP por ciclo.
        codec: Codec VoIP para o cálculo de MOS (g711, g729, g722).
        mos_threshold: Limite mínimo de MOS para disparar alerta.
        telegram_token: Token do bot do Telegram (ou lido de .env).
        telegram_chat_id: Chat ID do Telegram (ou lido de .env).
        test_alert: Se True, envia mensagem de teste no Telegram ao iniciar.
        privileged: Se True, tenta utilizar raw socket.
    """
    print_banner()

    resolved_ip = resolve_to_ip(target)
    if not resolved_ip:
        print_error(f"Não foi possível resolver o endereço: {target}")
        return

    # Obter credenciais do Telegram
    token, chat_id = get_telegram_credentials(telegram_token, telegram_chat_id)
    telegram_enabled = bool(token and chat_id)

    # Envio de alerta de teste se solicitado
    if test_alert:
        if not telegram_enabled:
            print_error(
                "Não foi possível enviar alerta de teste: TELEGRAM_TOKEN ou "
                "TELEGRAM_CHAT_ID não definidos (verifique o arquivo .env ou informe as flags)."
            )
        else:
            print_info(f"Enviando alerta de teste para o Telegram (Chat ID: {chat_id})...")
            success, message = send_test_alert(token, chat_id, target)
            if success:
                print_success("Alerta de teste enviado com sucesso para o Telegram!")
            else:
                print_error(f"Falha ao enviar alerta de teste: {message}")
        console.print()

    # Informações de cabeçalho do Modo NOC
    telegram_status = (
        f"[green]Ativo[/green] (Chat ID: {chat_id})"
        if telegram_enabled
        else "[yellow]Desativado (sem credenciais)[/yellow]"
    )

    header_text = (
        f"[bold]Alvo:[/bold] [cyan]{target}[/cyan]"
        + (f" ({resolved_ip})" if resolved_ip != target else "")
        + f"\n[bold]Intervalo:[/bold] {interval}s   "
        f"[bold]Pacotes/Ciclo:[/bold] {count}   "
        f"[bold]Codec:[/bold] [cyan]{codec.upper()}[/cyan]   "
        f"[bold]MOS Mínimo:[/bold] [yellow]{mos_threshold:.2f}[/yellow]\n"
        f"[bold]Alertas Telegram:[/bold] {telegram_status}\n"
        f"[dim]Pressione Ctrl+C para encerrar o monitoramento.[/dim]"
    )

    console.print(
        Panel(
            header_text,
            title="📡 NetPulse NOC — Monitoramento Contínuo",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )
    console.print()

    # Estado interno e métricas acumuladas
    alert_active = False
    cycle_count = 0
    ok_count = 0
    degraded_count = 0
    offline_count = 0
    alerts_sent = 0
    start_time = datetime.now()

    try:
        while True:
            cycle_count += 1
            now_str = datetime.now().strftime("%H:%M:%S")

            # Executa medição de qualidade do ciclo
            quality_res = run_quality_analysis(
                target=resolved_ip,
                count=count,
                interval=0.05,
                timeout=DEFAULT_PING_TIMEOUT,
                codec=codec,
                privileged=privileged,
            )

            # Classificação do estado no ciclo
            if quality_res.packets_received == 0 or quality_res.packet_loss_pct >= 100.0:
                current_state = "OFFLINE"
                offline_count += 1
            elif quality_res.mos_score < mos_threshold:
                current_state = "DEGRADADO"
                degraded_count += 1
            else:
                current_state = "OK"
                ok_count += 1

            # Formatação dos campos da linha de console
            if current_state == "OFFLINE":
                status_badge = "[bold white on red] OFFLINE [/bold white on red]"
                lat_str = "[dim]—[/dim]"
                jit_str = "[dim]—[/dim]"
                loss_str = "[bold red]100.0%[/bold red]"
                mos_str = "[bold red]0.00[/bold red]"
            elif current_state == "DEGRADADO":
                status_badge = "[bold black on yellow] DEGRADADO [/bold black on yellow]"
                lat_col = _latency_color(quality_res.avg_latency_ms)
                lat_str = f"[{lat_col}]{quality_res.avg_latency_ms:.1f}ms[/{lat_col}]"
                jit_col = "green" if quality_res.jitter_ok else "red"
                jit_str = f"[{jit_col}]{quality_res.jitter_ms:.1f}ms[/{jit_col}]"
                loss_col = _loss_color(quality_res.packet_loss_pct)
                loss_str = f"[{loss_col}]{quality_res.packet_loss_pct:.1f}%[/{loss_col}]"
                mos_col = _mos_color(quality_res.mos_score)
                mos_str = f"[{mos_col}]{quality_res.mos_score:.2f}[/{mos_col}]"
            else:  # OK
                status_badge = "[bold black on green]   OK   [/bold black on green]"
                lat_col = _latency_color(quality_res.avg_latency_ms)
                lat_str = f"[{lat_col}]{quality_res.avg_latency_ms:.1f}ms[/{lat_col}]"
                jit_col = "green" if quality_res.jitter_ok else "red"
                jit_str = f"[{jit_col}]{quality_res.jitter_ms:.1f}ms[/{jit_col}]"
                loss_col = _loss_color(quality_res.packet_loss_pct)
                loss_str = f"[{loss_col}]{quality_res.packet_loss_pct:.1f}%[/{loss_col}]"
                mos_col = _mos_color(quality_res.mos_score)
                mos_str = f"[{mos_col}]{quality_res.mos_score:.2f}[/{mos_col}]"

            # Linha de log estilizada no terminal
            target_col = target[:16]
            console.print(
                f" [dim]{now_str}[/dim] │ [bold cyan]{target_col:<16}[/bold cyan] │ "
                f"Lat: {lat_str:>12} │ Jit: {jit_str:>10} │ Perda: {loss_str:>10} │ "
                f"MOS: {mos_str:>9} │ {status_badge}"
            )

            # Lógica Anti-Spam de Alertas via Telegram
            if current_state in ("OFFLINE", "DEGRADADO"):
                if not alert_active:
                    alert_active = True
                    if telegram_enabled:
                        ok, msg = send_noc_alert(
                            token=token,
                            chat_id=chat_id,
                            target=target,
                            ip=resolved_ip,
                            state=current_state,
                            result=quality_res,
                            mos_threshold=mos_threshold,
                        )
                        if ok:
                            alerts_sent += 1
                            console.print(
                                f"   [dim cyan]↳ 📨 Alerta de {current_state} enviado ao Telegram[/dim cyan]"
                            )
                        else:
                            console.print(
                                f"   [dim red]↳ ✖ Falha ao enviar alerta ao Telegram: {msg}[/dim red]"
                            )
            else:  # current_state == "OK"
                if alert_active:
                    alert_active = False
                    if telegram_enabled:
                        ok, msg = send_noc_recovery(
                            token=token,
                            chat_id=chat_id,
                            target=target,
                            ip=resolved_ip,
                            result=quality_res,
                        )
                        if ok:
                            alerts_sent += 1
                            console.print(
                                "   [dim green]↳ 📨 Notificação de RECUPERAÇÃO enviada ao Telegram[/dim green]"
                            )
                        else:
                            console.print(
                                f"   [dim red]↳ ✖ Falha ao enviar recuperação ao Telegram: {msg}[/dim red]"
                            )

            time.sleep(interval)

    except KeyboardInterrupt:
        console.print()
        print_warning("Monitoramento contínuo encerrado pelo operador.")
        console.print()

        # Resumo final da sessão de monitoramento
        duration = datetime.now() - start_time
        total_seconds = int(duration.total_seconds())
        mins, secs = divmod(total_seconds, 60)
        hours, mins = divmod(mins, 60)
        duration_fmt = f"{hours:02d}h {mins:02d}m {secs:02d}s" if hours else f"{mins:02d}m {secs:02d}s"

        summary_table = Table(
            box=box.ROUNDED,
            show_header=False,
            title="📊 Resumo da Sessão NOC",
            title_style="bold cyan",
            border_style="cyan",
            padding=(0, 2),
        )
        summary_table.add_column("Métrica", style="bold")
        summary_table.add_column("Valor", justify="right")

        summary_table.add_row("Duração do Monitoramento", duration_fmt)
        summary_table.add_row("Total de Ciclos Executados", str(cycle_count))
        summary_table.add_row("Ciclos em Estado OK", f"[green]{ok_count}[/green]")
        summary_table.add_row("Ciclos Degradados", f"[yellow]{degraded_count}[/yellow]")
        summary_table.add_row("Ciclos Offline", f"[red]{offline_count}[/red]")
        summary_table.add_row("Notificações Enviadas (Telegram)", str(alerts_sent))

        console.print(summary_table)
        console.print()
