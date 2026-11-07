"""
Módulo de integração com Telegram Bot API utilizando apenas bibliotecas nativas.
Gerencia envio de alertas de NOC e leitura de variáveis em arquivo .env.
"""

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from typing import Optional

from netpulse.models.results import QualityResult


def load_dotenv(filepath: str = ".env") -> dict[str, str]:
    """
    Carrega variáveis de ambiente a partir de um arquivo .env local sem bibliotecas externas.
    Atribui valores a os.environ apenas se a variável ainda não existir.
    """
    env_vars: dict[str, str] = {}
    if not os.path.isfile(filepath):
        return env_vars

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, val = line.split("=", 1)
                    key = key.strip()
                    val = val.strip().strip("'\"")
                    env_vars[key] = val
                    if key not in os.environ:
                        os.environ[key] = val
    except Exception:
        pass
    return env_vars


def get_telegram_credentials(
    token: Optional[str] = None,
    chat_id: Optional[str] = None,
    env_file: str = ".env",
) -> tuple[Optional[str], Optional[str]]:
    """
    Recupera as credenciais do Telegram priorizando argumentos CLI e recorrendo ao .env.
    """
    load_dotenv(env_file)
    final_token = token or os.environ.get("TELEGRAM_TOKEN")
    final_chat_id = chat_id or os.environ.get("TELEGRAM_CHAT_ID")
    return final_token, final_chat_id


def send_telegram_message(
    token: str,
    chat_id: str,
    text: str,
    parse_mode: Optional[str] = "Markdown",
) -> tuple[bool, str]:
    """
    Envia uma mensagem de texto formatada para o chat do Telegram especificado.

    Args:
        token: Token do bot fornecido pelo @BotFather.
        chat_id: ID do chat ou canal destinatário.
        text: Mensagem formatada.
        parse_mode: Tipo de formatação ("Markdown", "HTML" ou None).

    Returns:
        Tupla (sucesso: bool, mensagem_retorno: str).
    """
    if not token or not chat_id:
        return False, "TELEGRAM_TOKEN ou TELEGRAM_CHAT_ID não definidos."

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload: dict[str, str] = {
        "chat_id": str(chat_id),
        "text": text,
        "disable_web_page_preview": "true",
    }
    if parse_mode:
        payload["parse_mode"] = parse_mode

    data = urllib.parse.urlencode(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")

    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            res_body = response.read().decode("utf-8")
            res_data = json.loads(res_body)
            if res_data.get("ok"):
                return True, "Mensagem enviada com sucesso."
            return False, res_data.get("description", "Falha na API do Telegram.")
    except urllib.error.HTTPError as e:
        try:
            err_body = e.read().decode("utf-8")
            err_json = json.loads(err_body)
            desc = err_json.get("description", str(e))
            # Se falhou por formatação de Markdown, tenta reenvio como texto simples
            if parse_mode and "can't parse entities" in desc.lower():
                return send_telegram_message(token, chat_id, text, parse_mode=None)
            return False, f"HTTP {e.code}: {desc}"
        except Exception:
            return False, f"HTTP {e.code}: {e.reason}"
    except urllib.error.URLError as e:
        return False, f"Erro de conexão com a API do Telegram: {e.reason}"
    except Exception as e:
        return False, f"Erro inesperado: {str(e)}"


def send_test_alert(token: str, chat_id: str, target: str) -> tuple[bool, str]:
    """Envia mensagem de validação de conectividade do Bot."""
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    text = (
        "🔔 *[NetPulse NOC]* *Teste de Integração Telegram*\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"📍 *Alvo monitorado:* `{target}`\n"
        "✨ *Status:* Bot conectado com sucesso e operacional!\n"
        f"🕒 *Horário:* `{now_str}`\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "🚀 O NetPulse alertará neste canal caso ocorra degradação ou queda."
    )
    return send_telegram_message(token, chat_id, text)


def send_noc_alert(
    token: str,
    chat_id: str,
    target: str,
    ip: str,
    state: str,
    result: QualityResult,
    mos_threshold: float,
) -> tuple[bool, str]:
    """Envia notificação de alerta de host OFFLINE ou MOS DEGRADADO."""
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    target_display = target if target == ip else f"{target} ({ip})"

    if state == "OFFLINE":
        text = (
            "🔴 *[NetPulse NOC]* *ALERTA CRÍTICO: Host Inalcançável!*\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"📍 *Alvo:* `{target_display}`\n"
            "⚠️ *Status:* *OFFLINE* (100% de perda de pacotes)\n"
            f"📦 *Pacotes enviados:* {result.packets_sent}\n"
            f"🕒 *Horário:* `{now_str}`\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "🚨 *Ação necessária:* Verifique conectividade física, gateway ou firewall."
        )
    else:  # DEGRADADO
        text = (
            "⚠️ *[NetPulse NOC]* *ALERTA: Qualidade VoIP Degradada!*\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"📍 *Alvo:* `{target_display}`\n"
            "⚠️ *Status:* *DEGRADADO*\n"
            f"📉 *MOS Score:* *{result.mos_score:.2f}* (Mínimo: {mos_threshold:.2f})\n"
            f"📊 *R-Factor:* {result.r_factor:.1f}\n"
            f"⏱️ *Latência Média:* {result.avg_latency_ms:.2f} ms\n"
            f"⚡ *Jitter:* {result.jitter_ms:.2f} ms\n"
            f"📦 *Perda de Pacotes:* {result.packet_loss_pct:.1f}%\n"
            f"🎙️ *Codec Simulado:* {result.codec.upper()}\n"
            f"🕒 *Horário:* `{now_str}`\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "🚨 *Impacto:* Risco de voz metalizada, picotamentos e atraso na ligação."
        )

    return send_telegram_message(token, chat_id, text)


def send_noc_recovery(
    token: str,
    chat_id: str,
    target: str,
    ip: str,
    result: QualityResult,
) -> tuple[bool, str]:
    """Envia notificação informando restabelecimento dos parâmetros normais do link."""
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    target_display = target if target == ip else f"{target} ({ip})"

    text = (
        "✅ *[NetPulse NOC]* *RECUPERADO: Conexão Normalizada!*\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"📍 *Alvo:* `{target_display}`\n"
        "✨ *Status:* *ONLINE / OPERAÇÃO NORMAL*\n"
        f"📈 *MOS Score:* *{result.mos_score:.2f}* ({result.quality_rating})\n"
        f"📊 *R-Factor:* {result.r_factor:.1f}\n"
        f"⏱️ *Latência Média:* {result.avg_latency_ms:.2f} ms\n"
        f"⚡ *Jitter:* {result.jitter_ms:.2f} ms\n"
        f"📦 *Perda de Pacotes:* {result.packet_loss_pct:.1f}%\n"
        f"🕒 *Horário:* `{now_str}`\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "👍 Todos os parâmetros retornaram aos níveis ideais de operação."
    )
    return send_telegram_message(token, chat_id, text)
