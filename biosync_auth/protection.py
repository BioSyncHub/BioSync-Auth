"""Detecção limitada de depuradores; não detecta toda leitura de memória."""

import ctypes
import json
import os
from datetime import datetime, timezone
import socket
import sys
import time
from ctypes import wintypes
from .paths import LOCAL_CONFIG_DIR

SECURITY_ROLE_ID = "1516411676096991232"
WEBHOOK_CONFIG = LOCAL_CONFIG_DIR / "webhook.local.json"


def security_webhook_url():
    # Uma variável definida, inclusive vazia, tem prioridade sobre o arquivo local.
    if "BIOSYNC_SECURITY_WEBHOOK_URL" in os.environ:
        return os.environ["BIOSYNC_SECURITY_WEBHOOK_URL"].strip()
    try:
        config = json.loads(WEBHOOK_CONFIG.read_text(encoding="utf-8"))
        value = config.get("security_webhook_url", "")
        return value.strip() if isinstance(value, str) else ""
    except (OSError, ValueError, TypeError, AttributeError, RecursionError):
        return ""


def detect_debugger():
    if sys.gettrace() is not None:
        return "python_debugger"
    if sys.platform != "win32":
        return None
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.IsDebuggerPresent.argtypes = []
    kernel.IsDebuggerPresent.restype = wintypes.BOOL
    if kernel.IsDebuggerPresent():
        return "windows_debugger"
    kernel.GetCurrentProcess.argtypes = []
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CheckRemoteDebuggerPresent.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
    kernel.CheckRemoteDebuggerPresent.restype = wintypes.BOOL
    present = wintypes.BOOL()
    if not kernel.CheckRemoteDebuggerPresent(kernel.GetCurrentProcess(), ctypes.byref(present)):
        raise OSError(ctypes.get_last_error(), "Falha ao consultar o depurador.")
    return "windows_debugger" if present.value else None


def record_incident(settings, signal, hwid=None, attempted_key=""):
    try:
        count = int(settings.value("security/debugger_incidents", 0))
    except (ValueError, TypeError, OverflowError):
        count = 0
    count = min(max(count, 0) + 1, 1000000)
    settings.setValue("security/debugger_incidents", count)
    settings.sync()
    return {
        "event": "debugger_detected", "signal": signal, "attempt": count,
        "computer": socket.gethostname()[:100], "hwid": hwid,
        "attempted_key": attempted_key[:512], "key_verified": False,
        "ban_applied": False, "timestamp": int(time.time()),
    }


def incident_message(event):
    if event["attempt"] >= 3:
        return (
            f'Opa, {event["computer"]}! Parece que o seu poder de luta não é grande '
            "o suficiente para tankar o nosso botão de Ban. Sugiro que você mude de "
            "atitude rápido, antes que a gente mande você e as suas artimanhas para um ban de HWID."
        )
    return (
        "Opa, ligeirinho! Pensou que não iríamos nos prevenir disso, né? Muito esperto "
        "você... Que tal tentar usar o app de forma correta"
    )


def webhook_payload(event):
    def inline_value(value):
        return "`" + str(value).replace("`", "'").replace("\n", " ").replace("\r", " ")[:900] + "`"

    return {
        "content": f"<@&{SECURITY_ROLE_ID}>",
        "allowed_mentions": {"parse": [], "roles": [SECURITY_ROLE_ID]},
        "embeds": [{
            "title": "⚠️ Alerta de Segurança | Detecção de Memória",
            "description": (
                f'Depurador detectado. Ocorrência local nº {event["attempt"]}. '
                "Este sinal não comprova acesso à memória, fraude ou uso indevido. "
                "O acesso foi bloqueado e o encerramento solicitado. Nenhum ban foi aplicado."
            ),
            "color": 15158332,
            "fields": [
                {"name": "👤 Usuário Afetado", "value": inline_value(event["hwid"] or "HWID indisponível"), "inline": True},
                {"name": "🔑 Key Relacionada", "value": inline_value(event["attempted_key"] or "Não informada") + "\nKey tentada, não validada.", "inline": True},
                {"name": "💻 Computador", "value": inline_value(event["computer"]), "inline": True},
                {"name": "🔎 Sinal", "value": inline_value(event["signal"]), "inline": True},
                {"name": "📋 Ação Recomendada", "value": "Favor entrar em contato com o usuário para verificar a situação. Pode se tratar de um erro de execução, falso positivo ou uso indevido.", "inline": False},
            ],
            "footer": {"text": "Sistema de Monitoramento de Segurança"},
            "timestamp": datetime.fromtimestamp(event["timestamp"], timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        }],
    }


def encode_webhook(payload):
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
