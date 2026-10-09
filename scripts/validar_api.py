"""Homologação real das três licenças de teste usando o login do próprio app."""

import getpass
import json
import os
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QByteArray, QEventLoop, QSettings, QTimer, QUrl
from PySide6.QtNetwork import QNetworkReply, QNetworkRequest
from PySide6.QtWidgets import QApplication

from biosync_auth.app import CryptoEnvelope, LOGIN_URL, MAX_AUTH_RESPONSE_BYTES, MenuAutenticacao
from biosync_auth.paths import LOCAL_CONFIG_DIR, REPORTS_DIR


class JanelaTeste(MenuAutenticacao):
    def __init__(self):
        self.loop = QEventLoop()
        self.http_status = None
        self.closed = False
        self.completed = False
        self.processing_error = False
        super().__init__()

    def login_finished(self):
        if self.reply is not None:
            self.http_status = self.reply.attribute(QNetworkRequest.HttpStatusCodeAttribute)
        try:
            super().login_finished()
        except Exception:
            # Não imprimir exceções que possam conter credenciais.
            self.processing_error = True
        finally:
            self.completed = True
            self.loop.quit()

    def closeEvent(self, event):
        self.closed = True
        super().closeEvent(event)


def logout(network, session_id):
    """Encerra somente a sessão criada pelo teste; não altera a licença."""
    secret = os.environ["PWF_APP_SECRET"]
    crypto = CryptoEnvelope(secret)
    request = QNetworkRequest(QUrl(LOGIN_URL.replace("login.php", "logout.php")))
    request.setHeader(QNetworkRequest.ContentTypeHeader, "application/json")
    request.setRawHeader(b"Accept", b"application/json")
    request.setRawHeader(b"X-App-Secret", secret.encode())
    request.setTransferTimeout(15000)
    request.setAttribute(QNetworkRequest.RedirectPolicyAttribute, QNetworkRequest.ManualRedirectPolicy)
    reply = network.post(request, QByteArray(json.dumps(crypto.pack({"session_id": session_id})).encode()))
    loop = QEventLoop()
    timer = QTimer()
    timer.setSingleShot(True)
    timer.timeout.connect(reply.abort)
    reply.finished.connect(loop.quit)
    timer.start(20000)
    if not reply.isFinished():
        loop.exec()
    timer.stop()
    try:
        status = reply.attribute(QNetworkRequest.HttpStatusCodeAttribute)
        raw = bytes(reply.read(MAX_AUTH_RESPONSE_BYTES + 1))
        if len(raw) > MAX_AUTH_RESPONSE_BYTES:
            return False
        data = crypto.unpack(json.loads(raw))
        return (
            isinstance(data, dict) and data.get("success") is True
            and status is not None and 200 <= status < 300
            and reply.error() == QNetworkReply.NoError
        )
    except (ValueError, KeyError, TypeError, OverflowError, RecursionError):
        return False
    finally:
        reply.deleteLater()


def run_case(label, key, expected, app, settings):
    with patch("biosync_auth.app.QSettings", return_value=settings), \
            patch("biosync_auth.app.keyring.get_password", return_value=None), \
            patch("biosync_auth.app.keyring.set_password") as save, \
            patch("biosync_auth.app.keyring.delete_password"), \
            patch("biosync_auth.app.QMessageBox.warning") as warning, \
            patch("biosync_auth.app.QMessageBox.information") as info:
        settings.clear()
        window = JanelaTeste()
        window.input_key.setText(key)
        timer = QTimer()
        timer.setSingleShot(True)
        timer.timeout.connect(window.loop.quit)
        try:
            window.login()
            if window.reply is not None and not window.completed:
                timer.start(20000)
                window.loop.exec()
            timer.stop()
            messages = [str(call.args[2]) for call in warning.call_args_list]
            # Só registra códigos conhecidos; nunca salva resposta, Key ou sessão.
            code = next((code for code in (
                "EXPIRED", "BANNED", "INVALID_KEY", "HWID_MISMATCH", "DEVICE_LIMIT",
                "INVALID_SIGNATURE", "INVALID_SECRET", "INVALID_APP_SECRET",
                "RATE_LIMITED", "MAINTENANCE",
            ) if any(f"Código: {code}" in message for message in messages)), None)
            accepted = window.auth_response is not None
            result = {
                "caso": label, "esperado": expected,
                "http": window.http_status, "codigo": code,
                "autorizado": accepted,
                "concluido": window.completed,
                "erro_processamento": window.processing_error,
                "credencial_salva": save.called,
            }
            if expected == "SUCCESS":
                passed = accepted and window.closed and info.called and not warning.called
            else:
                passed = not accepted and not window.closed and code == expected and not info.called
            result["aprovado"] = bool(
                passed and window.completed and not window.processing_error and not save.called
            )
            if accepted:
                result["logout_confirmado"] = logout(
                    window.network, window.auth_response["session_id"]
                )
            return result
        finally:
            timer.stop()
            window.close()
            window.auth_response = None
            window.deleteLater()
            app.processEvents()


def main():
    if not os.environ.get("PWF_APP_SECRET", "").strip():
        if not sys.stdin.isatty():
            print("PWF_APP_SECRET ausente. Execute este script no terminal onde configurou o segredo.")
            return 2
        secret = getpass.getpass("App Secret (entrada oculta, não será salvo): ").strip()
        if not secret:
            print("Segredo não informado; nenhuma requisição enviada.")
            return 2
        os.environ["PWF_APP_SECRET"] = secret
    fixture = LOCAL_CONFIG_DIR / "keys_teste.local.json"
    if not fixture.is_file():
        print("Arquivo keys_teste.local.json ausente; nenhuma requisição enviada.")
        return 2
    try:
        keys = json.loads(fixture.read_text(encoding="utf-8"))
        if not all(isinstance(keys.get(name), str) and keys[name].strip()
                   for name in ("ativa", "expirada", "banida")):
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        print("Configuração das Keys inválida; nenhuma requisição enviada.")
        return 2
    app = QApplication.instance() or QApplication([])
    app.setQuitOnLastWindowClosed(False)
    results = []
    with tempfile.TemporaryDirectory() as directory:
        settings = QSettings(str(Path(directory) / "api-test.ini"), QSettings.IniFormat)
        settings.setFallbacksEnabled(False)
        for label, expected in (("ativa", "SUCCESS"), ("expirada", "EXPIRED"), ("banida", "BANNED")):
            result = run_case(label, keys[label], expected, app, settings)
            results.append(result)
            print(json.dumps(result, ensure_ascii=False), flush=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    report = REPORTS_DIR / "resultado_teste_api.local.json"
    report.write_text(json.dumps({"teste_real": True, "resultados": results}, ensure_ascii=False, indent=2), encoding="utf-8")
    print("Relatório salvo em reports/resultado_teste_api.local.json (sem credenciais).")
    return 0 if all(result["aprovado"] and result.get("logout_confirmado", True) for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
