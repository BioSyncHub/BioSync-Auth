"""BioSync Menu — Python 3 / PySide6, com login real no PWF Auth."""

import base64
import hashlib
import hmac
import json
import math
import os
import random
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
import sys
import time

import keyring
from .protection import detect_debugger, encode_webhook, incident_message, record_incident, security_webhook_url, webhook_payload
from .paths import ASSETS_DIR
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from PySide6.QtCore import (
    QByteArray, QEasingCurve, QEvent, QRectF, QSettings, QSize, Qt, QTimer, QUrl,
    QVariantAnimation,
)
from PySide6.QtGui import (
    QColor, QCursor, QDesktopServices, QFontDatabase, QIcon, QImageReader, QLinearGradient,
    QMovie, QPainter, QPixmap,
)
from PySide6.QtNetwork import QNetworkAccessManager, QNetworkReply, QNetworkRequest
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QFrame, QGraphicsDropShadowEffect, QHBoxLayout,
    QLabel, QLineEdit, QMessageBox as QtMessageBox, QPushButton, QVBoxLayout, QWidget,
)

ASSETS = ASSETS_DIR
LOGIN_URL = "https://pwfauth.com/api/auth/login.php"
VAULT_SERVICE = "BioSyncMenu.PWFAuth"
MAX_AUTH_RESPONSE_BYTES = 1024 * 1024

# QSS controla cores, gradientes, bordas, tipografia e estados dos controles.
# Qt não possui a propriedade 'background-gradient': use background-color.
ESTILO_TELA = """
QWidget { font-family: 'Segoe UI'; color: #dddce5; font-size: 14px; }
QWidget#TelaPrincipal { background-color: #0b0c10; }
QFrame#Painel {
    background: transparent;
    border: 1px solid #3a3544; border-radius: 12px;
}
QLabel#Titulo { font-size: 44px; font-weight: 900; color: white; }
QLabel#Subtitulo { color: #aaa5b6; font-size: 13px; }
QLabel#KeyIcon { color: #d75aff; font-size: 24px; }
QFrame#KeyBorda {
    background-color: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 #d52fff, stop:0.48 #9975ef, stop:1 #00ff73);
    border-radius: 8px;
}
QFrame#KeyInterior { background-color: #090b10; border-radius: 6px; }
QLineEdit { background: transparent; border: none; color: #f0ecf8;
    font-size: 16px; padding: 8px 0; selection-background-color: #803bb3; }
QLineEdit:disabled { color: #817b8d; }
QPushButton { border-radius: 5px; padding: 8px; }
QPushButton#BotaoEntrar {
    background-color: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 #7820b7, stop:0.46 #35204e, stop:1 #00a94d);
    border: 2px solid qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 #e15aff, stop:0.5 #a48bff, stop:1 #37ff7d);
    border-radius: 10px; color: #ffffff;
    font-family: 'Bahnschrift'; font-size: 22px; font-weight: bold;
}
QPushButton#BotaoEntrar:hover {
    background-color: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 #9a29df, stop:0.46 #493065, stop:1 #00ce5e);
}
QPushButton#BotaoEntrar:pressed { background-color: #472065; }
QPushButton#BotaoEntrar:disabled { color: #aaa4b4; border-color: #625b6e; }
QCheckBox { spacing: 10px; color: #c8c5cf; }
QCheckBox::indicator { width: 20px; height: 20px; border: 1px solid #b4aebf;
    border-radius: 2px; background-color: #0c0d12; }
QCheckBox::indicator:checked { background-color: #9f36d4; border-color: #e3bcff; }
QCheckBox::indicator:hover { border-color: #e063ff; }
QPushButton#LinkEsqueci { border: none; padding: 0; color: #cf39ff;
    text-decoration: underline; background: transparent; }
QPushButton#LinkEsqueci:hover { color: #ed9aff; }
QFrame#Linha { background-color: #35333d; border: none; }
QLabel#Divisor { color: #888393; }
QPushButton#BotaoSocial { background-color: #0b0912; border: 1px solid #b32aff; }
QPushButton#BotaoSocial:hover { background-color: #241032; }
QPushButton#BotaoLoja { background-color: #080e0b; border: 1px solid #00f263; }
QPushButton#BotaoLoja:hover { background-color: #0b2c19; }
QPushButton:focus { border-color: #efe6ff; }
QMessageBox { background-color: #0b0c10; }
QMessageBox QPushButton { background-color: #492061; min-width: 80px; }
QLabel#TituloMensagem { color: #eee8f7; font-size: 14px; font-weight: bold; }
QPushButton#BotaoMensagem { background-color: #492061; border: 1px solid #a345d9;
    min-width: 80px; padding: 8px 18px; }
QPushButton#BotaoMensagem:hover { background-color: #652c85; border-color: #e28cff; }
QPushButton#BotaoMensagem:pressed { background-color: #351448; }
QPushButton#BotaoFechar { background: transparent; border: none; padding: 2px;
    min-width: 0px; border-radius: 6px; }
QPushButton#BotaoFechar:hover { background-color: #30123d; }
QPushButton#BotaoFechar:pressed { background-color: #481e58; }
QWidget#Cabecalho { background: transparent; }
QMessageBox { border: 1px solid #74418d; border-radius: 8px; }
"""

ERROR_MESSAGES = {
    "INVALID_KEY": "Chave inválida. Confira a Key e tente novamente.",
    "EXPIRED": "Sua licença expirou. Renove na loja oficial.",
    "HWID_MISMATCH": "Esta Key está vinculada a outro computador. Entre em contato com o suporte.",
    "DEVICE_LIMIT": "O limite de dispositivos desta licença foi atingido.",
    "BANNED": "Esta licença foi bloqueada. Entre em contato com o suporte.",
    "PAUSED": "Esta licença está pausada. Entre em contato com o suporte.",
    "MAINTENANCE": "O serviço está em manutenção. Tente novamente mais tarde.",
    "MISSING_FIELDS": "A API não recebeu todos os dados necessários para autenticar.",
    "INVALID_APP_SECRET": "O App Secret está incorreto. Verifique a configuração do aplicativo.",
    "INVALID_SECRET": "O App Secret está incorreto. Verifique a configuração do aplicativo.",
    "TOO_MANY_ATTEMPTS": "Muitas tentativas. Aguarde antes de tentar novamente.",
    "RATE_LIMITED": "Limite de requisições atingido. Aguarde e tente novamente.",
    "INVALID_SIGNATURE": "A API recusou a assinatura. Verifique o App Secret e o relógio do computador.",
}


def collect_hwid():
    """Fingerprint estável da instalação, sem enviar o identificador bruto."""
    if sys.platform == "win32":
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\Cryptography", 0,
                            winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
            machine_id = winreg.QueryValueEx(key, "MachineGuid")[0]
    elif sys.platform == "darwin":
        import subprocess
        import plistlib
        result = subprocess.run(
            ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice", "-a"],
            capture_output=True, check=True, timeout=5,
        )
        machine_id = plistlib.loads(result.stdout)[0]["IOPlatformUUID"]
    else:
        machine_id = ""
        for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            if Path(path).is_file():
                machine_id = Path(path).read_text().strip()
                break
    if not machine_id:
        raise ValueError("Identificador da máquina indisponível.")
    return hashlib.sha256(f"biosync-v1:{machine_id}".encode()).hexdigest()


class CryptoEnvelope:
    """Envelope AES-256-CBC/HMAC-SHA256 documentado pelo PWF Auth."""

    def __init__(self, secret):
        self.enc_key = hashlib.sha256(f"enc:{secret}".encode()).digest()
        self.mac_key = hashlib.sha256(f"mac:{secret}".encode()).digest()

    def pack(self, payload):
        raw = json.dumps(payload, separators=(",", ":")).encode()
        padder = padding.PKCS7(128).padder()
        padded = padder.update(raw) + padder.finalize()
        iv = os.urandom(16)
        encryptor = Cipher(algorithms.AES(self.enc_key), modes.CBC(iv)).encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        p = base64.b64encode(iv + ciphertext).decode()
        t = int(time.time())
        s = hmac.new(self.mac_key, f"{p}{t}".encode(), hashlib.sha256).hexdigest()
        return {"p": p, "t": t, "s": s}

    def unpack(self, envelope):
        p, t, signature = envelope["p"], envelope["t"], envelope["s"]
        if not isinstance(p, str) or type(t) is not int or not isinstance(signature, str):
            raise ValueError("Envelope inválido.")
        if not 0 <= t <= 2**63 - 1:
            raise ValueError("Timestamp da resposta inválido.")
        expected = hmac.new(self.mac_key, f"{p}{t}".encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            raise ValueError("Assinatura da resposta inválida.")
        if abs(time.time() - t) > 300:
            raise ValueError("Relógio fora de sincronia. Ajuste a data e a hora do computador.")
        raw = base64.b64decode(p, validate=True)
        if len(raw) < 32 or len(raw) % 16:
            raise ValueError("Resposta criptografada inválida.")
        decryptor = Cipher(algorithms.AES(self.enc_key), modes.CBC(raw[:16])).decryptor()
        padded = decryptor.update(raw[16:]) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return json.loads(unpadder.update(padded) + unpadder.finalize())


def icon_svg(body, color):
    svg = f'<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24"><g fill="none" stroke="{color}" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">{body}</g></svg>'
    pixmap = QPixmap()
    pixmap.loadFromData(QByteArray(svg.encode()), "SVG")
    return QIcon(pixmap)


def glow(widget, color, radius=18):
    effect = QGraphicsDropShadowEffect(widget)
    effect.setColor(QColor(color))
    effect.setBlurRadius(radius)
    effect.setOffset(0, 0)
    widget.setGraphicsEffect(effect)


@lru_cache(maxsize=1)
def load_fonts():
    # Também permite renderizar a prévia offscreen no Windows.
    if sys.platform == "win32":
        directory = Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts"
        for name in ("segoeui.ttf", "segoeuib.ttf", "bahnschrift.ttf"):
            path = directory / name
            if path.is_file():
                QFontDatabase.addApplicationFont(str(path))


class BotaoAnimado(QPushButton):
    """Desloca as setas no hover sem mover o texto ou alterar o layout."""

    def __init__(self, text="  ENTRAR", parent=None):
        super().__init__(text, parent)
        self.setObjectName("BotaoEntrar")
        self.setIconSize(QSize(40, 28))
        arrows = icon_svg(
            '<path d="m3 4 8 8-8 8M12 4l8 8-8 8"/>', "#d7a0ff"
        ).pixmap(28, 28)
        self._frames = []
        for offset in (0, 4, 8, 4):
            frame = QPixmap(self.iconSize())
            frame.fill(Qt.transparent)
            painter = QPainter(frame)
            painter.drawPixmap(offset, 0, arrows)
            painter.end()
            self._frames.append(QIcon(frame))
        self._frame_index = 0
        self.setIcon(self._frames[0])
        self._hover_timer = QTimer(self)
        self._hover_timer.setInterval(150)
        self._hover_timer.timeout.connect(self._advance_frame)

    def _advance_frame(self):
        self._frame_index = (self._frame_index + 1) % len(self._frames)
        self.setIcon(self._frames[self._frame_index])

    def _stop_animation(self):
        self._hover_timer.stop()
        self._frame_index = 0
        self.setIcon(self._frames[0])

    def enterEvent(self, event):
        super().enterEvent(event)
        if self.isEnabled():
            self._hover_timer.start()

    def leaveEvent(self, event):
        self._stop_animation()
        super().leaveEvent(event)

    def changeEvent(self, event):
        super().changeEvent(event)
        if event.type() == QEvent.EnabledChange:
            if self.isEnabled() and self.isVisible() and self.underMouse():
                self._hover_timer.start()
            else:
                self._stop_animation()

    def hideEvent(self, event):
        self._stop_animation()
        super().hideEvent(event)


class BotaoNeon(QPushButton):
    """Brilho que surge suavemente e pulsa enquanto o mouse está no botão."""

    def __init__(self, text, color, parent=None):
        super().__init__(text, parent)
        self._neon_color = QColor(color)
        self._hovered = False
        self._strength = 0.0
        self._glow = QGraphicsDropShadowEffect(self)
        self._glow.setOffset(0, 0)
        self.setGraphicsEffect(self._glow)
        self._animation = QVariantAnimation(self)
        self._animation.setEasingCurve(QEasingCurve.InOutSine)
        self._animation.valueChanged.connect(self._apply_glow)
        self._animation.finished.connect(self._start_pulse)
        self._apply_glow(0.0)

    def _apply_glow(self, value):
        self._strength = float(value)
        color = QColor(self._neon_color)
        color.setAlphaF(self._strength * 0.8)
        self._glow.setColor(color)
        self._glow.setBlurRadius(8 + 16 * self._strength)

    def _fade_to(self, strength):
        self._animation.stop()
        self._animation.setLoopCount(1)
        self._animation.setDuration(180)
        self._animation.setKeyValues([(0.0, self._strength), (1.0, strength)])
        self._animation.start()

    def _start_pulse(self):
        if self._hovered and self.isEnabled() and self.isVisible():
            self._animation.setDuration(1400)
            self._animation.setLoopCount(-1)
            self._animation.setKeyValues([(0.0, 0.65), (0.5, 1.0), (1.0, 0.65)])
            self._animation.start()

    def enterEvent(self, event):
        super().enterEvent(event)
        if self.isEnabled():
            self._hovered = True
            self._fade_to(0.65)

    def leaveEvent(self, event):
        self._hovered = False
        self._fade_to(0.0)
        super().leaveEvent(event)

    def _reset_glow(self):
        self._hovered = False
        self._animation.stop()
        self._apply_glow(0.0)

    def hideEvent(self, event):
        self._reset_glow()
        super().hideEvent(event)

    def changeEvent(self, event):
        super().changeEvent(event)
        if event.type() == QEvent.EnabledChange and not self.isEnabled():
            self._reset_glow()


class Cabecalho(QWidget):
    """Cabeçalho fixo, com botão X e cursor de seleção."""

    def __init__(self, window, title="", selection_cursor=None):
        super().__init__(window)
        self.setObjectName("Cabecalho")
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        if title:
            label = QLabel(title)
            label.setObjectName("TituloMensagem")
            row.addWidget(label)
        row.addStretch()
        self.close_button = BotaoNeon("", "#cf39ff", self)
        self.close_button.setObjectName("BotaoFechar")
        self.close_button.setFixedSize(34, 34)
        self.close_button.setIconSize(QSize(28, 28))
        icon = QIcon(str(ASSETS / "icons" / "Emblema X Neon Futurista.png"))
        if icon.isNull():
            self.close_button.setText("×")
        else:
            self.close_button.setIcon(icon)
        self.close_button.setToolTip("Fechar")
        self.close_button.setAccessibleName("Fechar janela")
        self.close_button.setAutoDefault(False)
        self.close_button.setCursor(selection_cursor or QCursor(Qt.PointingHandCursor))
        self.close_button.clicked.connect(window.close)
        row.addWidget(self.close_button)

class QMessageBox(QtMessageBox):
    """Alertas do BioSync sem barra nativa e com botões neon animados."""

    def __init__(self, parent, title, text, icon):
        super().__init__(parent)
        self.setWindowFlags(Qt.Dialog | Qt.FramelessWindowHint)
        self.setWindowTitle(title)
        self.setStyleSheet(ESTILO_TELA)
        self.setTextFormat(Qt.PlainText)
        self.setText(text)
        self.setIcon(icon)
        self.setCursor(parent.cursor())
        button = BotaoNeon("OK", "#cf39ff", self)
        button.setObjectName("BotaoMensagem")
        button.setCursor(parent.cursor_selecao)
        self.addButton(button, QtMessageBox.AcceptRole)
        self.setDefaultButton(button)
        self.setEscapeButton(button)
        self.header = Cabecalho(self, title, parent.cursor_selecao)
        # Insere o cabeçalho acima do layout interno, preservando ícone e texto.
        grid = self.layout()
        columns = grid.columnCount()
        items = []
        while grid.count():
            position = grid.getItemPosition(0)
            items.append((grid.takeAt(0), position))
        for item, (row, column, row_span, column_span) in items:
            grid.addItem(item, row + 1, column, row_span, column_span)
        grid.addWidget(self.header, 0, 0, 1, columns)
        grid.setContentsMargins(18, 10, 18, 18)
        grid.setVerticalSpacing(14)

    def showEvent(self, event):
        super().showEvent(event)
        frame = self.frameGeometry()
        frame.moveCenter(self.parentWidget().frameGeometry().center())
        self.move(frame.topLeft())

    @staticmethod
    def warning(parent, title, text):
        return QMessageBox(parent, title, text, QtMessageBox.Warning).exec()

    @staticmethod
    def information(parent, title, text):
        return QMessageBox(parent, title, text, QtMessageBox.Information).exec()


class MenuAutenticacao(QWidget):
    @dataclass
    class Particula:
        x: float
        y: float
        velocidade: float
        tamanho: float
        opacidade: float  # Opacidade máxima; o brilho varia abaixo deste valor.
        cor: QColor
        fase: float

    def __init__(self):
        super().__init__()
        load_fonts()
        self.settings = QSettings("BioSync", "Menu")
        self.network = QNetworkAccessManager(self)
        self.reply = None
        self.crypto = None
        self.pending_key = ""
        self.auth_response = None
        self.security_blocked = False
        self.security_check_failed = False
        self._centralizada = False
        self.init_ui()
        self.inicializar_particulas()
        self.aplicar_cursor_neon()
        self.aplicar_cursor_selecao()
        self.header = Cabecalho(self, selection_cursor=self.cursor_selecao)
        self.header.setGeometry(14, 10, self.width() - 28, 34)
        self.header.raise_()
        self.restore_key()
        self.timer_security = QTimer(self)
        self.timer_security.setInterval(500)
        self.timer_security.timeout.connect(self.check_security)
        self.timer_security.start()

    def check_security(self):
        if self.security_blocked:
            return True
        try:
            signal = detect_debugger()
        except OSError:
            # Falha técnica bloqueia login, mas não conta como tentativa nem gera ban.
            self.security_check_failed = True
            self.auth_response = None
            self.pending_key = ""
            self.crypto = None
            if self.reply is not None:
                self.reply.finished.disconnect(self.login_finished)
                self.reply.abort()
                self.reply.deleteLater()
                self.reply = None
            self.set_busy(True)
            return True
        self.security_check_failed = False
        if signal is None:
            self.set_busy(self.reply is not None)
            return False
        self.security_blocked = True
        self.timer_security.stop()
        attempted_key = self.pending_key or self.input_key.text().strip()
        try:
            hwid = collect_hwid()
        except Exception:
            hwid = None
        event = record_incident(self.settings, signal, hwid, attempted_key)
        # Invalida sessão e desconecta callback antes do abort, que emite finished.
        self.auth_response = None
        self.pending_key = ""
        self.crypto = None
        self.input_key.clear()
        self.set_busy(True)
        if self.reply is not None:
            self.reply.finished.disconnect(self.login_finished)
            self.reply.abort()
            self.reply.deleteLater()
            self.reply = None
        try:
            self.send_security_webhook(event)
        finally:
            try:
                self.show_security_warning(incident_message(event))
            finally:
                self.close()
                QApplication.instance().exit(3)
        return True

    def show_security_warning(self, text):
        dialog = QMessageBox(self, "Acesso bloqueado", text, QtMessageBox.Warning)
        timer = QTimer(dialog)
        timer.setSingleShot(True)
        timer.timeout.connect(dialog.reject)
        timer.start(5000)
        dialog.exec()

    def send_security_webhook(self, event):
        value = security_webhook_url()
        url = QUrl(value)
        if (url.scheme() != "https" or url.host() != "discord.com"
                or not url.path().startswith("/api/webhooks/")
                or url.userInfo() or url.fragment() or url.port(443) != 443):
            return
        request = QNetworkRequest(url)
        request.setHeader(QNetworkRequest.ContentTypeHeader, "application/json; charset=utf-8")
        request.setAttribute(QNetworkRequest.RedirectPolicyAttribute, QNetworkRequest.ManualRedirectPolicy)
        request.setTransferTimeout(3000)
        notification = self.network.post(request, QByteArray(encode_webhook(webhook_payload(event))))
        notification.finished.connect(notification.deleteLater)

    def inicializar_particulas(self):
        self.particulas = [
            self.Particula(
                x=random.uniform(0, self.width()),
                y=random.uniform(0, self.height()),
                velocidade=random.uniform(0.12, 0.45),
                tamanho=random.uniform(1, 3),
                opacidade=random.uniform(0.25, 0.65),
                cor=QColor(random.choice(("#8a2be2", "#00ff7f"))),
                fase=random.uniform(0, math.tau),
            )
            for _ in range(25)
        ]
        self._tempo_particulas = 0.0
        self._ultimo_frame_particulas = time.perf_counter()
        self.timer_particulas = QTimer(self)
        self.timer_particulas.setTimerType(Qt.PreciseTimer)
        self.timer_particulas.timeout.connect(self.atualizar_particulas)
        self.timer_particulas.start(16)

    def atualizar_particulas(self):
        now = time.perf_counter()
        # Mantém a velocidade estável e evita saltos após pausas do sistema.
        delta = min(now - self._ultimo_frame_particulas, 0.05)
        self._ultimo_frame_particulas = now
        self._tempo_particulas += delta
        for particula in self.particulas:
            particula.y -= particula.velocidade * delta * 60
            if particula.y + particula.tamanho < 0:
                particula.y = self.height() + particula.tamanho
                particula.x = random.uniform(0, self.width())
        self.update()

    def paintEvent(self, event):
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.fillRect(self.rect(), QColor("#0b0c10"))
        area = QRectF(self.rect()).adjusted(3, 3, -3, -3)
        gradient = QLinearGradient(area.topLeft(), area.bottomRight())
        gradient.setColorAt(0, QColor("#14101c"))
        gradient.setColorAt(0.48, QColor("#08090d"))
        gradient.setColorAt(1, QColor("#09160f"))
        painter.setPen(Qt.NoPen)
        painter.setBrush(gradient)
        painter.drawRoundedRect(area, 12, 12)
        # QWidget desenha seus filhos depois: os controles ficam sobre a poeira.
        for particula in self.particulas:
            brilho = 0.7 + 0.3 * math.sin(self._tempo_particulas * 0.8 + particula.fase)
            color = QColor(particula.cor)
            color.setAlphaF(particula.opacidade * brilho)
            painter.setBrush(color)
            painter.drawEllipse(QRectF(
                particula.x, particula.y, particula.tamanho, particula.tamanho,
            ))
        painter.end()

    def showEvent(self, event):
        super().showEvent(event)
        self._ultimo_frame_particulas = time.perf_counter()
        self.timer_particulas.start(16)
        if not self._centralizada:
            screen = QApplication.screenAt(QCursor.pos()) or self.screen()
            frame = self.frameGeometry()
            frame.moveCenter(screen.availableGeometry().center())
            self.move(frame.topLeft())
            self._centralizada = True

    def hideEvent(self, event):
        self.timer_particulas.stop()
        super().hideEvent(event)

    def aplicar_cursor_neon(self, hotspot_x=4, hotspot_y=4):
        """Aplica o cursor de assets em 48 px; hotspot em pixels após escalar."""
        pixmap = QPixmap(str(ASSETS / "cursors" / "cursor_neon.png"))
        if pixmap.isNull():
            return  # Mantém o cursor padrão se o arquivo não estiver disponível.
        pixmap = pixmap.scaled(
            48, 48, Qt.KeepAspectRatio, Qt.SmoothTransformation
        )
        cursor_customizado = QCursor(pixmap, hotspot_x, hotspot_y)
        self.setCursor(cursor_customizado)

    def aplicar_cursor_selecao(self):
        """Usa a mão neon nos controles clicáveis, com hotspot no indicador."""
        pixmap = QPixmap(str(ASSETS / "cursors" / "cursor_de-seleção.png"))
        if pixmap.isNull():
            cursor = QCursor(Qt.PointingHandCursor)
        else:
            pixmap = pixmap.scaled(
                48, 48, Qt.KeepAspectRatio, Qt.SmoothTransformation
            )
            # A ponta branca do indicador está a 42% da largura e 10% da altura.
            cursor = QCursor(
                pixmap, round(pixmap.width() * 0.42),
                round(pixmap.height() * 0.10),
            )
        self.cursor_selecao = cursor
        for control in self.findChildren(QPushButton) + self.findChildren(QCheckBox):
            control.setCursor(cursor)

    def init_ui(self):
        self.setObjectName("TelaPrincipal")
        self.setWindowFlags(Qt.Window | Qt.FramelessWindowHint)
        self.setWindowTitle("BioSync Menu • Autenticação")
        self.setFixedSize(503, 574)
        self.setStyleSheet(ESTILO_TELA)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(3, 3, 3, 3)
        panel = QFrame()
        panel.setObjectName("Painel")
        outer.addWidget(panel)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(20, 16, 20, 24)
        layout.setSpacing(0)

        title = QLabel()
        title.setObjectName("Titulo")
        title.setAlignment(Qt.AlignCenter)
        title.setFixedHeight(221)
        title.setAccessibleName("BIOSYNC MENU")
        gif_path = str(ASSETS / "branding" / "Emblema Neon BioSYNC MENU GIF.gif")
        self.banner_movie = QMovie(gif_path, QByteArray(), self)
        original_size = QImageReader(gif_path).size()
        logo = QPixmap(str(ASSETS / "branding" / "Emblema Neon BioSYNC MENU.png"))
        if not logo.isNull():
            self.setWindowIcon(QIcon(logo))
        if self.banner_movie.isValid() and original_size.isValid():
            self.banner_movie.setScaledSize(
                original_size.scaled(QSize(410, 221), Qt.KeepAspectRatio)
            )
            title.setMovie(self.banner_movie)
            self.banner_movie.start()
        elif not logo.isNull():
            title.setPixmap(logo.scaled(410, 221, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        else:
            title.setText("BIOSYNC\nMENU")
        layout.addWidget(title)
        subtitle = QLabel("A U T E N T I C A Ç Ã O")
        subtitle.setObjectName("Subtitulo")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setFixedHeight(31)
        layout.addWidget(subtitle)
        layout.addSpacing(10)

        border = QFrame()
        border.setObjectName("KeyBorda")
        border.setFixedHeight(54)
        border_layout = QVBoxLayout(border)
        border_layout.setContentsMargins(2, 2, 2, 2)
        inner = QFrame()
        inner.setObjectName("KeyInterior")
        row = QHBoxLayout(inner)
        row.setContentsMargins(16, 0, 16, 0)
        key_icon = QLabel()
        key_icon.setPixmap(icon_svg('<circle cx="16" cy="7" r="5"/><path d="m12 11-9 9v2h4v-3h3v-3l3-3"/>', "#d75aff").pixmap(28, 28))
        row.addWidget(key_icon)
        self.input_key = QLineEdit()
        self.input_key.setPlaceholderText("KEY:")
        self.input_key.setAccessibleName("Chave de licença")
        self.input_key.setMaxLength(512)
        self.input_key.setEchoMode(QLineEdit.Password)
        self.input_key.returnPressed.connect(self.login)
        row.addWidget(self.input_key)
        border_layout.addWidget(inner)
        glow(border, "#7d318b", 15)
        layout.addWidget(border)
        layout.addSpacing(18)

        self.btn_entrar = BotaoAnimado()
        self.btn_entrar.setFixedHeight(63)
        self.btn_entrar.clicked.connect(self.login)
        glow(self.btn_entrar, "#733099", 16)
        layout.addWidget(self.btn_entrar)
        layout.addSpacing(16)

        options = QHBoxLayout()
        self.chk_salvar = QCheckBox("Salvar Key")
        self.chk_salvar.toggled.connect(self.save_preference)
        self.btn_esqueci = QPushButton("Esqueci minha Key?")
        self.btn_esqueci.setObjectName("LinkEsqueci")
        self.btn_esqueci.clicked.connect(lambda: self.open_link("BIOSYNC_RECOVERY_URL", "recuperação de Key"))
        options.addWidget(self.chk_salvar)
        options.addStretch()
        options.addWidget(self.btn_esqueci)
        layout.addLayout(options)
        layout.addSpacing(23)

        divider = QHBoxLayout()
        divider.setSpacing(22)
        for index in range(3):
            if index == 1:
                label = QLabel("OU")
                label.setObjectName("Divisor")
                divider.addWidget(label)
            else:
                line = QFrame()
                line.setObjectName("Linha")
                line.setFixedHeight(1)
                divider.addWidget(line, 1)
        layout.addLayout(divider)
        layout.addSpacing(22)

        bottom = QHBoxLayout()
        bottom.setSpacing(22)
        discord = BotaoNeon("   DISCORD", "#b32aff")
        discord.setObjectName("BotaoSocial")
        discord.setIcon(icon_svg('<circle cx="12" cy="12" r="9"/><ellipse cx="12" cy="12" rx="4" ry="9"/><path d="M3 12h18M5 7h14M5 17h14"/>', "#b486ff"))
        discord.clicked.connect(lambda: self.open_link("BIOSYNC_DISCORD_URL", "Discord"))
        store = BotaoNeon("   LOJA OFICIAL", "#00f263")
        store.setObjectName("BotaoLoja")
        store.setIcon(icon_svg('<path d="M2 3h3l3 13h11l3-10H6"/><circle cx="9" cy="20" r="1"/><circle cx="18" cy="20" r="1"/>', "#00ff65"))
        store.clicked.connect(lambda: self.open_link("BIOSYNC_STORE_URL", "loja oficial"))
        for button in (discord, store):
            button.setFixedHeight(43)
            bottom.addWidget(button, 1)
        layout.addLayout(bottom)
        self.input_key.setFocus()

    def restore_key(self):
        if self.settings.value("remember", False, type=bool):
            try:
                saved = keyring.get_password(VAULT_SERVICE, "license_key")
                self.chk_salvar.blockSignals(True)
                self.chk_salvar.setChecked(True)
                self.chk_salvar.blockSignals(False)
                if saved:
                    self.input_key.setText(saved)
            except keyring.errors.KeyringError:
                self.settings.setValue("remember", False)

    def save_preference(self, checked):
        # Salva a chave apenas após um login válido; desmarcar apaga imediatamente.
        if not checked:
            self.settings.setValue("remember", False)
            try:
                if keyring.get_password(VAULT_SERVICE, "license_key") is not None:
                    keyring.delete_password(VAULT_SERVICE, "license_key")
            except keyring.errors.KeyringError:
                QMessageBox.warning(self, "Salvar Key", "Não foi possível remover a Key do cofre de credenciais do sistema.")

    def open_link(self, variable, label):
        value = os.environ.get(variable, "").strip()
        url = QUrl(value)
        if not value:
            QMessageBox.information(self, label.capitalize(), "O endereço deste serviço ainda não foi configurado.")
        elif url.scheme() != "https" or not url.host() or not QDesktopServices.openUrl(url):
            QMessageBox.warning(self, "Abrir link", "Não foi possível abrir o endereço HTTPS configurado.")

    def set_busy(self, busy):
        self.input_key.setEnabled(not busy)
        self.btn_entrar.setEnabled(not busy)
        self.btn_entrar.setText("  VALIDANDO…" if busy else "  ENTRAR")

    def login(self):
        if self.check_security():
            if self.security_check_failed:
                QMessageBox.warning(self, "Verificação indisponível", "Não foi possível executar a verificação de proteção. O login foi bloqueado.")
            return
        if self.reply is not None:
            return
        self.auth_response = None
        license_key = self.input_key.text().strip()
        if not license_key:
            QMessageBox.warning(self, "Key obrigatória", "Digite sua Key para entrar.")
            self.input_key.setFocus()
            return
        secret = os.environ.get("PWF_APP_SECRET", "").strip()
        if not secret:
            QMessageBox.warning(self, "Configuração pendente", "Configure PWF_APP_SECRET com o App Secret da sua aplicação no painel PWF Auth.")
            return
        try:
            hwid = collect_hwid()
        except (OSError, ValueError, KeyError) as exc:
            QMessageBox.warning(self, "HWID indisponível", f"Não foi possível identificar este computador.\n{exc}")
            return
        self.crypto = CryptoEnvelope(secret)
        payload = self.crypto.pack({"license_key": license_key, "hwid": hwid})
        request = QNetworkRequest(QUrl(LOGIN_URL))
        request.setHeader(QNetworkRequest.ContentTypeHeader, "application/json")
        request.setRawHeader(b"Accept", b"application/json")
        request.setRawHeader(b"X-App-Secret", secret.encode())
        request.setTransferTimeout(15000)
        # Não siga redirects que poderiam transportar o secret a outro host.
        request.setAttribute(QNetworkRequest.RedirectPolicyAttribute, QNetworkRequest.ManualRedirectPolicy)
        self.pending_key = license_key
        self.set_busy(True)
        self.reply = self.network.post(request, QByteArray(json.dumps(payload).encode()))
        self.reply.finished.connect(self.login_finished)

    def login_finished(self):
        if self.check_security():
            return
        reply = self.reply
        self.reply = None
        if reply is None:
            return
        self.auth_response = None
        self.set_busy(False)
        status = reply.attribute(QNetworkRequest.HttpStatusCodeAttribute)
        network_error = reply.error()
        key = self.pending_key
        self.pending_key = ""
        crypto = self.crypto
        self.crypto = None
        # O Qt também sinaliza HTTP 4xx/5xx como erro. Esses casos podem ter
        # uma recusa válida da API; falhas de transporte nunca autorizam.
        http_errors = (
            QNetworkReply.ContentAccessDenied,
            QNetworkReply.ContentOperationNotPermittedError,
            QNetworkReply.ContentNotFoundError,
            QNetworkReply.AuthenticationRequiredError,
            QNetworkReply.ContentConflictError,
            QNetworkReply.ContentGoneError,
            QNetworkReply.UnknownContentError,
            QNetworkReply.InternalServerError,
            QNetworkReply.OperationNotImplementedError,
            QNetworkReply.ServiceUnavailableError,
            QNetworkReply.UnknownServerError,
        )
        http_error_response = (
            status is not None and 400 <= status < 600 and network_error in http_errors
        )
        if status is None or (network_error != QNetworkReply.NoError and not http_error_response):
            reply.deleteLater()
            if network_error in (QNetworkReply.TimeoutError, QNetworkReply.ProxyTimeoutError):
                message = "A conexão com o PWF Auth excedeu o tempo de espera. Nenhum acesso foi autorizado. Tente novamente."
            elif network_error == QNetworkReply.SslHandshakeFailedError:
                message = "Não foi possível estabelecer uma conexão segura com o PWF Auth. Nenhum acesso foi autorizado."
            else:
                message = "Não foi possível concluir a conexão com o PWF Auth. Verifique a internet e tente novamente. Nenhum acesso foi autorizado."
            QMessageBox.warning(self, "Erro de conexão", message)
            return
        try:
            # Limita a cópia e o parsing; não lê um corpo arbitrário em Python.
            raw = bytes(reply.read(MAX_AUTH_RESPONSE_BYTES + 1))
            if len(raw) > MAX_AUTH_RESPONSE_BYTES:
                raise ValueError("Resposta excede o limite de tamanho.")
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError("Formato de resposta inválido.")
            encrypted = bool({"p", "t", "s"}.intersection(data))
            if encrypted:
                if not {"p", "t", "s"}.issubset(data) or crypto is None:
                    raise ValueError("Envelope criptografado incompleto.")
                data = crypto.unpack(data)
            if not isinstance(data, dict) or type(data.get("success")) is not bool:
                raise ValueError("Resposta sem resultado de autenticação válido.")
            if data["success"]:
                if not encrypted:
                    raise ValueError("Sucesso sem autenticação criptográfica recusado.")
                session_id = data.get("session_id")
                if not isinstance(session_id, str) or not session_id.strip():
                    raise ValueError("Identificador de sessão ausente ou inválido.")
        except (ValueError, KeyError, TypeError, RecursionError, OverflowError):
            QMessageBox.warning(self, "Resposta inválida", "Resposta inválida ou corrompida do servidor.")
            return
        finally:
            reply.deleteLater()
        if data["success"] is True and 200 <= status < 300 and network_error == QNetworkReply.NoError:
            self.auth_response = data
            if self.chk_salvar.isChecked():
                try:
                    keyring.set_password(VAULT_SERVICE, "license_key", key)
                    self.settings.setValue("remember", True)
                except keyring.errors.KeyringError:
                    self.settings.setValue("remember", False)
                    QMessageBox.warning(self, "Salvar Key", "Login autorizado, mas não foi possível salvar a Key no cofre de credenciais.")
            QMessageBox.information(self, "Autenticação concluída", "Login feito com sucesso! É uma alegria ter você aqui.")
            self.close()
            return
        code = str(data.get("error_code", "UNKNOWN")).upper()
        message = ERROR_MESSAGES.get(code)
        if data.get("reason") == "CLOCK_SKEW":
            message = "Ajuste a data e a hora do computador e tente novamente."
        if message is None:
            if status == 401:
                message = "App Secret ausente ou inválido. Verifique a configuração do aplicativo."
            elif status == 429:
                message = "Muitas requisições. Aguarde antes de tentar novamente."
            elif status >= 500:
                message = "O serviço está temporariamente indisponível. Tente novamente mais tarde."
            else:
                message = "Não foi possível autenticar. Entre em contato com o suporte."
        QMessageBox.warning(self, "Autenticação recusada", f"{message}\n\nCódigo: {code}")

    def closeEvent(self, event):
        self.timer_security.stop()
        # auth_response permanece disponível ao aplicativo que mantém a janela.
        self.input_key.clear()
        self.pending_key = ""
        self.crypto = None
        self.timer_particulas.stop()
        self.banner_movie.stop()
        if self.reply is not None:
            self.reply.finished.disconnect(self.login_finished)
            self.reply.abort()
            self.reply.deleteLater()
            self.reply = None
        super().closeEvent(event)


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = MenuAutenticacao()
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
