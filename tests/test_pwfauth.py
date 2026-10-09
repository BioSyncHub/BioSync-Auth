"""Testes locais sem acessar API ou gravar credenciais reais."""
import json
import hashlib
import hmac
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

os.environ["QT_QPA_PLATFORM"] = "offscreen"

from PySide6.QtCore import QByteArray, QSettings
from PySide6.QtNetwork import QNetworkReply, QNetworkRequest
from PySide6.QtWidgets import QApplication, QLineEdit
from biosync_auth.app import (
    MAX_AUTH_RESPONSE_BYTES, CryptoEnvelope, MenuAutenticacao, collect_hwid,
)
from biosync_auth.protection import SECURITY_ROLE_ID, encode_webhook, incident_message, record_incident, security_webhook_url, webhook_payload


class FakeReply:
    def __init__(self, data, status=200):
        self.data = data
        self.status = status

    def attribute(self, _):
        return self.status

    def read(self, limit):
        raw = self.data if isinstance(self.data, bytes) else json.dumps(self.data).encode()
        return QByteArray(raw[:limit])

    def error(self):
        return QNetworkReply.NoError

    def deleteLater(self):
        pass


class AuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        cls.temp = tempfile.TemporaryDirectory()

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        # O construtor QSettings(organização, app) usa NativeFormat no Windows.
        # Substitua-o antes de criar a janela e isole também todo acesso ao cofre.
        self.test_settings = QSettings(
            str(Path(self.temp.name) / "test.ini"), QSettings.IniFormat
        )
        self.test_settings.setFallbacksEnabled(False)
        self.test_settings.clear()
        self.settings_patch = patch("biosync_auth.app.QSettings", return_value=self.test_settings)
        self.settings_patch.start()
        self.addCleanup(self.settings_patch.stop)
        debugger_patch = patch("biosync_auth.app.detect_debugger", return_value=None)
        self.debugger_mock = debugger_patch.start()
        self.addCleanup(debugger_patch.stop)
        webhook_env = patch.dict(os.environ, {"BIOSYNC_SECURITY_WEBHOOK_URL": ""})
        webhook_env.start()
        self.addCleanup(webhook_env.stop)
        self.vault_mocks = {}
        for method in ("get_password", "set_password", "delete_password"):
            vault_patch = patch(f"biosync_auth.app.keyring.{method}", return_value=None)
            self.vault_mocks[method] = vault_patch.start()
            self.addCleanup(vault_patch.stop)
        self.window = MenuAutenticacao()
        self.window.settings.clear()
        self.window.crypto = CryptoEnvelope("test-secret")
        self.window.pending_key = "TEST-LICENSE"

    def tearDown(self):
        self.window.close()
        self.window.deleteLater()
        self.app.processEvents()

    def test_settings_and_vault_are_isolated(self):
        self.assertEqual(self.window.settings.format(), QSettings.IniFormat)
        self.assertEqual(
            Path(self.window.settings.fileName()).parent.resolve(),
            Path(self.temp.name).resolve(),
        )
        self.window.settings.setValue("remember", True)
        self.window.restore_key()
        self.vault_mocks["get_password"].assert_called_once_with(
            "BioSyncMenu.PWFAuth", "license_key"
        )

    def test_expired_envelope_is_rejected(self):
        with patch("biosync_auth.app.time.time", return_value=1000):
            envelope = self.window.crypto.pack({"success": True})
        with patch("biosync_auth.app.time.time", return_value=1301):
            with self.assertRaisesRegex(ValueError, "sincronia"):
                self.window.crypto.unpack(envelope)

    @patch("biosync_auth.app.QMessageBox.warning")
    def test_network_error_cannot_authorize_signed_success(self, warning):
        self.window.reply = FakeReply(self.window.crypto.pack({"success": True, "session_id": "test"}))
        self.window.reply.error = lambda: QNetworkReply.SslHandshakeFailedError
        with patch.object(self.window, "close") as close:
            self.window.login_finished()
            close.assert_not_called()
        warning.assert_called_once()

    def test_envelope_roundtrip_and_tampering(self):
        crypto = self.window.crypto
        body = {"license_key": "TEST-LICENSE", "hwid": "machine"}
        envelope = crypto.pack(body)
        self.assertEqual(crypto.unpack(envelope), body)
        self.assertNotIn("TEST-LICENSE", json.dumps(envelope))
        envelope["s"] = "0" * 64
        with self.assertRaises(ValueError):
            crypto.unpack(envelope)

    def test_hwid_is_stable(self):
        self.assertEqual(collect_hwid(), collect_hwid())
        self.assertEqual(len(collect_hwid()), 64)

    @patch("biosync_auth.app.QMessageBox.information")
    @patch("biosync_auth.app.keyring.set_password")
    def test_encrypted_success_saves_and_closes(self, save, info):
        self.window.chk_salvar.setChecked(True)
        self.window.reply = FakeReply(self.window.crypto.pack({"success": True, "session_id": "test"}))
        with patch.object(self.window, "close") as close:
            self.window.login_finished()
            close.assert_called_once()
        save.assert_called_once_with("BioSyncMenu.PWFAuth", "license_key", "TEST-LICENSE")
        info.assert_called_once()

    @patch("biosync_auth.app.QMessageBox.warning")
    def test_api_errors_remain_open_and_translate(self, warning):
        for code, phrase in (("INVALID_KEY", "Chave inválida"), ("EXPIRED", "expirou"),
                             ("HWID_MISMATCH", "outro computador")):
            self.window.reply = FakeReply({"success": False, "error_code": code}, 403)
            with patch.object(self.window, "close") as close:
                self.window.login_finished()
                close.assert_not_called()
            self.assertIn(phrase, warning.call_args.args[2])

    @patch("biosync_auth.app.QMessageBox.warning")
    def test_tampered_success_is_rejected(self, warning):
        envelope = self.window.crypto.pack({"success": True})
        envelope["s"] = "0" * 64
        self.window.reply = FakeReply(envelope)
        with patch.object(self.window, "close") as close:
            self.window.login_finished()
            close.assert_not_called()
        self.assertIn("Resposta inválida ou corrompida", warning.call_args.args[2])

    @patch("biosync_auth.app.QMessageBox.warning")
    @patch("biosync_auth.app.QMessageBox.information")
    def test_plain_success_is_rejected_without_saving(self, info, warning):
        self.window.chk_salvar.setChecked(True)
        self.window.auth_response = {"success": True, "session_id": "old-session"}
        self.window.reply = FakeReply({"success": True, "session_id": "forged"})
        with patch.object(self.window, "close") as close:
            self.window.login_finished()
            close.assert_not_called()
        self.assertIsNone(self.window.auth_response)
        self.vault_mocks["set_password"].assert_not_called()
        info.assert_not_called()
        warning.assert_called_once()
        self.assertEqual(self.window.pending_key, "")
        self.assertIsNone(self.window.crypto)

    @patch("biosync_auth.app.QMessageBox.warning")
    def test_incomplete_envelopes_are_rejected(self, warning):
        for field in ("p", "t", "s"):
            with self.subTest(missing=field):
                self.window.crypto = CryptoEnvelope("test-secret")
                envelope = self.window.crypto.pack({"success": True, "session_id": "test"})
                del envelope[field]
                self.window.reply = FakeReply(envelope)
                with patch.object(self.window, "close") as close:
                    self.window.login_finished()
                    close.assert_not_called()
                self.assertIsNone(self.window.auth_response)
        self.assertEqual(warning.call_count, 3)

    @patch("biosync_auth.app.QMessageBox.warning")
    def test_invalid_session_ids_are_rejected_without_saving(self, warning):
        self.window.chk_salvar.setChecked(True)
        for session in (None, "", " \t\n", 123, True, [], {}):
            with self.subTest(session=session):
                self.window.crypto = CryptoEnvelope("test-secret")
                payload = {"success": True}
                if session is not None:
                    payload["session_id"] = session
                self.window.reply = FakeReply(self.window.crypto.pack(payload))
                with patch.object(self.window, "close") as close:
                    self.window.login_finished()
                    close.assert_not_called()
                self.assertIsNone(self.window.auth_response)
        self.vault_mocks["set_password"].assert_not_called()
        self.assertEqual(warning.call_count, 7)

    @patch("biosync_auth.app.QMessageBox.warning")
    def test_hostile_json_is_rejected_and_reply_is_released(self, warning):
        for raw in (
            b"[" * 20000 + b"0" + b"]" * 20000,
            b"x" * (MAX_AUTH_RESPONSE_BYTES + 1),
            b'{"success":',
            b"\xff",
        ):
            with self.subTest(size=len(raw)):
                self.window.reply = FakeReply(raw)
                reply = self.window.reply
                with patch.object(reply, "deleteLater") as release, patch.object(self.window, "close") as close:
                    self.window.login_finished()
                    release.assert_called_once()
                    close.assert_not_called()
                self.assertIsNone(self.window.reply)
                self.assertIsNone(self.window.auth_response)
                self.assertTrue(self.window.btn_entrar.isEnabled())
                self.assertEqual(warning.call_args.args[2], "Resposta inválida ou corrompida do servidor.")

    @patch("biosync_auth.app.QMessageBox.warning")
    def test_hostile_decrypted_json_is_rejected(self, warning):
        crypto = self.window.crypto
        pack_json = json.dumps
        with patch("biosync_auth.app.json.dumps", return_value="[" * 20000 + "0" + "]" * 20000):
            envelope = crypto.pack({})
        self.window.reply = FakeReply(pack_json(envelope).encode())
        with patch.object(self.window, "close") as close:
            self.window.login_finished()
            close.assert_not_called()
        self.assertIsNone(self.window.auth_response)
        warning.assert_called_once()

    @patch("biosync_auth.app.QMessageBox.warning")
    def test_extreme_timestamp_is_rejected(self, warning):
        envelope = self.window.crypto.pack({"success": True, "session_id": "test"})
        envelope["t"] = 10**400
        self.window.reply = FakeReply(envelope)
        self.window.login_finished()
        self.assertIsNone(self.window.auth_response)
        warning.assert_called_once()

    @patch("biosync_auth.app.QMessageBox.warning")
    def test_overflow_and_recursion_from_unpack_are_handled(self, warning):
        for exception in (OverflowError, RecursionError):
            with self.subTest(exception=exception.__name__):
                self.window.crypto = CryptoEnvelope("test-secret")
                envelope = self.window.crypto.pack({"success": True, "session_id": "test"})
                self.window.reply = FakeReply(envelope)
                with patch.object(self.window.crypto, "unpack", side_effect=exception), patch.object(self.window, "close") as close:
                    self.window.login_finished()
                    close.assert_not_called()
                self.assertIsNone(self.window.auth_response)
        self.assertEqual(warning.call_count, 2)

    @patch("biosync_auth.app.QMessageBox.information")
    def test_valid_payload_survives_close_and_key_field_is_cleared(self, info):
        payload = {
            "success": True, "session_id": "test-session",
            "user": {"license_key": "TEST-LICENSE"}, "heartbeat_interval": 30,
        }
        self.window.input_key.setText("TEST-LICENSE")
        self.assertEqual(self.window.input_key.echoMode(), QLineEdit.Password)
        self.window.reply = FakeReply(self.window.crypto.pack(payload))
        self.window.login_finished()
        self.assertEqual(self.window.auth_response, payload)
        self.assertEqual(self.window.input_key.text(), "")
        self.assertEqual(self.window.pending_key, "")
        self.assertIsNone(self.window.crypto)
        info.assert_called_once()

    def test_cancellation_clears_temporary_credentials(self):
        self.window.input_key.setText("TEST-LICENSE")
        self.window.reply = MagicMock()
        reply = self.window.reply
        self.window.close()
        reply.abort.assert_called_once()
        self.assertEqual(self.window.input_key.text(), "")
        self.assertEqual(self.window.pending_key, "")
        self.assertIsNone(self.window.crypto)
        self.assertIsNone(self.window.auth_response)

    @patch("biosync_auth.app.QMessageBox.warning")
    def test_empty_key_never_sends_request(self, warning):
        self.window.input_key.clear()
        self.window.login()
        self.assertIsNone(self.window.reply)
        warning.assert_called_once()

    @patch.dict(os.environ, {"PWF_APP_SECRET": "test-secret"})
    @patch("biosync_auth.app.collect_hwid", return_value="test-hwid")
    def test_request_uses_real_login_contract(self, hwid):
        self.window.network = MagicMock()
        self.window.input_key.setText("  TEST-LICENSE  ")
        self.window.login()
        request, body = self.window.network.post.call_args.args
        self.assertEqual(request.url().toString(), "https://pwfauth.com/api/auth/login.php")
        self.assertEqual(bytes(request.rawHeader("X-App-Secret")), b"test-secret")
        payload = self.window.crypto.unpack(json.loads(bytes(body)))
        self.assertEqual(payload, {"license_key": "TEST-LICENSE", "hwid": "test-hwid"})
        self.assertFalse(self.window.btn_entrar.isEnabled())
        self.window.login()
        self.window.network.post.assert_called_once()

    @patch("biosync_auth.app.QMessageBox.warning")
    def test_http_failure_cannot_authorize_success_body(self, warning):
        self.window.reply = FakeReply(self.window.crypto.pack({"success": True, "session_id": "test"}), 500)
        with patch.object(self.window, "close") as close:
            self.window.login_finished()
            close.assert_not_called()
        self.assertIn("indisponível", warning.call_args.args[2])

    def assert_attack_rejected(self, body, status=200, network_error=QNetworkReply.NoError):
        self.window.crypto = CryptoEnvelope("test-secret")
        self.window.pending_key = "TEST-LICENSE"
        self.window.chk_salvar.setChecked(True)
        self.window.reply = FakeReply(body, status)
        self.window.reply.error = lambda: network_error
        with patch("biosync_auth.app.QMessageBox.warning") as warning, \
                patch("biosync_auth.app.QMessageBox.information") as info, \
                patch.object(self.window, "close") as close:
            self.window.login_finished()
            self.assertIsNone(self.window.auth_response)
            close.assert_not_called()
            info.assert_not_called()
            warning.assert_called_once()
        self.vault_mocks["set_password"].assert_not_called()
        self.assertIsNone(self.window.reply)
        self.assertIsNone(self.window.crypto)
        self.assertEqual(self.window.pending_key, "")

    def test_tampering_of_each_authenticated_field_is_rejected(self):
        original = CryptoEnvelope("test-secret").pack({"success": True, "session_id": "test"})
        for field, replacement in (
            ("p", ("B" if original["p"][0] == "A" else "A") + original["p"][1:]),
            ("t", original["t"] + 1),
            ("s", "f" * 64),
        ):
            with self.subTest(field=field):
                envelope = dict(original)
                envelope[field] = replacement
                self.assert_attack_rejected(envelope)

    def test_envelope_field_types_are_strict(self):
        original = CryptoEnvelope("test-secret").pack({"success": True, "session_id": "test"})
        cases = {
            "p": (None, 123, True, [], {}),
            "t": (None, "123", True, 1.5, -1, 2**63, [], {}),
            "s": (None, 123, True, [], {}, "", "é" * 64),
        }
        for field, replacements in cases.items():
            for replacement in replacements:
                with self.subTest(field=field, replacement=replacement):
                    envelope = dict(original)
                    envelope[field] = replacement
                    self.assert_attack_rejected(envelope)

    def test_wrong_app_secret_cannot_authorize(self):
        envelope = CryptoEnvelope("another-app-secret").pack({"success": True, "session_id": "test"})
        self.assert_attack_rejected(envelope)

    def test_signed_invalid_ciphertext_is_rejected(self):
        crypto = CryptoEnvelope("test-secret")
        original = crypto.pack({"success": True, "session_id": "test"})
        for encoded in ("", "not-base64!", "AA==", "A" * 44):
            with self.subTest(encoded=encoded):
                envelope = dict(original, p=encoded)
                envelope["s"] = hmac.new(
                    crypto.mac_key, f'{encoded}{envelope["t"]}'.encode(), hashlib.sha256
                ).hexdigest()
                self.assert_attack_rejected(envelope)

    def test_signed_payload_schema_cannot_fake_boolean_success(self):
        crypto = CryptoEnvelope("test-secret")
        payloads = [None, [], "success", 1, {}]
        payloads.extend({"success": value, "session_id": "test"}
                        for value in (1, 0, "true", "false", None, [], {}))
        for payload in payloads:
            with self.subTest(payload=payload):
                self.assert_attack_rejected(crypto.pack(payload))

    def test_signed_success_cannot_bypass_http_or_transport_failure(self):
        crypto = CryptoEnvelope("test-secret")
        payload = {"success": True, "session_id": "test"}
        for status in (None, 301, 302, 400, 401, 403, 429, 500, 503):
            with self.subTest(status=status):
                self.assert_attack_rejected(crypto.pack(payload), status)
        for error in (
            QNetworkReply.SslHandshakeFailedError, QNetworkReply.TimeoutError,
            QNetworkReply.ConnectionRefusedError, QNetworkReply.OperationCanceledError,
        ):
            with self.subTest(error=error):
                self.assert_attack_rejected(crypto.pack(payload), network_error=error)

    def test_stale_or_future_signed_response_cannot_authorize(self):
        crypto = CryptoEnvelope("test-secret")
        with patch("biosync_auth.app.time.time", return_value=1000):
            envelope = crypto.pack({"success": True, "session_id": "test"})
        for now in (699, 1301):
            with self.subTest(now=now), patch("biosync_auth.app.time.time", return_value=now):
                self.assert_attack_rejected(envelope)

    def test_signed_banned_or_expired_payload_cannot_authorize(self):
        crypto = CryptoEnvelope("test-secret")
        for code in ("BANNED", "EXPIRED"):
            with self.subTest(code=code):
                self.assert_attack_rejected(crypto.pack({
                    "success": False, "error_code": code, "session_id": "test",
                }))

    @patch.dict(os.environ, {"PWF_APP_SECRET": "test-secret"})
    @patch("biosync_auth.app.collect_hwid", return_value="test-hwid")
    def test_request_does_not_follow_redirects_with_secret(self, hwid):
        self.window.network = MagicMock()
        self.window.input_key.setText("TEST-LICENSE")
        self.window.login()
        request = self.window.network.post.call_args.args[0]
        self.assertEqual(request.url().scheme(), "https")
        self.assertEqual(request.attribute(QNetworkRequest.RedirectPolicyAttribute),
                         QNetworkRequest.ManualRedirectPolicy)

    @patch("biosync_auth.app.QMessageBox.warning")
    def test_rejection_clears_old_authorization(self, warning):
        self.window.auth_response = {"success": True, "session_id": "old-session"}
        self.window.reply = FakeReply({"success": False, "error_code": "BANNED"})
        self.window.login_finished()
        self.assertIsNone(self.window.auth_response)
        self.vault_mocks["set_password"].assert_not_called()

    def test_disconnect_with_expired_key_never_parses_or_authorizes(self):
        crypto = CryptoEnvelope("test-secret")
        bodies = (
            b'{"success":',
            crypto.pack({"success": False, "error_code": "EXPIRED"}),
            crypto.pack({"success": True, "session_id": "forged-success"}),
        )
        errors = (
            QNetworkReply.RemoteHostClosedError,
            QNetworkReply.TemporaryNetworkFailureError,
            QNetworkReply.NetworkSessionFailedError,
            QNetworkReply.TimeoutError,
            QNetworkReply.SslHandshakeFailedError,
            QNetworkReply.ProxyTimeoutError,
            QNetworkReply.OperationCanceledError,
        )
        for body in bodies:
            for status in (None, 200, 403):
                for error in errors:
                    with self.subTest(status=status, error=error, body_type=type(body).__name__):
                        self.window.auth_response = {"success": True, "session_id": "old"}
                        self.window.pending_key = "SIMULATED-EXPIRED-KEY"
                        self.window.crypto = crypto
                        self.window.chk_salvar.setChecked(True)
                        self.window.set_busy(True)
                        self.window.reply = FakeReply(body, status)
                        reply = self.window.reply
                        reply.error = lambda: error
                        with patch.object(reply, "read") as read, \
                                patch.object(reply, "deleteLater") as release, \
                                patch("biosync_auth.app.QMessageBox.warning") as warning, \
                                patch("biosync_auth.app.QMessageBox.information") as info, \
                                patch.object(self.window, "close") as close:
                            self.window.login_finished()
                            read.assert_not_called()
                            release.assert_called_once()
                            close.assert_not_called()
                            info.assert_not_called()
                            warning.assert_called_once()
                            self.assertEqual(warning.call_args.args[1], "Erro de conexão")
                            self.assertIn("Nenhum acesso foi autorizado", warning.call_args.args[2])
                        self.assertIsNone(self.window.auth_response)
                        self.assertIsNone(self.window.crypto)
                        self.assertIsNone(self.window.reply)
                        self.assertEqual(self.window.pending_key, "")
                        self.assertTrue(self.window.btn_entrar.isEnabled())
                        self.vault_mocks["set_password"].assert_not_called()

    @patch("biosync_auth.app.QMessageBox.warning")
    def test_http_rejections_are_not_misclassified_as_disconnection(self, warning):
        crypto = CryptoEnvelope("test-secret")
        for code in ("EXPIRED", "BANNED"):
            with self.subTest(code=code):
                self.window.crypto = crypto
                self.window.reply = FakeReply(crypto.pack({"success": False, "error_code": code}), 403)
                self.window.reply.error = lambda: QNetworkReply.ContentAccessDenied
                self.window.login_finished()
                self.assertIsNone(self.window.auth_response)
                self.assertEqual(warning.call_args.args[1], "Autenticação recusada")
                self.assertIn(f"Código: {code}", warning.call_args.args[2])

    @patch("biosync_auth.app.QMessageBox.warning")
    def test_login_can_retry_after_disconnection_without_reusing_authorization(self, warning):
        self.window.reply = FakeReply(b"", 200)
        self.window.reply.error = lambda: QNetworkReply.RemoteHostClosedError
        self.window.login_finished()
        self.window.network = MagicMock()
        self.window.input_key.setText("SIMULATED-EXPIRED-KEY")
        with patch.dict(os.environ, {"PWF_APP_SECRET": "test-secret"}), \
                patch("biosync_auth.app.collect_hwid", return_value="test-hwid"):
            self.window.login()
        self.window.network.post.assert_called_once()
        self.assertIsNone(self.window.auth_response)
        self.assertFalse(self.window.btn_entrar.isEnabled())

    def test_detected_debugger_blocks_login_and_clears_session(self):
        self.debugger_mock.return_value = "windows_debugger"
        self.window.auth_response = {"success": True, "session_id": "old"}
        self.window.input_key.setText("TEST-LICENSE")
        self.window.network = MagicMock()
        with patch("biosync_auth.app.collect_hwid", return_value="a" * 64), \
                patch.object(self.window, "show_security_warning") as warning, \
                patch.object(self.window, "send_security_webhook") as notify, \
                patch("biosync_auth.app.QApplication.exit") as exit_app:
            self.window.login()
            self.assertIn("Opa, ligeirinho!", warning.call_args.args[0])
            self.assertEqual(notify.call_args.args[0]["attempted_key"], "TEST-LICENSE")
            self.assertFalse(notify.call_args.args[0]["ban_applied"])
            exit_app.assert_called_once_with(3)
        self.window.network.post.assert_not_called()
        self.assertTrue(self.window.security_blocked)
        self.assertIsNone(self.window.auth_response)
        self.assertEqual(self.window.input_key.text(), "")
        self.assertEqual(self.window.pending_key, "")
        self.assertIsNone(self.window.crypto)

    def test_debugger_during_reply_aborts_without_processing_success(self):
        self.debugger_mock.return_value = "python_debugger"
        reply = MagicMock()
        self.window.reply = reply
        with patch("biosync_auth.app.collect_hwid", return_value="a" * 64), \
                patch.object(self.window, "show_security_warning"), \
                patch.object(self.window, "send_security_webhook"), \
                patch("biosync_auth.app.QApplication.exit"):
            self.window.login_finished()
        reply.finished.disconnect.assert_called_once()
        reply.abort.assert_called_once()
        reply.read.assert_not_called()
        self.assertIsNone(self.window.auth_response)
        self.assertIsNone(self.window.reply)

    def test_third_incident_names_pc_without_banning(self):
        with patch("biosync_auth.protection.socket.gethostname", return_value="PC-TESTE"):
            events = [record_incident(self.window.settings, "windows_debugger", "a" * 64) for _ in range(3)]
        self.assertEqual([event["attempt"] for event in events], [1, 2, 3])
        self.assertIn("Opa, PC-TESTE!", incident_message(events[2]))
        self.assertIn("ban de HWID", incident_message(events[2]))
        self.assertTrue(all(not event["ban_applied"] for event in events))
        self.assertFalse(self.window.settings.contains("security/attempted_key"))

    def test_unknown_hwid_still_closes_without_ban(self):
        self.debugger_mock.return_value = "windows_debugger"
        with patch("biosync_auth.app.collect_hwid", side_effect=OSError), \
                patch.object(self.window, "show_security_warning"), \
                patch.object(self.window, "send_security_webhook") as notify, \
                patch("biosync_auth.app.QApplication.exit") as exit_app:
            self.window.check_security()
        self.assertIsNone(notify.call_args.args[0]["hwid"])
        self.assertFalse(notify.call_args.args[0]["ban_applied"])
        exit_app.assert_called_once_with(3)

    def test_one_incident_per_process_even_when_polled_again(self):
        self.debugger_mock.return_value = "windows_debugger"
        with patch("biosync_auth.app.collect_hwid", return_value="a" * 64), \
                patch.object(self.window, "show_security_warning") as warning, \
                patch.object(self.window, "send_security_webhook") as notify, \
                patch("biosync_auth.app.QApplication.exit"):
            self.window.check_security()
            self.window.check_security()
        warning.assert_called_once()
        notify.assert_called_once()
        self.assertEqual(self.window.settings.value("security/debugger_incidents", type=int), 1)

    def test_protection_api_failure_blocks_without_counting_fraud(self):
        self.debugger_mock.side_effect = OSError("simulated")
        self.window.network = MagicMock()
        with patch("biosync_auth.app.QMessageBox.warning"):
            self.window.login()
        self.window.network.post.assert_not_called()
        self.assertIsNone(self.window.auth_response)
        self.assertFalse(self.window.settings.contains("security/debugger_incidents"))

    def test_webhook_contains_attempted_key_and_disables_mentions(self):
        event = record_incident(self.window.settings, "windows_debugger", attempted_key="TEST-KEY @everyone")
        payload = webhook_payload(event)
        self.assertIn("TEST-KEY @everyone", payload["embeds"][0]["fields"][1]["value"])
        self.assertIn("não validada", payload["embeds"][0]["fields"][1]["value"])
        self.assertEqual(payload["content"], f"<@&{SECURITY_ROLE_ID}>")
        self.assertEqual(payload["allowed_mentions"], {"parse": [], "roles": [SECURITY_ROLE_ID]})
        self.assertNotIn("test-secret", json.dumps(payload))

    def test_webhook_uses_https_no_redirect_and_no_app_secret(self):
        self.window.network = MagicMock()
        event = record_incident(self.window.settings, "windows_debugger", attempted_key="TEST-KEY")
        with patch.dict(os.environ, {"BIOSYNC_SECURITY_WEBHOOK_URL": "https://discord.com/api/webhooks/123/test-token"}):
            self.window.send_security_webhook(event)
        request, body = self.window.network.post.call_args.args
        self.assertFalse(request.hasRawHeader("X-App-Secret"))
        self.assertEqual(request.attribute(QNetworkRequest.RedirectPolicyAttribute), QNetworkRequest.ManualRedirectPolicy)
        self.assertIn("TEST-KEY", json.loads(bytes(body))["embeds"][0]["fields"][1]["value"])

    def test_webhook_embed_uses_real_timestamp_and_unknown_hwid(self):
        with patch("biosync_auth.protection.time.time", return_value=0):
            event = record_incident(self.window.settings, "python_debugger")
        embed = webhook_payload(event)["embeds"][0]
        self.assertEqual(embed["timestamp"], "1970-01-01T00:00:00.000Z")
        self.assertIn("HWID indisponível", embed["fields"][0]["value"])
        self.assertIn("não comprova", embed["description"])

    def test_webhook_utf8_preserves_accents_and_emoji(self):
        event = record_incident(self.window.settings, "python_debugger")
        payload = webhook_payload(event)
        raw = encode_webhook(payload)
        decoded = json.loads(raw.decode("utf-8"))
        self.assertEqual(decoded, payload)
        self.assertIn("⚠️ Alerta de Segurança", decoded["embeds"][0]["title"])
        self.assertIn("Usuário", decoded["embeds"][0]["fields"][0]["name"])
        self.assertIn("não", decoded["embeds"][0]["description"])

    def test_local_webhook_config_and_environment_priority(self):
        config = Path(self.temp.name) / "webhook-test.json"
        config.write_text(json.dumps({"security_webhook_url": "https://discord.com/api/webhooks/123/fake"}), encoding="utf-8")
        with patch("biosync_auth.protection.WEBHOOK_CONFIG", config), patch.dict(os.environ):
            os.environ.pop("BIOSYNC_SECURITY_WEBHOOK_URL", None)
            self.assertEqual(security_webhook_url(), "https://discord.com/api/webhooks/123/fake")
            os.environ["BIOSYNC_SECURITY_WEBHOOK_URL"] = ""
            self.assertEqual(security_webhook_url(), "")
            config.write_text("{broken", encoding="utf-8")
            os.environ.pop("BIOSYNC_SECURITY_WEBHOOK_URL")
            self.assertEqual(security_webhook_url(), "")

    def test_unconfigured_or_untrusted_webhook_sends_nothing(self):
        self.window.network = MagicMock()
        event = record_incident(self.window.settings, "windows_debugger")
        for url in ("", "http://discord.com/api/webhooks/123/token", "https://example.com/api/webhooks/123/token", "https://discord.com.evil.test/api/webhooks/123/token"):
            with patch.dict(os.environ, {"BIOSYNC_SECURITY_WEBHOOK_URL": url}):
                self.window.send_security_webhook(event)
        self.window.network.post.assert_not_called()


if __name__ == "__main__":
    unittest.main()
