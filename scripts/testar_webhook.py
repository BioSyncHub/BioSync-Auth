"""Envia uma mensagem de teste sem credenciais e verifica o Unicode recebido."""

import json
import time
import urllib.error
import urllib.parse
import urllib.request

from biosync_auth.protection import encode_webhook, security_webhook_url, webhook_payload


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main():
    url = urllib.parse.urlsplit(security_webhook_url())
    if (url.scheme != "https" or url.hostname != "discord.com"
            or not url.path.startswith("/api/webhooks/") or url.username
            or url.password or url.fragment or url.port not in (None, 443)):
        print("Webhook ausente ou inválido; nada enviado.")
        return 2
    query = dict(urllib.parse.parse_qsl(url.query))
    query["wait"] = "true"
    destination = urllib.parse.urlunsplit(url._replace(query=urllib.parse.urlencode(query)))
    event = {
        "attempt": 1, "computer": "TESTE DE CONFIGURAÇÃO", "hwid": None,
        "attempted_key": "TESTE — SEM LICENÇA REAL", "signal": "teste_manual_sem_detecção",
        "timestamp": int(time.time()),
    }
    payload = webhook_payload(event)
    embed = payload["embeds"][0]
    embed["title"] = "🧪 Teste de Webhook | BioSync — UTF-8"
    embed["description"] = (
        "Teste de codificação: ação, segurança, memória, usuário, não. ✅\n"
        "Nenhum depurador foi detectado, nenhum acesso foi bloqueado e nenhum ban foi aplicado."
    )
    embed["fields"][-1]["value"] = "Confirme o recebimento. Nenhuma ação contra usuários é necessária."
    request = urllib.request.Request(
        destination, data=encode_webhook(payload), method="POST",
        headers={"Content-Type": "application/json; charset=utf-8", "User-Agent": "BioSync-Webhook-Test/1.0"},
    )
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=15) as response:
            received = json.loads(response.read(65536))
            received_embed = received.get("embeds", [{}])[0]
            verified = all(received_embed.get(field) == embed[field] for field in ("title", "description", "fields", "footer", "color"))
            print(json.dumps({"http": response.status, "mensagem_confirmada": bool(received.get("id")), "unicode_preservado": verified}, ensure_ascii=True))
            return 0 if received.get("id") and verified else 1
    except urllib.error.HTTPError as exc:
        print(json.dumps({"http": exc.code, "mensagem_confirmada": False}))
        return 1
    except (urllib.error.URLError, TimeoutError, OSError):
        print("Falha de conexao; entrega nao confirmada.")
        return 2
    except (ValueError, KeyError, IndexError):
        print("Resposta inesperada; codificacao nao confirmada. Nao repetir automaticamente.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
