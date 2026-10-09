# BioSync Menu

## Estrutura do projeto

```text
pwfauth/
├── biosync_auth/          # Código do autenticador
│   ├── app.py            # Janela, login e integração Qt
│   ├── protection.py     # Detector e mensagens do webhook
│   ├── paths.py          # Caminhos do projeto
│   └── __main__.py       # Entrada: python -m biosync_auth
├── tests/                # Testes automatizados isolados
├── scripts/              # Homologação da API e teste do webhook
├── assets/
│   ├── branding/         # Logo e banner animado
│   ├── icons/            # Ícones da interface
│   └── cursors/          # Cursores personalizados
├── config/
│   ├── examples/         # Modelos sem credenciais reais
│   └── local/            # Keys e webhook locais; ignorados pelo Git
├── reports/              # Resultados gerados; JSON ignorado pelo Git
├── docs/
│   ├── security/         # Auditoria e relatório de proteção
├── pwfauth.py            # Atalho compatível para iniciar o app
├── requirements.txt
└── README.md
```

Execute os comandos abaixo na raiz do projeto. Crie seu ambiente `.venv` localmente;
ele não é enviado ao GitHub.
O atalho `python pwfauth.py` continua disponível; para incorporar a janela,
prefira `from biosync_auth import MenuAutenticacao`.

Testes locais, sem envio à API ou ao Discord:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Documentação: [auditoria](docs/security/ANALISE_SEGURANCA.md) e
[teste de proteção](docs/security/TESTE_PROTECAO.md).

Tela desktop em Python 3 e PySide6 com estilos QSS. Usa o emblema em
`assets/branding/Emblema Neon BioSYNC MENU.png`. O layout segue a referência; a textura
decorativa do fundo e do botão da imagem original não está incluída.

## Executar no Windows (PowerShell)

```powershell
git clone https://github.com/BioSyncHub/BioSync-Auth.git
cd BioSync-Auth
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
$env:PWF_APP_SECRET = 'APP_SECRET_DA_SUA_APLICACAO'
$env:BIOSYNC_DISCORD_URL = 'https://discord.gg/SEU_CONVITE'
$env:BIOSYNC_STORE_URL = 'https://SUA_LOJA'
$env:BIOSYNC_RECOVERY_URL = 'https://SEU_SUPORTE'
.\.venv\Scripts\python -m biosync_auth
```

Obtenha o App Secret no painel do PWF Auth, dentro da sua aplicação. Não coloque
credenciais reais no repositório. As variáveis de links são opcionais: se não
estiverem configuradas, o botão mostra uma mensagem.

## Autenticação

A chamada real é `POST https://pwfauth.com/api/auth/login.php`, com
`X-App-Secret`, `Content-Type: application/json` e `Accept: application/json`.
O conteúdo inclui `license_key` e `hwid`. Conforme a
[documentação oficial](https://pwfauth.com/api-reference), o login exige um
envelope JSON `{p, t, s}`: os campos são criptografados com AES-256-CBC e
assinados com HMAC-SHA256. O código valida a assinatura e o horário da resposta
antes de descriptografá-la. O endpoint `check-key.php` aceita JSON simples,
mas não faz Hardware Binding, por isso não é usado aqui.

No Windows, o HWID é um SHA-256 do MachineGuid com um prefixo fixo. É estável
entre execuções e pode mudar após reinstalar/clonar o sistema. Não é uma prova
inviolável de identidade física. macOS usa IOPlatformUUID e Linux usa machine-id.

A requisição usa QtNetwork de forma assíncrona, valida TLS normalmente e tem
timeout de 15 segundos. Os códigos de erro da API são traduzidos para português.
Somente uma resposta HTTP de sucesso com `success: true` fecha a janela após
o alerta. “Salvar Key” guarda a chave após autenticar, usando o cofre do sistema
via `keyring`; desmarcar remove a chave salva. QSettings armazena apenas a
preferência. Nunca há fallback de armazenamento da chave em texto simples.

Este programa termina após autenticar, conforme solicitado. A resposta fica em
`MenuAutenticacao.auth_response` para uma futura integração com o menu principal.
Se você mantiver outro aplicativo aberto usando a sessão, implemente heartbeat
no intervalo retornado pelo login e logout ao encerrar, conforme a API.

Um App Secret distribuído em um cliente desktop pode ser extraído; uma variável
de ambiente evita incluí-lo no código, mas não o torna inacessível no computador.

## Validação e uso do resultado

Um resultado positivo exige envelope completo `{p, t, s}`, assinatura e horário
válidos, `success` booleano e `session_id` como string não vazia nem composta
somente por espaços. Sucesso em JSON simples é recusado; erros simples continuam
permitidos para exibir falhas da API. HTTP sem sucesso ou erro de rede impedem a
autorização mesmo quando o payload é válido.

Falhas de transporte são verificadas antes de ler ou validar o corpo, inclusive
quando já há status HTTP. Queda de rede, timeout, cancelamento e falha TLS recusam
o login, limpam a autorização anterior e exibem “Erro de conexão”. Não existe
autorização offline nem aproveitamento de resposta parcial. Uma nova tentativa
precisa de nova requisição válida. Respostas HTTP 4xx/5xx com erros correspondentes
do Qt continuam permitindo exibir a recusa da API, como `EXPIRED` ou `BANNED`.

A leitura para parsing é limitada a 1 MiB. JSON inválido, aninhamento excessivo,
estouro numérico e timestamp fora da faixa são recusados com a mensagem
“Resposta inválida ou corrompida do servidor”. Esse limite protege a cópia e o
parsing em Python; ainda não limita o buffer de rede do Qt durante a transferência.

A Key fica mascarada e seu campo é limpo ao fechar, junto das referências
temporárias `pending_key` e `crypto`. O payload validado é preservado integralmente
em `auth_response`, incluindo as credenciais que o servidor retornar. Limpar
referências não garante sobrescrever todas as cópias na memória do Python.

Um script controlador no mesmo processo pode manter a referência à janela:

```python
from PySide6.QtWidgets import QApplication
from biosync_auth import MenuAutenticacao

app = QApplication([])
window = MenuAutenticacao()
window.show()
app.exec()

response = window.auth_response
if response is not None:
    session_id = response["session_id"]
    # Integre response ao aplicativo e mantenha o ciclo de sessão.
else:
    # Cancelamento, falha de conexão ou autenticação recusada.
    raise SystemExit(1)
```

`auth_response` não é transferido automaticamente para outro processo. O programa
que incorpora a janela é responsável pelo uso, retenção e descarte dessa sessão.

## Homologação com as três Keys de teste

No terminal com `PWF_APP_SECRET` configurado, execute:

```powershell
New-Item -ItemType Directory -Force config/local | Out-Null
Copy-Item config/examples/keys_teste.example.json config/local/keys_teste.local.json
# Edite o arquivo local com suas três Keys de teste antes de executar.
.\.venv\Scripts\python.exe -m scripts.validar_api
```

O script lê `config/local/keys_teste.local.json` e usa os métodos `login` e `login_finished`
do app com a rede real e o HWID deste computador. Os alertas e o cofre são
simulados; as preferências são isoladas em arquivo temporário. A Key ativa deve
autorizar com sessão válida; a expirada deve ser recusada especificamente com
`EXPIRED`; a banida, com `BANNED`. Falha de conexão ou configuração não conta como
recusa correta de uma licença.

Após qualquer sucesso, o script tenta encerrar somente a sessão criada usando
o logout criptografado descrito na [API oficial](https://pwfauth.com/api-reference).
Não altera status, vínculo ou validade das licenças por endpoints administrativos.
O login continua sujeito às regras de sessão/dispositivo do provedor.

Se o segredo não estiver na variável de ambiente, o script solicita uma entrada
oculta no terminal interativo, sem salvá-lo. O resultado é gravado em
`reports/resultado_teste_api.local.json`, sem Keys, segredo, HWID ou identificador de sessão.
Os dois arquivos locais estão no `.gitignore`. Saída 0 significa três cenários
aprovados e logout confirmado; saída 1 indica falha e saída 2, configuração ausente.

## Aviso e encerramento por depurador

`biosync_auth/protection.py` consulta `sys.gettrace()` e, no Windows, as APIs documentadas
[IsDebuggerPresent](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-isdebuggerpresent)
e [CheckRemoteDebuggerPresent](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-checkremotedebuggerpresent).
Elas indicam depuração; **não detectam toda leitura de memória, keyloggers ou
malware**. Ferramentas legítimas de depuração/trace também podem ativar o bloqueio.

A verificação ocorre a cada 500 ms, antes do login e antes de processar a resposta.
Ao detectar o sinal, o cliente invalida a sessão local, limpa Key/referências
temporárias, aborta a requisição e bloqueia novos logins. Mostra o texto solicitado
e fecha o diálogo automaticamente em até cinco segundos, ou quando o usuário o
dispensa. Em seguida fecha a janela e sai do loop Qt com código 3. No programa
standalone, `main` encerra o processo com esse código; um aplicativo que incorpora
a janela precisa respeitar o encerramento, sem continuar usando uma sessão antiga.
Isso não termina outros processos nem realiza logout remoto.

É contada uma ocorrência por execução, persistida em QSettings para este usuário.
A partir da terceira ocorrência, o aviso inclui o nome do PC e o texto sobre ban
de HWID. **Nenhum ban é executado**, conforme a preferência confirmada. O contador
local pode ser alterado/apagado e não é evidência confiável para um ban automático.
Se o HWID não puder ser coletado, o aviso e o encerramento continuam, com HWID
marcado como indisponível. Uma falha técnica na consulta bloqueia o login, mas
não aumenta o contador de ocorrências.

Para habilitar o aviso no Discord, configure no mesmo terminal:

```powershell
$env:BIOSYNC_SECURITY_WEBHOOK_URL = 'https://discord.com/api/webhooks/ID/TOKEN'
```

Também é possível configurar `security_webhook_url` em `config/local/webhook.local.json`.
Para criar esse arquivo em uma cópia baixada do GitHub:

```powershell
New-Item -ItemType Directory -Force config/local | Out-Null
Copy-Item config/examples/webhook.example.json config/local/webhook.local.json
# Edite security_webhook_url no arquivo local com a URL do seu webhook.
```

O arquivo local está no `.gitignore`; ele contém um token sensível e não deve
ser publicado ou incluído no instalador. Sem essa configuração, o envio de
alertas ao Discord fica desativado.
Uma variável de ambiente definida tem prioridade sobre o arquivo. Se a variável
estiver definida como vazia, o envio é desativado.

O envio segue o [formato de webhook do Discord](https://docs.discord.com/developers/resources/webhook#execute-webhook)
e informa sinal detectado, contador local, nome do PC, HWID coletado e **Key tentada
sem validação**, quando existir. Não envia App Secret, sessão ou conteúdo da
memória. Não grava a Key do evento nas preferências. O alerta usa um embed com
o modelo solicitado, HWID, Key tentada, computador, sinal e horário UTC do evento.
Somente a menção ao cargo `1516411676096991232` é permitida; menções adicionais
em nomes/Keys, incluindo `@everyone`, não são autorizadas. O Discord ainda aplica
as permissões de menção do cargo/canal.
A URL deve ser HTTPS no host `discord.com`, sem redirects automáticos.

O alerta é enviado de forma assíncrona, com timeout de transferência de três
segundos. Sem internet ou com encerramento antecipado, pode não ser entregue;
falha de envio não deve liberar acesso. A URL do webhook é um segredo recuperável
no cliente, e um evento enviado por ele pode ser falsificado. Em produção,
prefira um serviço seu para validar eventos e encaminhá-los ao Discord.

Para enviar uma mensagem de teste sem credenciais reais:

```powershell
.\.venv\Scripts\python.exe -m scripts.testar_webhook
```

Os textos vêm do arquivo Python em UTF-8, evitando a conversão de caracteres ao
enviar código pelo pipeline do PowerShell. O app e o script usam a mesma função
de serialização UTF-8, com `Content-Type: application/json; charset=utf-8`.
O teste solicita confirmação ao Discord e compara os textos retornados com os
enviados. `unicode_preservado: true` confirma acentos e emojis na resposta.
