# Análise de prontidão — BioSync Menu

Organização atual (09/10/2026): o antigo `pwfauth.py` está em
`biosync_auth/app.py`; proteção em `biosync_auth/protection.py`; testes em `tests/`;
scripts em `scripts/`; configurações locais em `config/local/` e resultados em
`reports/`. O `pwfauth.py` da raiz agora é um atalho. As referências de código e
comandos nas evidências históricas descrevem a versão analisada naquele momento.
Consulte o [README atual](../../README.md) para os comandos atualizados.

Data: 8 de outubro de 2026. Escopo: arquivos do projeto, ambiente Python instalado, testes locais e contrato público da API.

## Parecer

Atualização mais recente: verificação de depurador, avisos e encerramento foram
adicionados conforme a solicitação; **42 testes passaram**. Não há detecção
garantida de toda leitura de memória nem ban automático. Webhook ainda depende
de configuração e não foi enviado a um canal real. Consulte README e
TESTE_PROTECAO.md para os limites.

Teste de proteção posterior: [TESTE_PROTECAO.md](TESTE_PROTECAO.md).
Foram executados 30 testes automatizados com sucesso. Sondagens adicionais
confirmaram aceitação de resposta assinada repetida e de resposta para outra Key,
em simulação local controlada. Consulte o relatório para o escopo e os limites.

Atualização posterior de conexão: a suíte agora tem **33 testes aprovados**.
`login_finished` interrompe falhas de transporte antes de ler o corpo, limpa
qualquer autorização anterior e mostra “Erro de conexão”. Foram simuladas
63 combinações incluindo recusa de Key expirada e queda de rede. Recusas HTTP
normais continuam traduzidas. Esta alteração não resolve correlação/replay ou
manutenção de sessão.

**O aplicativo tem uma base funcional de login por licença, mas ainda não está pronto para uma implantação segura em produção.** Está apto a receber a implementação complementar, desde que os bloqueadores abaixo sejam tratados. Não há evidência suficiente para certificar a segurança do sistema completo.

Hoje existe uma tela de autenticação; após o sucesso ela exibe um alerta e encerra o programa. Não existe aplicação protegida posterior, serviço próprio, controle de acesso a recursos, manutenção da sessão ou empacotamento para distribuição no material analisado. O login por Key não implementa contas com usuário/senha ou autenticação multifator.

Na auditoria original, o código de execução em `pwfauth.py` foi mantido e o isolamento dos testes foi corrigido. A implementação posterior solicitada está registrada abaixo; os achados detalhados preservam as evidências do estado original.

## Atualização após as correções solicitadas

- **Achado 1 corrigido:** resultados positivos exigem envelope completo e decifração autenticada. JSON simples de sucesso é recusado; erros simples continuam sendo exibidos.
- **Achado 2 corrigido:** resultados positivos exigem `session_id` como string não vazia e não composta somente por espaços.
- **Achado 5 parcialmente corrigido:** parsing e decifração capturam `RecursionError` e `OverflowError`; timestamp tem faixa validada; leitura para cópia/parsing limitada a 1 MiB. Permanece pendente limitar a transferência/buffer do Qt durante o recebimento.
- **Achado 8 parcialmente corrigido:** Key mascarada por padrão e campo/referências temporárias limpos no fechamento. O payload validado permanece em `auth_response` para o controlador, por solicitação; seu descarte e a manutenção da sessão cabem ao aplicativo consumidor. Não há garantia de sobrescrita de memória em Python.
- **Estado confirmado:** `auth_response` permanece `None` em rejeições e guarda integralmente o payload validado em sucesso HTTP sem erro de rede, mesmo após fechar a janela.
- **Validação posterior:** 20 testes passaram, com respostas simuladas e settings/cofre isolados. Incluem envelope parcial/adulterado, sucesso simples, sessões inválidas, JSON hostil simples e criptografado, timestamp extremo, exceções de overflow/recursão, falhas de HTTP/TLS e retenção do payload no fechamento.

Estas correções não implementam heartbeat/logout, autorização em servidor ou homologação real, nem eliminam os demais limites desta auditoria.

### Preparação da homologação das três licenças

A pedido do usuário, foram fornecidas três Keys de teste declaradas como ativa
neste PC, expirada e banida. A suíte local foi novamente executada: **20 testes
passaram**. O processo das ferramentas não tinha `PWF_APP_SECRET`, portanto
**nenhum dos três estados foi confirmado na API real nesta execução**.

Foi criado `validar_api.py` para executar o login do próprio app contra o serviço,
com preferências e cofre isolados. O script foi conferido com respostas simuladas
nos três cenários; essa conferência não valida as licenças reais. A execução real
foi interrompida antes de qualquer requisição por ausência do segredo.

Os resultados reais, quando o usuário executar o script no terminal configurado,
serão registrados em `resultado_teste_api.local.json` sem credenciais. O logout
adicionado pertence apenas ao script de homologação; o app ainda não implementa
o ciclo de sessão contínua.

## Evidências executadas

- Leitura de `pwfauth.py`, `test_pwfauth.py`, `requirements.txt`, `README.md` e `.gitignore`; conferência dos assets referenciados e do ambiente local.
- Suíte original: **8 testes passaram**. Após isolamento e novas verificações: **11 testes passaram**.
- `python -m pip check`: **nenhum conflito de dependências**. Esse comando não pesquisa vulnerabilidades conhecidas.
- Ambiente: Python **3.12.10**, PySide6 **6.12.0**, cryptography **50.0.2**, keyring **25.7.0**.
- Qt informou suporte a TLS via Secure Channel do Windows. Isso verifica a disponibilidade local do mecanismo, sem provar negociação TLS com a API.
- Backend local do cofre: `keyring.backends.Windows.WinVaultKeyring`. Nenhuma credencial foi impressa.
- A janela abriu em modo offscreen e o GIF principal foi reconhecido. Não foi feita inspeção visual interativa nem teste de acessibilidade completo.
- As quatro variáveis de configuração consultadas estavam ausentes no processo: `PWF_APP_SECRET`, `BIOSYNC_DISCORD_URL`, `BIOSYNC_STORE_URL` e `BIOSYNC_RECOVERY_URL`.
- Respostas simuladas confirmaram aceitação de sucesso sem envelope, aceitação de sessão ausente/vazia, repetição de envelope e exceções não tratadas para timestamp extremo e JSON profundamente aninhado.
- Não houve chamada autenticada à API, ativação de licença, envio de HWID real ao provedor ou teste de invasão do serviço.

## O que já está adequado

| Área | Evidência local | Limite da avaliação |
| --- | --- | --- |
| Transporte | URL fixa HTTPS; não há desativação explícita da validação TLS | Falta teste real de conexão e certificado inválido |
| Redirecionamentos | Política manual impede seguimento automático | Deve permanecer nas futuras chamadas autenticadas |
| Criptografia | IV aleatório, chaves distintas de cifra/MAC, HMAC comparado em tempo constante antes da decifragem | O envelope ainda é opcional ao receber sucesso |
| Horário | Envelope rejeitado quando fora da janela de 300 segundos | Não impede repetição dentro dessa janela |
| Credenciais locais | Key salva somente após sucesso; preferência separada em QSettings | Backend do cofre precisa ser verificado no ambiente distribuído |
| Concorrência | Impede segundo envio enquanto `reply` existe | Não controla frequência entre requisições |
| Resultado HTTP | Sucesso exige HTTP 2xx e ausência de erro de rede | Corpo de sucesso tem validação incompleta |
| Interface | Entrada limitada a 512 caracteres; alertas exibem texto simples | A licença continua visível na tela |
| Encerramento | Aborta requisição pendente e interrompe animações | Não encerra sessão remota |
| Identificação | HWID local retornou hash estável de 64 caracteres | Identificador pode ser copiado ou alterado |
| Repositório | `.env` e ambiente virtual estão no `.gitignore`; nenhum segredo literal identificado no código revisado | A pasta atual não é um repositório Git; não foi possível revisar histórico |

## Achados priorizados

### 1. Alta — sucesso aceito sem autenticação do envelope

**Local:** `pwfauth.py:735–743`, método `login_finished`.

`self.crypto.unpack(data)` só é chamado quando existe o campo `p`. Uma resposta HTTP 200 com `{"success": true}` é aceita, salva a Key se solicitado e fecha a janela, sem verificar HMAC ou timestamp. A reprodução local confirmou esse comportamento.

É uma falha de validação do protocolo. Não demonstra que um atacante na rede consiga contornar TLS: ainda precisaria controlar a resposta recebida pelo cliente, comprometer sua confiança ou manipular sua execução.

**Correção necessária:** exigir envelope completo e válido para qualquer resultado positivo. Se forem suportados erros em JSON simples, esses erros nunca podem autorizar acesso. Criar testes que rejeitem sucesso simples, envelope parcial e assinatura inválida.

### 2. Alta — sucesso sem sessão válida

**Local:** `pwfauth.py:739–755`.

Mesmo um envelope válido contendo apenas `{"success": true}`, ou com `session_id` vazio, autoriza o fluxo atual. Foram reproduzidos ambos os casos.

**Correção necessária:** validar o esquema mínimo de sucesso, incluindo `session_id` como string não vazia, antes de persistir credenciais e disponibilizar qualquer recurso. Definir regras para o intervalo de heartbeat e campos de autorização efetivamente utilizados. Valores inesperados devem recusar o acesso.

### 3. Alta para uma aplicação contínua — ciclo de sessão inexistente

**Local:** `pwfauth.py:744–755`, `closeEvent` e `main`.

`auth_response` guarda o corpo, mas não é consumido por outro componente. Não há heartbeat, logout nem transição para um menu protegido. Fechar a tela após sucesso encerra o processo atual; fechar sem autenticar também encerra normalmente. Um lançador externo não deve interpretar simplesmente a saída do processo como autorização.

**Correção necessária:** criar um componente responsável pela sessão e uma transição explícita de autenticação confirmada para o aplicativo. Para uso contínuo, definir comportamento em revogação, expiração, falha de rede e retomada após suspensão. Se o produto permanecer apenas uma demonstração de login que termina imediatamente, documentar esse escopo e encerrar a sessão remota criada.

### 4. Alta como limite arquitetural — cliente não é uma autoridade confiável

**Local:** `pwfauth.py:698–711`, `CryptoEnvelope` e `collect_hwid`.

O App Secret chega ao computador do usuário por variável de ambiente e é usado no cabeçalho e na criptografia. Pode ser extraído nesse computador. O próprio código Python e os ramos de sucesso podem ser modificados. SHA-256 do identificador da máquina não transforma o HWID em prova inviolável.

**Correção necessária:** tratar o App Secret distribuído como credencial recuperável. Operações e dados sensíveis devem exigir autorização do lado de um serviço confiável. Nunca distribuir token administrativo. Definir rotação de credenciais, escopo das permissões e resposta à extração. Para funcionalidades inteiramente locais, explicitar que barreiras no cliente não oferecem garantia absoluta contra adulteração.

### 5. Média — respostas sem limite de tamanho ou complexidade

**Local:** `pwfauth.py:166–181` e `724–740`.

O corpo é lido integralmente e passado a `json.loads`, sem limite de bytes. JSON com 20 mil níveis de aninhamento causou `RecursionError` não tratado. Um timestamp inteiro extremo, acompanhado de MAC válido na simulação, causou `OverflowError` não tratado. O segundo caso depende de quem pode produzir uma assinatura válida; o primeiro nem chega à verificação do envelope.

**Correção necessária:** limitar o volume recebido durante a transferência, abortar respostas excedentes e validar tipos e faixas dos campos antes das operações. Tratar as falhas específicas de parsing/overflow e garantir limpeza do estado. Verificar também tipo de conteúdo e resposta truncada. Não basta limitar somente depois de alocar o corpo inteiro.

### 6. Média — não há vínculo entre resposta e tentativa atual

**Local:** `pwfauth.py:166–173`, `pending_key` e `login_finished`.

O mesmo envelope foi decifrado duas vezes com sucesso. O cliente valida assinatura e proximidade temporal, mas não relaciona o resultado a uma tentativa específica. Não há nonce, identificador de requisição ou verificação de correspondência da licença retornada.

**Correção necessária:** verificar identidade e sessão retornadas quando disponíveis e investigar mecanismos de correlação suportados pelo provedor. Não inventar campos incompatíveis com a API. Repetição criptográfica dentro da janela é uma limitação observada; não foi demonstrado ataque remoto nem ausência de proteção no servidor.

### 7. Média — testes acessavam configuração real; corrigido

**Local original:** `test_pwfauth.py`, `setUpClass` e `setUp`.

`QSettings.setDefaultFormat(IniFormat)` não mudou o formato do construtor usado pelo app. A conferência mostrou `NativeFormat` e o destino `HKEY_CURRENT_USER\Software\BioSync\Menu`. A suíte original executava `settings.clear()` nesse destino e a criação da janela podia consultar o cofre real antes dos mocks individuais.

**Impacto da execução inicial:** ela alcançou as preferências reais do app e executou sua limpeza. Não há snapshot anterior para restaurá-las. Não foi identificado caminho de gravação ou exclusão de Key real nos testes executados; a gravação do teste de sucesso estava simulada.

**Correção aplicada:** substituir o construtor de settings antes de criar a janela, usar arquivo INI temporário explícito com fallbacks desativados e simular leitura, gravação e exclusão no cofre para todos os testes. Uma verificação nova confirma o destino temporário.

### 8. Média — retenção e exposição local de credenciais

**Local:** `pwfauth.py:591–595`, `653–673` e `770–777`.

O campo usa `QLineEdit.Normal`, deixando a licença visível, inclusive quando restaurada do cofre. No encerramento com requisição pendente, o código não limpa `pending_key`, `crypto` ou a entrada; no sucesso conserva toda a resposta em memória enquanto o objeto existir.

**Correção necessária:** mascarar a licença com opção de revelar, limpar referências e campos em cancelamento/logout e reter apenas dados necessários da sessão. Python não permite prometer apagamento seguro de todas as cópias em memória. No Windows avaliado, o backend é o cofre nativo; outros ambientes e configurações do keyring ainda precisam ser verificados.

### 9. Média operacional — frequência e falhas de rede incompletas

**Local:** `pwfauth.py:683–717` e `756–768`.

Não existe espera aplicada após 429; o botão volta a ficar disponível e `Retry-After` não é utilizado. O timeout de transferência está configurado, mas não foi demonstrado prazo máximo total para uma resposta recebida lentamente. Erros de transporte com status HTTP presente podem resultar em mensagem genérica de autenticação.

**Correção necessária:** aplicar espera indicada pelo serviço e eventual prazo total independente. Diferenciar erro de TLS, timeout, falha de transporte, redirecionamento recusado e licença inválida. Proteção contra força bruta precisa continuar no servidor; bloqueio no cliente melhora experiência e comportamento, sem impedir abuso externo.

### 10. Média operacional — configuração e distribuição incompletas

**Local:** `requirements.txt`, `README.md` e `main`.

As dependências usam faixas abertas, sem lockfile ou hashes. Não existem pipeline, instalador, manifesto de versão ou validação de uma instalação limpa. O ambiente atual contém componentes adicionais do PySide6 cuja presença não é especificada pelo projeto. As variáveis necessárias para o login e os links não estavam configuradas.

**Correção necessária:** registrar versões resolvidas, auditar vulnerabilidades conhecidas das dependências diretas e transitivas, escolher versão Python suportada e validar o artefato distribuído. Planejar inclusão dos assets e atualização/autenticidade do instalador conforme o canal escolhido. A aprovação de `pip check` não substitui auditoria de CVEs.

### 11. Baixa — tratamento de HWID não cobre falhas do processo no macOS

**Local:** `pwfauth.py:128–134` e `701–704`.

O caminho macOS usa `subprocess.run(..., check=True, timeout=5)`, mas o tratamento em `login` não inclui `CalledProcessError` ou `TimeoutExpired`. Essas falhas podem escapar do fluxo de mensagem ao usuário. O teste local do HWID foi feito apenas no Windows.

**Correção necessária:** tratar as exceções específicas, testar cada plataforma declarada e documentar mudanças de identidade após reinstalação/clonagem. Evitar expor detalhes internos desnecessários nas mensagens.

### 12. Baixa — manutenção e cobertura insuficientes

Interface, efeitos visuais, criptografia, rede, persistência e autenticação estão no mesmo arquivo. Os 11 testes verificam comportamentos importantes, mas não cobrem ciclo de sessão, formatos hostis de resposta, falhas do cofre, links malformados, cancelamento em todas as fases, conexão real, plataformas alternativas ou distribuição.

**Correção necessária:** separar configuração, transporte, validação de respostas e sessão da interface à medida que esses recursos forem implementados. Se futuramente for utilizado o SDK Python chamado `pwfauth`, o arquivo local de mesmo nome pode ocultar o pacote nos imports; resolver essa colisão antes da integração.

## Conferência do contrato externo

A derivação das chaves, o envelope e os campos enviados no login correspondem ao contrato consultado. A documentação exige envelope no login e descreve `session_id`, heartbeat periódico e logout; o cliente ainda não aplica todo esse fluxo. Também indica espera por `Retry-After` em 429. Fonte: [referência oficial PWF Auth](https://pwfauth.com/api-reference), consultada em 08/10/2026.

## Ordem de implementação e critérios de aceite

1. **Validação de autenticação:** sucesso simples, envelope inválido e sessão ausente/vazia devem ser rejeitados; HTTP ou TLS com falha nunca podem conceder acesso.
2. **Sessão e autorização:** definir o aplicativo posterior, manter a sessão quando houver uso contínuo e impedir acesso após revogação/expiração. Verificar permissões no serviço responsável por cada recurso sensível.
3. **Robustez:** respostas excessivas, JSON inválido/aninhado, timestamp fora da faixa, timeout, cancelamento e falhas do cofre devem terminar em estado conhecido, sem autorização acidental.
4. **Credenciais e identificação:** validar política de secret/HWID, armazenamento nativo, retenção e rotação; revisar quais dados serão transmitidos e informar o usuário.
5. **Entrega:** fixar dependências resolvidas, executar auditoria de vulnerabilidades, testar instalação limpa e configurar os serviços necessários.
6. **Homologação real:** com aplicação/licença de teste, verificar login válido/inválido, expiração, bloqueio, dispositivo divergente, 429, heartbeat, revogação e logout. Usar mocks para falhas que não possam ser provocadas com segurança no provedor.

## Limites do parecer

Não foram analisados código do servidor, painel da aplicação, regras reais de licença, permissões administrativas, vulnerabilidades do provedor, histórico Git, instalador ou outras aplicações consumidoras. Não houve auditoria automatizada de CVEs nem teste de autenticação com credenciais válidas. Passar nos testes locais demonstra apenas os casos cobertos; os achados reproduzidos de aceitação indevida permanecem no app.

**Resultado final:** base pronta para desenvolvimento complementar; implantação segura ainda depende dos bloqueadores, das correções e da homologação descritas acima.
