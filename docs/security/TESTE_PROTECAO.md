# Teste de proteção da aplicação

Organização atual (09/10/2026): código em `biosync_auth/`, testes em `tests/`,
ferramentas em `scripts/`, configurações em `config/local/` e resultados em
`reports/`. As descrições anteriores mantêm os nomes históricos dos arquivos.
Consulte o [README atual](../../README.md) para execução e configuração.

Data: 8 de outubro de 2026.

## Atualização em 9 de outubro: modelo do webhook

Validação posterior de codificação: **45 testes locais passaram**. Foi criado
`testar_webhook.py`, que envia o texto a partir de arquivo UTF-8 e compartilha a
serialização com o app. Uma mensagem real de teste foi enviada sem credenciais:
o Discord retornou HTTP 200, confirmou a mensagem e preservou título, descrição,
campos e footer com acentos e emojis. O teste não simula uma ocorrência de fraude
nem valida a entrega quando há queda de conexão.

A URL fornecida foi configurada em `webhook.local.json`, ignorado pelo Git.
O alerta passou a usar o embed solicitado, com HWID e Key tentada reais do evento,
horário UTC dinâmico e menção restrita ao cargo informado. A descrição distingue
depuração de leitura de memória/fraude, sem afirmar múltiplas tentativas quando
há apenas uma ocorrência local. O restante das menções é bloqueado.

**44 testes passaram**, incluindo configuração local/prioridade da variável,
timestamp, HWID ausente e payload. Nenhuma mensagem foi enviada ao Discord nesta
validação; entrega e permissões de menção no canal ainda não foram verificadas.

## Atualização: aviso por depurador e webhook opcional

Foram implementadas verificações de depurador Python/Windows, aviso com fechamento
automático, contagem local por execução e mensagem específica a partir da terceira
ocorrência. Nenhum ban automático é executado. Webhook opcional inclui a Key
tentada (não confirmada), sem App Secret ou sessão.

A suíte atual contém **42 testes aprovados**. Os nove novos testes verificam
bloqueio antes do login, limpeza de sessão, aborto durante a resposta, mensagem
da terceira ocorrência, HWID indisponível sem ban, contagem única por execução,
falha técnica sem registro de fraude, conteúdo do webhook e restrições de envio.
O detector nativo foi consultado neste ambiente e retornou ausência de depurador.
Detecções positivas foram simuladas; não foi anexado um depurador real, capturada
memória nem enviado webhook a um canal real.

Consultar as APIs de depuração não permite garantir detecção de qualquer leitura
de memória. O contador é local e manipulável; detecção de trace pode decorrer de
ferramentas legítimas. Encerramento e contagem não resolvem as lacunas de replay
e correlação identificadas anteriormente. Os detalhes e as referências oficiais
estão na seção correspondente do README.

## Atualização: queda de conexão durante autenticação

Foi implementada uma verificação de falhas de transporte antes da leitura do
corpo em `login_finished`. A suíte atual contém **33 testes, todos aprovados**.
O novo teste percorre 63 combinações de respostas parciais, recusa `EXPIRED` ou
sucesso assinado, com status ausente/200/403 e sete falhas de conexão, timeout,
TLS, proxy ou cancelamento. Em todas essas combinações, o corpo não é lido, o
acesso é recusado, a autorização antiga é limpa e nenhuma credencial é salva.

Outros dois testes verificam a preservação de recusas `EXPIRED`/`BANNED` em HTTP
403 e uma nova tentativa após queda de conexão sem reutilizar autorização.
A classificação distingue falhas de transporte dos erros de conteúdo/servidor
descritos na [referência oficial do Qt](https://doc.qt.io/qt-6/qnetworkreply.html#NetworkError-enum).

Não foi desligada fisicamente a internet do computador nem alterado o serviço
remoto: as falhas foram simuladas no objeto de resposta. O cliente já recusava
sucesso com erro de rede; a mudança impede também processamento de respostas
parciais e padroniza a mensagem. As demais lacunas abaixo permanecem.

**Resultado: 30 testes automatizados passaram, mas a aplicação ainda tem limites de proteção.** Duas sondagens adicionais confirmaram aceitação de uma resposta assinada repetida e de uma resposta cuja licença retornada difere da Key submetida.

## Escopo e execução

Foram exercitados os métodos reais de validação, criptografia e autenticação do cliente, usando respostas controladas e segredo fictício. As preferências foram isoladas em arquivo temporário; leitura, gravação e exclusão no cofre foram simuladas. Não foram enviados ataques à API nem utilizadas as licenças reais neste teste de proteção.

Foram adicionados 10 testes à suíte anterior de 20. Alguns testes percorrem múltiplos valores hostis por meio de subtestes; o total de 30 refere-se aos métodos de teste.

Comando de execução:

```powershell
.\.venv\Scripts\python.exe -m unittest -v
```

## Proteções verificadas

| Tentativa ou condição | Resultado observado |
| --- | --- |
| Sucesso em JSON simples | Recusado sem autorização ou persistência de Key |
| Alteração do ciphertext, timestamp ou HMAC sem nova assinatura | Recusada |
| Envelope assinado com segredo de outra aplicação | Recusado |
| Campos ausentes ou com tipos incorretos | Recusados |
| Assinatura com caracteres inválidos | Recusada sem exceção não tratada |
| Base64 ou ciphertext inválido, mesmo com HMAC calculado no ambiente simulado | Recusado |
| `success` numérico, texto ou outros valores não booleanos | Recusado |
| Sessão ausente, vazia, somente espaços ou com tipo incorreto | Recusada |
| Resposta assinada antiga ou futura além da janela aceita | Recusada |
| Timestamp extremo | Recusado sem overflow não tratado |
| JSON aninhado em excesso, inclusive dentro do envelope | Recusado sem recursão não tratada |
| JSON truncado ou bytes incompatíveis com JSON | Recusado |
| Corpo maior que 1 MiB | Recusado durante leitura para parsing |
| Sucesso assinado acompanhado de HTTP 3xx, 4xx, 5xx ou status ausente | Não autoriza |
| Sucesso assinado com erro de TLS, timeout, cancelamento ou conexão recusada | Não autoriza |
| Payload negativo `BANNED` ou `EXPIRED` com `session_id` presente | Não autoriza |
| Autorização antiga seguida de nova recusa | Estado de autorização limpo |
| Configuração da requisição autenticada | HTTPS e redirects manuais confirmados |
| Segundo login durante requisição pendente | Novo envio impedido |
| Cancelamento e fechamento | Requisição abortada; referências temporárias e campo da Key limpos |
| Sucesso legítimo simulado | Payload preservado após fechamento; Key mascarada |

O teste de redirects verifica a política configurada na requisição; não é um teste de servidor redirecionando a conexão. O teste de TLS simula o erro informado pelo Qt; não intercepta tráfego nem valida uma cadeia de certificados real.

## Limitações reproduzidas separadamente

### Repetição de resposta assinada recente

Foi criado um envelope com `success: true`, sessão fictícia e licença fictícia A. Ele foi entregue ao `login_finished` em uma tentativa original e, depois, em outra tentativa para a mesma licença, restaurando o contexto criptográfico como ocorreria em um novo login.

**Observação:** ambas as tentativas autorizaram. Não existe identificação de tentativa ou registro de respostas já consumidas no cliente. O timestamp limita a idade da resposta, mas não garante uso único.

### Resposta válida referente a outra Key

O mesmo envelope, contendo `user.license_key` da licença fictícia A, foi entregue a uma tentativa com `pending_key` da licença fictícia B.

**Observação:** a tentativa também autorizou. O cliente não compara a licença retornada com a licença submetida.

Esses resultados confirmam lacunas na validação de correlação. As sondagens controlavam diretamente a resposta recebida pelo app e não demonstram que um atacante de rede consiga contornar TLS, obter um envelope ou reproduzir esse comportamento contra o provedor. Também não avaliam proteções existentes no servidor.

Correções a considerar: conferir a identidade retornada quando disponível e implementar correlação/rejeição de replay compatível com a API. Conferir a Key sozinha não impede repetição para a mesma Key. Não adicionar campos ao protocolo sem verificar suporte do provedor.

## Pendências além dos casos testados

- O limite de 1 MiB não limita o buffer do Qt durante a transferência. Não foi realizado teste de esgotamento de memória ou de respostas recebidas lentamente.
- O app ainda não mantém heartbeat nem encerra a sessão remota por conta própria. O logout do script `validar_api.py` não adiciona essa proteção ao app.
- O código Python, o estado local e o App Secret continuam acessíveis no computador do usuário. Os testes não comprovam resistência à modificação do cliente nem autorização de recursos sensíveis no servidor.
- Não houve auditoria de dependências, do servidor, do instalador ou de outras aplicações que utilizarão o autenticador nesta execução.

## Relação com a homologação anterior

Na saída real fornecida pelo usuário, a licença ativa autorizou com logout confirmado, a expirada foi recusada com `EXPIRED` e a banida com `BANNED`. Isso comprova os cenários daquela execução relatada; não substitui as simulações adversariais nem resolve os limites acima.

## Parecer

As proteções implementadas bloquearam os formatos inválidos e as falhas de transporte cobertos pelos testes. **Não é possível declarar a aplicação inviolável ou plenamente pronta para produção:** há lacunas confirmadas de correlação/replay e pendências de sessão e proteção de recursos.

O código de execução do app foi mantido durante este teste. As alterações foram feitas na suíte de testes e neste relatório.
