# Changelog

## v2.1.1 · 2026-09-24

Integra o branch `fix/revisao-doc-oficial` (29/07), que tinha ficado fora da `main`, e arruma o repositório.

- **`sintaxe-e-performance.md`:** novas seções "As regras que quebram a query" (alias obrigatório em toda agregação, `now()` e `isnotnull()` inexistentes, tipos estritos, `let` no topo, aspas no `with`, `take` que não corta no meio do pipeline), "O editor mente", "Combinando fontes" (`join` com o lado direito em `let`, `union`) e "Gráficos" (os 5 tipos que renderizam, `xtitle`/`ytitle`). `project` escolhe colunas; quem renomeia é `extend`. Nota de que `DeviceProcessEvents` vem do MDE ingerido por conector.
- **E-mail · Regras de e-mail que mais dispararam:** o alias do `mv-expand` não colide mais com o do `summarize` (`regraExpandida` / `regraId`).
- **`tags`:** `has_any ("MITRE.T1055")` no lugar de `has "MITRE.T1055"` (Triagem, cola 4.4, README). Funciona com um valor ou vários.
- `ago(24h)` padronizado para `ago(1d)`; `summarize count() by` da cola ganhou alias.
- **Releases automáticas:** versão nova no `CHANGELOG.md` chegando na `main` vira tag anotada + Release no GitHub (`.github/workflows/release.yml`); versões antigas podem ser marcadas pelo Run workflow. `kb.py versao` / `kb.py notas` leem o CHANGELOG, e o `build` mantém o rodapé do README na versão certa.
- **Repositório:** CI roda uma vez por PR (antes rodava no push e no PR), com `workflow_dispatch` e permissão só de leitura; selos no README; template de PR e formulários de issue (**Hunt novo**, **Hunt com problema**); convenção de mensagens de commit no `CONTRIBUTING.md`; `.editorconfig`; `.mailmap` unifica os nomes do mesmo autor; `__pycache__/` no `.gitignore`.

## v2.1.0 · 2026-09-24

Revisão de correção dos hunts, validação automática e painel gerado a partir do Markdown. De 149 para **154 hunts**.

**Correções que mudam resultado (falsos negativos):**

- **`has_any` trocado por `matches regex "(?i)…"` em 23 hunts de linha de comando.** `has`/`has_any` são case-sensitive, então variações de caixa escapavam: `iex`, `\\srv\C$`, `ADMIN$`, `schtasks /Create`, `NET USER`, `CertUtil`, `.VBS`, `README.txt`, etc.
- **Criação de conta / grupo admin:** o termo literal `"net user /add"` nunca casava com o comando real (`net user <nome> <senha> /add`). Agora cobre `net`/`net1`, `localgroup`/`group` com admin ou `/add`, e os cmdlets `New-LocalUser` / `Add-LocalGroupMember` / `Add-ADGroupMember`.
- **Cópia para share administrativo:** `C$`/`ADMIN$` em maiúsculas (a forma mais comum) não eram pegos.
- **PowerShell codificado:** agora pega `-e`, `-ec`, `-enc`, `-EncodedCommand` (e `/e…`) seguidos do blob base64, e também `pwsh`. Antes só `-enc`.
- **Precisão (menos ruído):** reverse shell não casa mais `concat`/`sync.exe`; dump de SAM exige `reg save|export HKLM\SAM|SYSTEM|SECURITY` (antes casava qualquer linha com "reg", "save" e "system"); Registry Run e Winlogon exigem a chave certa; Startup exige a pasta Startup de fato.
- `take 100` nos 9 hunts de linhas cruas que não tinham limite; `sort by hora asc` antes do `render` nos gráficos que não ordenavam.
- **Cola de consultas:** janela de tempo nas 8 queries que varriam tudo, limite nas que não tinham, hostname real trocado por `NOME-DO-HOST`, aviso de que `DeviceLogonEvents` não está confirmado em todos os tenants.

**Novos hunts (5):** Beaconing · presença constante e baixo volume (Rede / C2), Brute force · falhas e bloqueios por host (Credenciais), Servidor web ou SQL gerando shell (webshell) (Persistência), Detecções por técnica MITRE (ranking) (Triagem), Coletores ativos (todas as fontes) (Visão geral). Montados a partir de padrões já verificados em produção; valide no seu tenant na primeira execução.

**Limitações explícitas:** hunts que esbarram num limite do TQL ganharam a linha `> **Limitação:**` (decode de base64, `bin()` sem 5 min, spray sem filtro de falha, "viagem impossível" sem geolocalização, `userIdentity` do root), exibida também no painel.

**Ferramentas:**

- `scripts/tqlcheck.py`: validador estático de TQL (funções que não existem, `bin()`/`ago()` inválidos, `&&`/`||`, join anti, regex em coluna dynamic, sem janela, sem limite).
- `scripts/kb.py`: `lint` (tqlcheck + regras da base, incluindo `has_any` em linha de comando), `test` (amostras de `tests/amostras.json` contra os filtros dos hunts), `build` (regera `hunts/README.md`, contadores do README e os dados do painel a partir dos `.md`) e `check` (CI).
- `.github/workflows/validar.yml`: roda tudo em cada push e PR.
- Índice de hunts agora linka direto na âncora de cada hunt.

**Painel:** dados gerados pelo `build` (Markdown e painel não se desalinham mais), técnica MITRE vira link para attack.mitre.org, nota de limitação no card e checagem da query ao vivo no "+ Adicionar hunt".

**Documentação:** `sintaxe-e-performance.md` ganhou "Limites da linguagem", o checklist "Voltou vazio? Confirme antes de concluir", o link para o dicionário de colunas (`tm-v1-schema`) e a lista de funções que funcionam mas não estão documentadas. A orientação "zero resultado também é resposta" virou "zero resultado só vale depois de confirmar a fonte".

## v2.0.0 · 2026-07-22

Grande expansão: de 41 para **149 hunts** em **17 categorias**, cobrindo o ciclo MITRE de ponta a ponta.

- Novas categorias: **Evasão de defesa, Escalonamento de privilégio, Coleta, Exfiltração, Impacto / Ransomware, Nuvem (AWS CloudTrail)**.
- E-mail ampliado para 13 hunts; Identidade para 9; Triagem e Visão geral para 8 cada.
- Cobertura por tática: execução/LOLBins, dump de credenciais (mimikatz / DCSync / Kerberoasting / SAM), UAC bypass, desabilitar EDR/AMSI/firewall, PsExec/WinRM/DCOM/RDP, RMM e túneis, exfil por nuvem/FTP/HTTP, deleção de shadow copies e indícios de ransomware.
- Nota de compatibilidade: os hunts de endpoint usam `eventCategory == "DeviceProcessEvents"`; se o seu tenant não expuser esse valor, troque por `with (log_type="telemetry")` (ver `sintaxe-e-performance.md`). Campos de e-mail/identidade/nuvem devem ser validados no editor.

## v1.1.0 · 2026-07-22

Expansão da base (21 → **41 hunts**) e correção dos hunts de e-mail com o schema real.

- Nova categoria **Movimento lateral** (PsExec / execução remota; WinRM / PowerShell remoto).
- **E-mail refeito com o schema expandido real** do tenant: `mailSmtpFromAddresses`, `mailSmtpRecipients`, `mailAttachmentHash`, `mailThreatTypes`, `mailUrlsVisibleLink` / `mailUrlsRealLink`, `malSrc` / `malDst`. Os campos genéricos dos exemplos oficiais (`mailFromAddresses`, `mailToAddresses`, `mailMsgSubject`, `attachmentFileName`) não existiam no ambiente (parecem ser do método legado).
- **Novos hunts:** Office gerando shell (macro), script em pasta temporária, ferramentas de dump (mimikatz/procdump/comsvcs), NTDS.dit / shadow copy, assinatura de evento WMI, recon de Active Directory, descoberta de compartilhamentos, túnel/anonymizer, falhas de sign-in por conta (Entra), password spray por IP, Fortigate por ação (vendorParsed), detecções não bloqueadas, detecções por severidade (gráfico), eventos por productCode, e "último log recebido" por fonte de terceiro (qualidade de dados).
- **Conteúdo** nos arquivos Markdown de `hunts/`, espelhado no painel HTML (`painel/tql-threat-hunting.html`).
- Nota de contexto no README: aposentadoria dos métodos de busca antigos no fim de setembro/2026.

## v1.0.0 · 2026-07-22

Versão inicial da base de conhecimento.

- 21 hunts em TQL, organizados em 10 categorias (Execução, Credenciais, Persistência, Descoberta, Rede/C2, Identidade, E-mail, Firewall de terceiros, Triagem, Visão geral).
- Índice de hunts (`hunts/README.md`) com tabela por categoria e lista completa por técnica MITRE.
- Cola de bolso com ~25 consultas de exemplo (`consultas-de-exemplo.md`).
- Referência de sintaxe, performance, campos confirmados e troubleshooting (`sintaxe-e-performance.md`).
- Painel interativo em HTML (`painel/tql-threat-hunting.html`): busca, filtro por tática, copiar-query, adicionar hunt (localStorage) e backup/restaurar em JSON.
- Guia de contribuição (`CONTRIBUTING.md`).
