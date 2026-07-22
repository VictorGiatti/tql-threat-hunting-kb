# Changelog

## v2.0.0 — 2026-07-22

Grande expansão: de 41 para **149 hunts** em **17 categorias**, cobrindo o ciclo MITRE de ponta a ponta.

- Novas categorias: **Evasão de defesa, Escalonamento de privilégio, Coleta, Exfiltração, Impacto / Ransomware, Nuvem (AWS CloudTrail)**.
- E-mail ampliado para 13 hunts; Identidade para 9; Triagem e Visão geral para 8 cada.
- Cobertura por tática: execução/LOLBins, dump de credenciais (mimikatz / DCSync / Kerberoasting / SAM), UAC bypass, desabilitar EDR/AMSI/firewall, PsExec/WinRM/DCOM/RDP, RMM e túneis, exfil por nuvem/FTP/HTTP, deleção de shadow copies e indícios de ransomware.
- Nota de compatibilidade: os hunts de endpoint usam `eventCategory == "DeviceProcessEvents"`; se o seu tenant não expuser esse valor, troque por `with (log_type="telemetry")` (ver `sintaxe-e-performance.md`). Campos de e-mail/identidade/nuvem devem ser validados no editor.

## v1.1.0 — 2026-07-22

Expansão da base (21 → **41 hunts**) e correção dos hunts de e-mail com o schema real.

- Nova categoria **Movimento lateral** (PsExec / execução remota; WinRM / PowerShell remoto).
- **E-mail refeito com o schema expandido real** do tenant: `mailSmtpFromAddresses`, `mailSmtpRecipients`, `mailAttachmentHash`, `mailThreatTypes`, `mailUrlsVisibleLink` / `mailUrlsRealLink`, `malSrc` / `malDst`. Os campos genéricos dos exemplos oficiais (`mailFromAddresses`, `mailToAddresses`, `mailMsgSubject`, `attachmentFileName`) não existiam no ambiente (parecem ser do método legado).
- **Novos hunts:** Office gerando shell (macro), script em pasta temporária, ferramentas de dump (mimikatz/procdump/comsvcs), NTDS.dit / shadow copy, assinatura de evento WMI, recon de Active Directory, descoberta de compartilhamentos, túnel/anonymizer, falhas de sign-in por conta (Entra), password spray por IP, Fortigate por ação (vendorParsed), detecções não bloqueadas, detecções por severidade (gráfico), eventos por productCode, e "último log recebido" por fonte de terceiro (qualidade de dados).
- **Fonte única de verdade:** `hunts_data.js` + `build_all.js` regeneram o HTML, o painel e todo o Markdown de uma vez.
- Nota de contexto no README: aposentadoria dos métodos de busca antigos no fim de setembro/2026.

## v1.0.0 — 2026-07-22

Versão inicial da base de conhecimento.

- 21 hunts em TQL, organizados em 10 categorias (Execução, Credenciais, Persistência, Descoberta, Rede/C2, Identidade, E-mail, Firewall de terceiros, Triagem, Visão geral).
- Índice de hunts (`hunts/README.md`) com tabela por categoria e lista completa por técnica MITRE.
- Cola de bolso com ~25 consultas de exemplo (`consultas-de-exemplo.md`).
- Referência de sintaxe, performance, campos confirmados e troubleshooting (`sintaxe-e-performance.md`).
- Painel interativo em HTML (`painel/tql-threat-hunting.html`): busca, filtro por tática, copiar-query, adicionar hunt (localStorage) e backup/restaurar em JSON.
- Guia de contribuição (`CONTRIBUTING.md`).
