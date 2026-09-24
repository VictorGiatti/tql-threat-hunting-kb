# Base de Hunts · índice

**154 hunts** em **17 categorias**. Ative o toggle **"Use Trend Query Language"** antes de rodar.

> Gerado por `python scripts/kb.py build` a partir dos arquivos de cada categoria. Não edite à mão.

## Por categoria

| Categoria | Hunts | Arquivo |
|---|--:|---|
| Execução | 14 | [execucao.md](execucao.md) |
| Evasão de defesa | 12 | [evasao-de-defesa.md](evasao-de-defesa.md) |
| Credenciais | 11 | [credenciais.md](credenciais.md) |
| Persistência | 12 | [persistencia.md](persistencia.md) |
| Escalonamento de privilégio | 6 | [escalonamento-de-privilegio.md](escalonamento-de-privilegio.md) |
| Descoberta | 10 | [descoberta.md](descoberta.md) |
| Movimento lateral | 8 | [movimento-lateral.md](movimento-lateral.md) |
| Coleta | 5 | [coleta.md](coleta.md) |
| Rede / C2 | 10 | [rede-c2.md](rede-c2.md) |
| Exfiltração | 5 | [exfiltracao.md](exfiltracao.md) |
| Impacto / Ransomware | 7 | [impacto-ransomware.md](impacto-ransomware.md) |
| Identidade | 9 | [identidade.md](identidade.md) |
| E-mail | 13 | [e-mail.md](e-mail.md) |
| Nuvem | 8 | [nuvem.md](nuvem.md) |
| Firewall (3rd-party) | 6 | [firewall-3rd-party.md](firewall-3rd-party.md) |
| Triagem | 9 | [triagem.md](triagem.md) |
| Visão geral | 9 | [visao-geral.md](visao-geral.md) |

## Todos os hunts

| Técnica (MITRE) | Hunt | Categoria |
|---|---|---|
| `T1059.001` | [PowerShell codificado (-enc)](execucao.md#powershell-codificado--enc) | Execução |
| `T1059.001` | [PowerShell download cradle](execucao.md#powershell-download-cradle) | Execução |
| `T1218` | [LOLBins (binários confiáveis abusados)](execucao.md#lolbins-binários-confiáveis-abusados) | Execução |
| `T1047` | [Abuso de WMI](execucao.md#abuso-de-wmi) | Execução |
| `T1059 / T1566.001` | [Office gerando shell (macro)](execucao.md#office-gerando-shell-macro) | Execução |
| `T1059` | [Script rodando de pasta temporária](execucao.md#script-rodando-de-pasta-temporária) | Execução |
| `T1070.001` | [Limpeza de logs de evento](execucao.md#limpeza-de-logs-de-evento) | Execução |
| `T1218.005` | [mshta executando script remoto](execucao.md#mshta-executando-script-remoto) | Execução |
| `T1218.011` | [rundll32 suspeito](execucao.md#rundll32-suspeito) | Execução |
| `T1218.010` | [regsvr32 scriptlet (Squiblydoo)](execucao.md#regsvr32-scriptlet-squiblydoo) | Execução |
| `T1059.005 / T1059.007` | [WScript/CScript rodando script](execucao.md#wscriptcscript-rodando-script) | Execução |
| `T1197` | [bitsadmin transferindo arquivo](execucao.md#bitsadmin-transferindo-arquivo) | Execução |
| `T1127` | [Proxy de execução via dev tools](execucao.md#proxy-de-execução-via-dev-tools) | Execução |
| `T1059.003` | [cmd encadeado (one-liner)](execucao.md#cmd-encadeado-one-liner) | Execução |
| `T1562.001` | [Desabilitar Defender (realtime)](evasao-de-defesa.md#desabilitar-defender-realtime) | Evasão de defesa |
| `T1562.001` | [Exclusão adicionada no Defender](evasao-de-defesa.md#exclusão-adicionada-no-defender) | Evasão de defesa |
| `T1562.001` | [Parar serviço de segurança](evasao-de-defesa.md#parar-serviço-de-segurança) | Evasão de defesa |
| `T1562.004` | [Desabilitar firewall do Windows](evasao-de-defesa.md#desabilitar-firewall-do-windows) | Evasão de defesa |
| `T1548.002` | [UAC bypass (LOLBins conhecidos)](evasao-de-defesa.md#uac-bypass-lolbins-conhecidos) | Evasão de defesa |
| `T1562.001` | [Bypass de AMSI](evasao-de-defesa.md#bypass-de-amsi) | Evasão de defesa |
| `T1564.001` | [Ocultar arquivos (attrib +h +s)](evasao-de-defesa.md#ocultar-arquivos-attrib-h-s) | Evasão de defesa |
| `T1070.006` | [Timestomp (alterar timestamps)](evasao-de-defesa.md#timestomp-alterar-timestamps) | Evasão de defesa |
| `T1070` | [Apagar histórico do PowerShell](evasao-de-defesa.md#apagar-histórico-do-powershell) | Evasão de defesa |
| `T1562.006` | [Desabilitar logging (ETW/logman)](evasao-de-defesa.md#desabilitar-logging-etwlogman) | Evasão de defesa |
| `T1562.001` | [Reg desabilitando Defender/Tamper](evasao-de-defesa.md#reg-desabilitando-defendertamper) | Evasão de defesa |
| `T1553.005` | [Remoção de Mark-of-the-Web](evasao-de-defesa.md#remoção-de-mark-of-the-web) | Evasão de defesa |
| `T1003.001` | [Acesso ao LSASS (dump de credencial)](credenciais.md#acesso-ao-lsass-dump-de-credencial) | Credenciais |
| `T1003.001` | [Ferramentas de dump conhecidas](credenciais.md#ferramentas-de-dump-conhecidas) | Credenciais |
| `T1003.003` | [Acesso ao NTDS.dit / shadow copy](credenciais.md#acesso-ao-ntdsdit--shadow-copy) | Credenciais |
| `T1110` | [Logons falhos / brute force (gráfico)](credenciais.md#logons-falhos--brute-force-gráfico) | Credenciais |
| `T1003.002` | [Dump do SAM/SYSTEM via reg save](credenciais.md#dump-do-samsystem-via-reg-save) | Credenciais |
| `T1558.003` | [Kerberoasting](credenciais.md#kerberoasting) | Credenciais |
| `T1003.006` | [DCSync](credenciais.md#dcsync) | Credenciais |
| `T1555` | [Acesso a cofres de credencial](credenciais.md#acesso-a-cofres-de-credencial) | Credenciais |
| `T1552.001` | [Busca por senhas em arquivos](credenciais.md#busca-por-senhas-em-arquivos) | Credenciais |
| `T1112 / T1003` | [Habilitar WDigest (creds em claro)](credenciais.md#habilitar-wdigest-creds-em-claro) | Credenciais |
| `T1110` | [Brute force · falhas e bloqueios por host](credenciais.md#brute-force--falhas-e-bloqueios-por-host) | Credenciais |
| `T1547.001` | [Persistência via Registry Run](persistencia.md#persistência-via-registry-run) | Persistência |
| `T1053.005` | [Tarefa agendada / serviço novo](persistencia.md#tarefa-agendada--serviço-novo) | Persistência |
| `T1136 / T1098` | [Criação de conta / grupo admin](persistencia.md#criação-de-conta--grupo-admin) | Persistência |
| `T1546.003` | [Assinatura de evento WMI (persistência)](persistencia.md#assinatura-de-evento-wmi-persistência) | Persistência |
| `T1547.001` | [Drop na pasta Startup](persistencia.md#drop-na-pasta-startup) | Persistência |
| `T1543.003` | [Serviço com binPath suspeito](persistencia.md#serviço-com-binpath-suspeito) | Persistência |
| `T1547.004` | [Winlogon/Userinit alterado](persistencia.md#winlogonuserinit-alterado) | Persistência |
| `T1546.012` | [IFEO Debugger (sequestro de imagem)](persistencia.md#ifeo-debugger-sequestro-de-imagem) | Persistência |
| `T1546.007` | [Netsh helper DLL](persistencia.md#netsh-helper-dll) | Persistência |
| `T1546.008` | [Accessibility features (sethc/utilman)](persistencia.md#accessibility-features-sethcutilman) | Persistência |
| `T1197` | [BITS job com notify (persistência)](persistencia.md#bits-job-com-notify-persistência) | Persistência |
| `T1505.003` | [Servidor web ou SQL gerando shell (webshell)](persistencia.md#servidor-web-ou-sql-gerando-shell-webshell) | Persistência |
| `T1068` | [PrintNightmare (spoolsv gerando processo)](escalonamento-de-privilegio.md#printnightmare-spoolsv-gerando-processo) | Escalonamento de privilégio |
| `T1134.001` | [Exploits 'Potato'](escalonamento-de-privilegio.md#exploits-potato) | Escalonamento de privilégio |
| `T1134` | [Manipulação de token](escalonamento-de-privilegio.md#manipulação-de-token) | Escalonamento de privilégio |
| `T1078` | [runas com credencial alternativa](escalonamento-de-privilegio.md#runas-com-credencial-alternativa) | Escalonamento de privilégio |
| `T1543.003` | [Serviço criado como SYSTEM](escalonamento-de-privilegio.md#serviço-criado-como-system) | Escalonamento de privilégio |
| `T1053.005` | [Tarefa agendada como SYSTEM](escalonamento-de-privilegio.md#tarefa-agendada-como-system) | Escalonamento de privilégio |
| `T1087 / T1016 / T1082` | [Reconhecimento (discovery)](descoberta.md#reconhecimento-discovery) | Descoberta |
| `T1087.002` | [Reconhecimento de Active Directory](descoberta.md#reconhecimento-de-active-directory) | Descoberta |
| `T1135 / T1049` | [Descoberta de compartilhamentos/rede](descoberta.md#descoberta-de-compartilhamentosrede) | Descoberta |
| `T1057 / T1007` | [Enumeração de processos e serviços](descoberta.md#enumeração-de-processos-e-serviços) | Descoberta |
| `T1518.001` | [Enumeração de segurança (AV/firewall)](descoberta.md#enumeração-de-segurança-avfirewall) | Descoberta |
| `T1482` | [Descoberta de trusts de domínio](descoberta.md#descoberta-de-trusts-de-domínio) | Descoberta |
| `T1201` | [Política de senha / contas](descoberta.md#política-de-senha--contas) | Descoberta |
| `T1018` | [Descoberta de sistemas remotos](descoberta.md#descoberta-de-sistemas-remotos) | Descoberta |
| `T1083` | [Descoberta de arquivos e pastas](descoberta.md#descoberta-de-arquivos-e-pastas) | Descoberta |
| — | [Enumeração de tarefas agendadas](descoberta.md#enumeração-de-tarefas-agendadas) | Descoberta |
| `T1021.002 / T1570` | [PsExec / execução remota](movimento-lateral.md#psexec--execução-remota) | Movimento lateral |
| `T1021.006` | [WinRM / execução remota PowerShell](movimento-lateral.md#winrm--execução-remota-powershell) | Movimento lateral |
| `T1021.001` | [RDP interativo / hijack de sessão](movimento-lateral.md#rdp-interativo--hijack-de-sessão) | Movimento lateral |
| `T1021.002` | [Cópia para share administrativo](movimento-lateral.md#cópia-para-share-administrativo) | Movimento lateral |
| `T1047` | [WMIC remoto (/node)](movimento-lateral.md#wmic-remoto-node) | Movimento lateral |
| `T1021.003` | [Execução via DCOM](movimento-lateral.md#execução-via-dcom) | Movimento lateral |
| `T1053.005` | [Tarefa agendada remota](movimento-lateral.md#tarefa-agendada-remota) | Movimento lateral |
| `T1543.003` | [Instalação de serviço (Evento 7045)](movimento-lateral.md#instalação-de-serviço-evento-7045) | Movimento lateral |
| `T1560.001` | [Compactação para exfil (archive)](coleta.md#compactação-para-exfil-archive) | Coleta |
| `T1560.001` | [Archive protegido por senha](coleta.md#archive-protegido-por-senha) | Coleta |
| `T1113` | [Captura de tela](coleta.md#captura-de-tela) | Coleta |
| `T1115` | [Acesso à área de transferência](coleta.md#acesso-à-área-de-transferência) | Coleta |
| `T1074` | [Staging em pasta temporária](coleta.md#staging-em-pasta-temporária) | Coleta |
| `T1071` | [Beaconing · hosts muito falantes](rede-c2.md#beaconing--hosts-muito-falantes) | Rede / C2 |
| `T1090 / T1572` | [Túnel / anonymizer (processos)](rede-c2.md#túnel--anonymizer-processos) | Rede / C2 |
| `T1219` | [Ferramentas de acesso remoto (RMM)](rede-c2.md#ferramentas-de-acesso-remoto-rmm) | Rede / C2 |
| `T1059` | [Reverse shell (one-liner)](rede-c2.md#reverse-shell-one-liner) | Rede / C2 |
| `T1105` | [Download por linha de comando](rede-c2.md#download-por-linha-de-comando) | Rede / C2 |
| `T1071.004` | [DNS suspeito (TXT/tunnel)](rede-c2.md#dns-suspeito-txttunnel) | Rede / C2 |
| `T1071` | [Conexões de saída por host](rede-c2.md#conexões-de-saída-por-host) | Rede / C2 |
| `T1090` | [Proxy / port forwarding](rede-c2.md#proxy--port-forwarding) | Rede / C2 |
| `T1105` | [Start-BitsTransfer (download PS)](rede-c2.md#start-bitstransfer-download-ps) | Rede / C2 |
| `T1071` | [Beaconing · presença constante e baixo volume](rede-c2.md#beaconing--presença-constante-e-baixo-volume) | Rede / C2 |
| `T1567` | [Upload para nuvem (rclone/aws/az)](exfiltracao.md#upload-para-nuvem-rcloneawsaz) | Exfiltração |
| `T1048` | [Transferência via FTP/SFTP/SCP](exfiltracao.md#transferência-via-ftpsftpscp) | Exfiltração |
| `T1041` | [Envio via HTTP POST/PUT com arquivo](exfiltracao.md#envio-via-http-postput-com-arquivo) | Exfiltração |
| `T1567.002` | [Sites de compartilhamento anônimo](exfiltracao.md#sites-de-compartilhamento-anônimo) | Exfiltração |
| `T1048.003` | [Exfil por DNS (subdomínios longos)](exfiltracao.md#exfil-por-dns-subdomínios-longos) | Exfiltração |
| `T1490` | [Deleção de shadow copies](impacto-ransomware.md#deleção-de-shadow-copies) | Impacto / Ransomware |
| `T1490` | [Desabilitar recuperação do Windows](impacto-ransomware.md#desabilitar-recuperação-do-windows) | Impacto / Ransomware |
| `T1070` | [Limpar journal USN](impacto-ransomware.md#limpar-journal-usn) | Impacto / Ransomware |
| `T1485` | [Wipe de dados (cipher /w)](impacto-ransomware.md#wipe-de-dados-cipher-w) | Impacto / Ransomware |
| `T1489` | [Parar serviços críticos (pré-ransom)](impacto-ransomware.md#parar-serviços-críticos-pré-ransom) | Impacto / Ransomware |
| `T1486` | [Indícios de nota de resgate](impacto-ransomware.md#indícios-de-nota-de-resgate) | Impacto / Ransomware |
| `T1491` | [Alteração de papel de parede](impacto-ransomware.md#alteração-de-papel-de-parede) | Impacto / Ransomware |
| `T1078` | [Sign-ins de identidade (Entra ID)](identidade.md#sign-ins-de-identidade-entra-id) | Identidade |
| `T1110 / T1078` | [Falhas de sign-in por conta (Entra ID)](identidade.md#falhas-de-sign-in-por-conta-entra-id) | Identidade |
| `T1110.003` | [Password spray por IP (Entra ID)](identidade.md#password-spray-por-ip-entra-id) | Identidade |
| `T1078` | [Conta com muitos IPs (viagem impossível)](identidade.md#conta-com-muitos-ips-viagem-impossível) | Identidade |
| `T1078` | [Top contas por volume de sign-in](identidade.md#top-contas-por-volume-de-sign-in) | Identidade |
| — | [Sign-ins por hora (gráfico)](identidade.md#sign-ins-por-hora-gráfico) | Identidade |
| — | [Sign-ins por motivo de status](identidade.md#sign-ins-por-motivo-de-status) | Identidade |
| `T1110.003` | [IP servindo muitas contas (make_set)](identidade.md#ip-servindo-muitas-contas-make_set) | Identidade |
| — | [Eventos de identidade por tipo](identidade.md#eventos-de-identidade-por-tipo) | Identidade |
| `T1566` | [Panorama: ameaças por tipo](e-mail.md#panorama-ameaças-por-tipo) | E-mail |
| `T1566` | [Remetentes mais tóxicos](e-mail.md#remetentes-mais-tóxicos) | E-mail |
| `T1566` | [Destinatários mais visados](e-mail.md#destinatários-mais-visados) | E-mail |
| `T1566.001` | [Malware por e-mail (anexo + ameaça)](e-mail.md#malware-por-e-mail-anexo--ameaça) | E-mail |
| — | [Vírus por tipo (majorVirusType)](e-mail.md#vírus-por-tipo-majorvirustype) | E-mail |
| `T1566.002` | [Phishing: link visível vs. link real](e-mail.md#phishing-link-visível-vs-link-real) | E-mail |
| `T1566` | [Reply-To diferente do remetente (BEC)](e-mail.md#reply-to-diferente-do-remetente-bec) | E-mail |
| `T1566` | [Origem/destino malicioso em e-mail](e-mail.md#origemdestino-malicioso-em-e-mail) | E-mail |
| `T1566` | [Ferramenta de envio suspeita (X-Mailer)](e-mail.md#ferramenta-de-envio-suspeita-x-mailer) | E-mail |
| — | [E-mail sem TLS (transporte em claro)](e-mail.md#e-mail-sem-tls-transporte-em-claro) | E-mail |
| — | [Volume de e-mail por hora (gráfico)](e-mail.md#volume-de-e-mail-por-hora-gráfico) | E-mail |
| `T1566` | [Ameaças por direção (entrada/saída)](e-mail.md#ameaças-por-direção-entradasaída) | E-mail |
| — | [Regras de e-mail que mais dispararam](e-mail.md#regras-de-e-mail-que-mais-dispararam) | E-mail |
| `T1078.004` | [CloudTrail: ações sensíveis de IAM](nuvem.md#cloudtrail-ações-sensíveis-de-iam) | Nuvem |
| `T1562.008` | [CloudTrail: logging desabilitado](nuvem.md#cloudtrail-logging-desabilitado) | Nuvem |
| `T1098` | [CloudTrail: mudança em security group](nuvem.md#cloudtrail-mudança-em-security-group) | Nuvem |
| `T1530` | [CloudTrail: S3 exposto](nuvem.md#cloudtrail-s3-exposto) | Nuvem |
| `T1078.004` | [CloudTrail: uso da conta root](nuvem.md#cloudtrail-uso-da-conta-root) | Nuvem |
| — | [CloudTrail: logins de console por hora](nuvem.md#cloudtrail-logins-de-console-por-hora) | Nuvem |
| — | [CloudTrail: chamadas mais frequentes](nuvem.md#cloudtrail-chamadas-mais-frequentes) | Nuvem |
| `T1578` | [CloudTrail: mudança em compute](nuvem.md#cloudtrail-mudança-em-compute) | Nuvem |
| — | [Fortigate · tipos de evento](firewall-3rd-party.md#fortigate--tipos-de-evento) | Firewall (3rd-party) |
| — | [Fortigate · por ação (vendorParsed)](firewall-3rd-party.md#fortigate--por-ação-vendorparsed) | Firewall (3rd-party) |
| — | [Check Point · tipos de evento](firewall-3rd-party.md#check-point--tipos-de-evento) | Firewall (3rd-party) |
| — | [Terceiros · volume por vendor e produto](firewall-3rd-party.md#terceiros--volume-por-vendor-e-produto) | Firewall (3rd-party) |
| — | [Fortigate · top IPs de destino (vendorParsed)](firewall-3rd-party.md#fortigate--top-ips-de-destino-vendorparsed) | Firewall (3rd-party) |
| — | [Terceiros · eventos por coletor](firewall-3rd-party.md#terceiros--eventos-por-coletor) | Firewall (3rd-party) |
| — | [Detecções de alta severidade](triagem.md#detecções-de-alta-severidade) | Triagem |
| — | [Detecções que não foram bloqueadas](triagem.md#detecções-que-não-foram-bloqueadas) | Triagem |
| `pivot` | [Pivot por técnica MITRE (tags)](triagem.md#pivot-por-técnica-mitre-tags) | Triagem |
| — | [Detecções por severidade (gráfico)](triagem.md#detecções-por-severidade-gráfico) | Triagem |
| — | [Regras que mais dispararam](triagem.md#regras-que-mais-dispararam) | Triagem |
| — | [Hosts com mais detecções](triagem.md#hosts-com-mais-detecções) | Triagem |
| — | [Detecções por produto](triagem.md#detecções-por-produto) | Triagem |
| — | [Tipos de evento mais frequentes](triagem.md#tipos-de-evento-mais-frequentes) | Triagem |
| `pivot` | [Detecções por técnica MITRE (ranking)](triagem.md#detecções-por-técnica-mitre-ranking) | Triagem |
| — | [Inventário de fontes de dados](visao-geral.md#inventário-de-fontes-de-dados) | Visão geral |
| — | [Eventos por produto (productCode)](visao-geral.md#eventos-por-produto-productcode) | Visão geral |
| — | [Volume por categoria de evento](visao-geral.md#volume-por-categoria-de-evento) | Visão geral |
| — | [Ingestão de terceiros por hora (gráfico)](visao-geral.md#ingestão-de-terceiros-por-hora-gráfico) | Visão geral |
| — | [Terceiros: volume por vendor](visao-geral.md#terceiros-volume-por-vendor) | Visão geral |
| — | [Fontes de terceiros: último log recebido](visao-geral.md#fontes-de-terceiros-último-log-recebido) | Visão geral |
| — | [Volume total por dia (gráfico)](visao-geral.md#volume-total-por-dia-gráfico) | Visão geral |
| — | [Windows (terceiro): eventos por categoria](visao-geral.md#windows-terceiro-eventos-por-categoria) | Visão geral |
| — | [Coletores ativos (todas as fontes)](visao-geral.md#coletores-ativos-todas-as-fontes) | Visão geral |

> Para adicionar um hunt, veja o [guia de contribuição](../CONTRIBUTING.md).
