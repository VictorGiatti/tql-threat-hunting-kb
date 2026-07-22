# Base de Hunts · índice

**149 hunts** em **17 categorias**. Ative o toggle **"Use Trend Query Language"** antes de rodar.

## Por categoria

| Categoria | Hunts | Arquivo |
|---|--:|---|
| Execução | 14 | [execucao.md](execucao.md) |
| Evasão de defesa | 12 | [evasao-de-defesa.md](evasao-de-defesa.md) |
| Credenciais | 10 | [credenciais.md](credenciais.md) |
| Persistência | 11 | [persistencia.md](persistencia.md) |
| Escalonamento de privilégio | 6 | [escalonamento-de-privilegio.md](escalonamento-de-privilegio.md) |
| Descoberta | 10 | [descoberta.md](descoberta.md) |
| Movimento lateral | 8 | [movimento-lateral.md](movimento-lateral.md) |
| Coleta | 5 | [coleta.md](coleta.md) |
| Rede / C2 | 9 | [rede-c2.md](rede-c2.md) |
| Exfiltração | 5 | [exfiltracao.md](exfiltracao.md) |
| Impacto / Ransomware | 7 | [impacto-ransomware.md](impacto-ransomware.md) |
| Identidade | 9 | [identidade.md](identidade.md) |
| E-mail | 13 | [e-mail.md](e-mail.md) |
| Nuvem | 8 | [nuvem.md](nuvem.md) |
| Firewall (3rd-party) | 6 | [firewall-3rd-party.md](firewall-3rd-party.md) |
| Triagem | 8 | [triagem.md](triagem.md) |
| Visão geral | 8 | [visao-geral.md](visao-geral.md) |

## Todos os hunts

| Técnica (MITRE) | Hunt | Categoria |
|---|---|---|
| `T1059.001` | [PowerShell codificado (-enc)](execucao.md) | Execução |
| `T1059.001` | [PowerShell download cradle](execucao.md) | Execução |
| `T1218` | [LOLBins (binários confiáveis abusados)](execucao.md) | Execução |
| `T1047` | [Abuso de WMI](execucao.md) | Execução |
| `T1059 / T1566.001` | [Office gerando shell (macro)](execucao.md) | Execução |
| `T1059` | [Script rodando de pasta temporária](execucao.md) | Execução |
| `T1070.001` | [Limpeza de logs de evento](execucao.md) | Execução |
| `T1218.005` | [mshta executando script remoto](execucao.md) | Execução |
| `T1218.011` | [rundll32 suspeito](execucao.md) | Execução |
| `T1218.010` | [regsvr32 scriptlet (Squiblydoo)](execucao.md) | Execução |
| `T1059.005 / T1059.007` | [WScript/CScript rodando script](execucao.md) | Execução |
| `T1197` | [bitsadmin transferindo arquivo](execucao.md) | Execução |
| `T1127` | [Proxy de execução via dev tools](execucao.md) | Execução |
| `T1059.003` | [cmd encadeado (one-liner)](execucao.md) | Execução |
| `T1562.001` | [Desabilitar Defender (realtime)](evasao-de-defesa.md) | Evasão de defesa |
| `T1562.001` | [Exclusão adicionada no Defender](evasao-de-defesa.md) | Evasão de defesa |
| `T1562.001` | [Parar serviço de segurança](evasao-de-defesa.md) | Evasão de defesa |
| `T1562.004` | [Desabilitar firewall do Windows](evasao-de-defesa.md) | Evasão de defesa |
| `T1548.002` | [UAC bypass (LOLBins conhecidos)](evasao-de-defesa.md) | Evasão de defesa |
| `T1562.001` | [Bypass de AMSI](evasao-de-defesa.md) | Evasão de defesa |
| `T1564.001` | [Ocultar arquivos (attrib +h +s)](evasao-de-defesa.md) | Evasão de defesa |
| `T1070.006` | [Timestomp (alterar timestamps)](evasao-de-defesa.md) | Evasão de defesa |
| `T1070` | [Apagar histórico do PowerShell](evasao-de-defesa.md) | Evasão de defesa |
| `T1562.006` | [Desabilitar logging (ETW/logman)](evasao-de-defesa.md) | Evasão de defesa |
| `T1562.001` | [Reg desabilitando Defender/Tamper](evasao-de-defesa.md) | Evasão de defesa |
| `T1553.005` | [Remoção de Mark-of-the-Web](evasao-de-defesa.md) | Evasão de defesa |
| `T1003.001` | [Acesso ao LSASS (dump de credencial)](credenciais.md) | Credenciais |
| `T1003.001` | [Ferramentas de dump conhecidas](credenciais.md) | Credenciais |
| `T1003.003` | [Acesso ao NTDS.dit / shadow copy](credenciais.md) | Credenciais |
| `T1110` | [Logons falhos / brute force (gráfico)](credenciais.md) | Credenciais |
| `T1003.002` | [Dump do SAM/SYSTEM via reg save](credenciais.md) | Credenciais |
| `T1558.003` | [Kerberoasting](credenciais.md) | Credenciais |
| `T1003.006` | [DCSync](credenciais.md) | Credenciais |
| `T1555` | [Acesso a cofres de credencial](credenciais.md) | Credenciais |
| `T1552.001` | [Busca por senhas em arquivos](credenciais.md) | Credenciais |
| `T1112 / T1003` | [Habilitar WDigest (creds em claro)](credenciais.md) | Credenciais |
| `T1547.001` | [Persistência via Registry Run](persistencia.md) | Persistência |
| `T1053.005` | [Tarefa agendada / serviço novo](persistencia.md) | Persistência |
| `T1136 / T1098` | [Criação de conta / grupo admin](persistencia.md) | Persistência |
| `T1546.003` | [Assinatura de evento WMI (persistência)](persistencia.md) | Persistência |
| `T1547.001` | [Drop na pasta Startup](persistencia.md) | Persistência |
| `T1543.003` | [Serviço com binPath suspeito](persistencia.md) | Persistência |
| `T1547.004` | [Winlogon/Userinit alterado](persistencia.md) | Persistência |
| `T1546.012` | [IFEO Debugger (sequestro de imagem)](persistencia.md) | Persistência |
| `T1546.007` | [Netsh helper DLL](persistencia.md) | Persistência |
| `T1546.008` | [Accessibility features (sethc/utilman)](persistencia.md) | Persistência |
| `T1197` | [BITS job com notify (persistência)](persistencia.md) | Persistência |
| `T1068` | [PrintNightmare (spoolsv gerando processo)](escalonamento-de-privilegio.md) | Escalonamento de privilégio |
| `T1134.001` | [Exploits 'Potato'](escalonamento-de-privilegio.md) | Escalonamento de privilégio |
| `T1134` | [Manipulação de token](escalonamento-de-privilegio.md) | Escalonamento de privilégio |
| `T1078` | [runas com credencial alternativa](escalonamento-de-privilegio.md) | Escalonamento de privilégio |
| `T1543.003` | [Serviço criado como SYSTEM](escalonamento-de-privilegio.md) | Escalonamento de privilégio |
| `T1053.005` | [Tarefa agendada como SYSTEM](escalonamento-de-privilegio.md) | Escalonamento de privilégio |
| `T1087 / T1016 / T1082` | [Reconhecimento (discovery)](descoberta.md) | Descoberta |
| `T1087.002` | [Reconhecimento de Active Directory](descoberta.md) | Descoberta |
| `T1135 / T1049` | [Descoberta de compartilhamentos/rede](descoberta.md) | Descoberta |
| `T1057 / T1007` | [Enumeração de processos e serviços](descoberta.md) | Descoberta |
| `T1518.001` | [Enumeração de segurança (AV/firewall)](descoberta.md) | Descoberta |
| `T1482` | [Descoberta de trusts de domínio](descoberta.md) | Descoberta |
| `T1201` | [Política de senha / contas](descoberta.md) | Descoberta |
| `T1018` | [Descoberta de sistemas remotos](descoberta.md) | Descoberta |
| `T1083` | [Descoberta de arquivos e pastas](descoberta.md) | Descoberta |
| — | [Enumeração de tarefas agendadas](descoberta.md) | Descoberta |
| `T1021.002 / T1570` | [PsExec / execução remota](movimento-lateral.md) | Movimento lateral |
| `T1021.006` | [WinRM / execução remota PowerShell](movimento-lateral.md) | Movimento lateral |
| `T1021.001` | [RDP interativo / hijack de sessão](movimento-lateral.md) | Movimento lateral |
| `T1021.002` | [Cópia para share administrativo](movimento-lateral.md) | Movimento lateral |
| `T1047` | [WMIC remoto (/node)](movimento-lateral.md) | Movimento lateral |
| `T1021.003` | [Execução via DCOM](movimento-lateral.md) | Movimento lateral |
| `T1053.005` | [Tarefa agendada remota](movimento-lateral.md) | Movimento lateral |
| `T1543.003` | [Instalação de serviço (Evento 7045)](movimento-lateral.md) | Movimento lateral |
| `T1560.001` | [Compactação para exfil (archive)](coleta.md) | Coleta |
| `T1560.001` | [Archive protegido por senha](coleta.md) | Coleta |
| `T1113` | [Captura de tela](coleta.md) | Coleta |
| `T1115` | [Acesso à área de transferência](coleta.md) | Coleta |
| `T1074` | [Staging em pasta temporária](coleta.md) | Coleta |
| `T1071` | [Beaconing, hosts muito falantes](rede-c2.md) | Rede / C2 |
| `T1090 / T1572` | [Túnel / anonymizer (processos)](rede-c2.md) | Rede / C2 |
| `T1219` | [Ferramentas de acesso remoto (RMM)](rede-c2.md) | Rede / C2 |
| `T1059` | [Reverse shell (one-liner)](rede-c2.md) | Rede / C2 |
| `T1105` | [Download por linha de comando](rede-c2.md) | Rede / C2 |
| `T1071.004` | [DNS suspeito (TXT/tunnel)](rede-c2.md) | Rede / C2 |
| `T1071` | [Conexões de saída por host](rede-c2.md) | Rede / C2 |
| `T1090` | [Proxy / port forwarding](rede-c2.md) | Rede / C2 |
| `T1105` | [Start-BitsTransfer (download PS)](rede-c2.md) | Rede / C2 |
| `T1567` | [Upload para nuvem (rclone/aws/az)](exfiltracao.md) | Exfiltração |
| `T1048` | [Transferência via FTP/SFTP/SCP](exfiltracao.md) | Exfiltração |
| `T1041` | [Envio via HTTP POST/PUT com arquivo](exfiltracao.md) | Exfiltração |
| `T1567.002` | [Sites de compartilhamento anônimo](exfiltracao.md) | Exfiltração |
| `T1048.003` | [Exfil por DNS (subdomínios longos)](exfiltracao.md) | Exfiltração |
| `T1490` | [Deleção de shadow copies](impacto-ransomware.md) | Impacto / Ransomware |
| `T1490` | [Desabilitar recuperação do Windows](impacto-ransomware.md) | Impacto / Ransomware |
| `T1070` | [Limpar journal USN](impacto-ransomware.md) | Impacto / Ransomware |
| `T1485` | [Wipe de dados (cipher /w)](impacto-ransomware.md) | Impacto / Ransomware |
| `T1489` | [Parar serviços críticos (pré-ransom)](impacto-ransomware.md) | Impacto / Ransomware |
| `T1486` | [Indícios de nota de resgate](impacto-ransomware.md) | Impacto / Ransomware |
| `T1491` | [Alteração de papel de parede](impacto-ransomware.md) | Impacto / Ransomware |
| `T1078` | [Sign-ins de identidade (Entra ID)](identidade.md) | Identidade |
| `T1110 / T1078` | [Falhas de sign-in por conta (Entra ID)](identidade.md) | Identidade |
| `T1110.003` | [Password spray por IP (Entra ID)](identidade.md) | Identidade |
| `T1078` | [Conta com muitos IPs (viagem impossível)](identidade.md) | Identidade |
| `T1078` | [Top contas por volume de sign-in](identidade.md) | Identidade |
| — | [Sign-ins por hora (gráfico)](identidade.md) | Identidade |
| — | [Sign-ins por motivo de status](identidade.md) | Identidade |
| `T1110.003` | [IP servindo muitas contas (make_set)](identidade.md) | Identidade |
| — | [Eventos de identidade por tipo](identidade.md) | Identidade |
| `T1566` | [Panorama: ameaças por tipo](e-mail.md) | E-mail |
| `T1566` | [Remetentes mais tóxicos](e-mail.md) | E-mail |
| `T1566` | [Destinatários mais visados](e-mail.md) | E-mail |
| `T1566.001` | [Malware por e-mail (anexo + ameaça)](e-mail.md) | E-mail |
| — | [Vírus por tipo (majorVirusType)](e-mail.md) | E-mail |
| `T1566.002` | [Phishing: link visível vs. link real](e-mail.md) | E-mail |
| `T1566` | [Reply-To diferente do remetente (BEC)](e-mail.md) | E-mail |
| `T1566` | [Origem/destino malicioso em e-mail](e-mail.md) | E-mail |
| `T1566` | [Ferramenta de envio suspeita (X-Mailer)](e-mail.md) | E-mail |
| — | [E-mail sem TLS (transporte em claro)](e-mail.md) | E-mail |
| — | [Volume de e-mail por hora (gráfico)](e-mail.md) | E-mail |
| `T1566` | [Ameaças por direção (entrada/saída)](e-mail.md) | E-mail |
| — | [Regras de e-mail que mais dispararam](e-mail.md) | E-mail |
| `T1078.004` | [CloudTrail: ações sensíveis de IAM](nuvem.md) | Nuvem |
| `T1562.008` | [CloudTrail: logging desabilitado](nuvem.md) | Nuvem |
| `T1098` | [CloudTrail: mudança em security group](nuvem.md) | Nuvem |
| `T1530` | [CloudTrail: S3 exposto](nuvem.md) | Nuvem |
| `T1078.004` | [CloudTrail: uso da conta root](nuvem.md) | Nuvem |
| — | [CloudTrail: logins de console por hora](nuvem.md) | Nuvem |
| — | [CloudTrail: chamadas mais frequentes](nuvem.md) | Nuvem |
| `T1578` | [CloudTrail: mudança em compute](nuvem.md) | Nuvem |
| — | [Fortigate, tipos de evento](firewall-3rd-party.md) | Firewall (3rd-party) |
| — | [Fortigate, por ação (vendorParsed)](firewall-3rd-party.md) | Firewall (3rd-party) |
| — | [Check Point, tipos de evento](firewall-3rd-party.md) | Firewall (3rd-party) |
| — | [Terceiros, volume por vendor e produto](firewall-3rd-party.md) | Firewall (3rd-party) |
| — | [Fortigate, top IPs de destino (vendorParsed)](firewall-3rd-party.md) | Firewall (3rd-party) |
| — | [Terceiros, eventos por coletor](firewall-3rd-party.md) | Firewall (3rd-party) |
| — | [Detecções de alta severidade](triagem.md) | Triagem |
| — | [Detecções que não foram bloqueadas](triagem.md) | Triagem |
| `pivot` | [Pivot por técnica MITRE (tags)](triagem.md) | Triagem |
| — | [Detecções por severidade (gráfico)](triagem.md) | Triagem |
| — | [Regras que mais dispararam](triagem.md) | Triagem |
| — | [Hosts com mais detecções](triagem.md) | Triagem |
| — | [Detecções por produto](triagem.md) | Triagem |
| — | [Tipos de evento mais frequentes](triagem.md) | Triagem |
| — | [Inventário de fontes de dados](visao-geral.md) | Visão geral |
| — | [Eventos por produto (productCode)](visao-geral.md) | Visão geral |
| — | [Volume por categoria de evento](visao-geral.md) | Visão geral |
| — | [Ingestão de terceiros por hora (gráfico)](visao-geral.md) | Visão geral |
| — | [Terceiros: volume por vendor](visao-geral.md) | Visão geral |
| — | [Fontes de terceiros: último log recebido](visao-geral.md) | Visão geral |
| — | [Volume total por dia (gráfico)](visao-geral.md) | Visão geral |
| — | [Windows (terceiro): eventos por categoria](visao-geral.md) | Visão geral |

> Para adicionar um hunt, veja o [guia de contribuição](../CONTRIBUTING.md).
