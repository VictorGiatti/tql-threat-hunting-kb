# E-mail · Threat Hunting TQL

[← Índice de hunts](README.md) · [Início da base](../README.md)

> Ative o toggle **"Use Trend Query Language"** no XDR Data Explorer antes de rodar. Zero resultado só vale como "nada encontrado" depois de confirmar que a fonte está reportando: veja o [checklist](../sintaxe-e-performance.md#voltou-vazio-confirme-antes-de-concluir).

## Panorama: ameaças por tipo

**MITRE ATT&CK:** `T1566`

Distribui as mensagens com ameaça pelos tipos detectados (mv-expand).

```text
datasource("xdr") with (log_type="messaging")
| where eventTime > ago(7d)
| where array_length(mailThreatTypes) > 0
| mv-expand ameaca = mailThreatTypes
| summarize total = count() by tipo = tostring(ameaca)
| top 20 by total desc
```

---

## Remetentes mais tóxicos

**MITRE ATT&CK:** `T1566`

Endereços de origem com maior volume de mensagens com ameaça.

```text
datasource("xdr") with (log_type="messaging")
| where eventTime > ago(7d)
| where array_length(mailThreatTypes) > 0
| summarize ameacas = count() by remetente = tostring(mailSmtpFromAddresses)
| top 50 by ameacas desc
```

---

## Destinatários mais visados

**MITRE ATT&CK:** `T1566`

Quem mais recebe ameaça, candidatos a alvo dirigido.

```text
datasource("xdr") with (log_type="messaging")
| where eventTime > ago(7d)
| where array_length(mailThreatTypes) > 0
| mv-expand dest = mailSmtpRecipients
| summarize ameacas = count() by destinatario = tostring(dest)
| top 30 by ameacas desc
```

---

## Malware por e-mail (anexo + ameaça)

**MITRE ATT&CK:** `T1566.001`

Mensagens com anexo (hash) e tipo de ameaça sinalizado.

```text
datasource("xdr") with (log_type="messaging")
| where eventTime > ago(7d)
| where isnotempty(mailAttachmentHash)
| where array_length(mailThreatTypes) > 0
| project eventTime, mailSmtpFromAddresses, mailSmtpRecipients, mailThreatTypes, mailAttachmentHash, majorVirusType
| sort by eventTime desc
| take 100
```

---

## Vírus por tipo (majorVirusType)

Distribuição dos tipos de vírus detectados no fluxo de e-mail.

```text
datasource("xdr") with (log_type="messaging")
| where eventTime > ago(7d)
| where isnotempty(majorVirusType)
| summarize total = count() by majorVirusType
| top 20 by total desc
```

---

## Phishing: link visível vs. link real

**MITRE ATT&CK:** `T1566.002`

Compara o link exibido com o link real, divergência = phishing clássico.

```text
datasource("xdr") with (log_type="messaging")
| where eventTime > ago(7d)
| where array_length(mailUrlsRealLink) > 0
| project eventTime, mailSmtpFromAddresses, mailSmtpRecipients, mailUrlsVisibleLink, mailUrlsRealLink, mailThreatTypes
| sort by eventTime desc
| take 100
```

---

## Reply-To diferente do remetente (BEC)

**MITRE ATT&CK:** `T1566`

Reply-To presente pra revisar divergência com o From, sinal de BEC/spoofing.

```text
datasource("xdr") with (log_type="messaging")
| where eventTime > ago(7d)
| where array_length(mailReplyToAddresses) > 0
| project eventTime, mailSmtpFromAddresses, mailReplyToAddresses, mailSmtpRecipients, mailThreatTypes
| sort by eventTime desc
| take 100
```

---

## Origem/destino malicioso em e-mail

**MITRE ATT&CK:** `T1566`

E-mails com IP/host de origem ou destino marcado como malicioso.

```text
datasource("xdr") with (log_type="messaging")
| where eventTime > ago(7d)
| where isnotempty(malSrc) or isnotempty(malDst)
| project eventTime, mailSmtpFromAddresses, mailSmtpRecipients, malSrc, malDst, malTypeGroup, majorVirusType
| sort by eventTime desc
| take 100
```

---

## Ferramenta de envio suspeita (X-Mailer)

**MITRE ATT&CK:** `T1566`

Agrupa por X-Mailer, mass mailers e ferramentas de phishing se destacam.

```text
datasource("xdr") with (log_type="messaging")
| where eventTime > ago(7d)
| where isnotempty(mailXMailer)
| summarize total = count() by mailXMailer
| top 40 by total desc
```

---

## E-mail sem TLS (transporte em claro)

Mensagens sem TLS no transporte, exposição de conteúdo.

```text
datasource("xdr") with (log_type="messaging")
| where eventTime > ago(1d)
| where isempty(mailSmtpTls)
| project eventTime, mailSmtpFromAddresses, mailSmtpRecipients, mailRecipientIp, mailSmtpHelo
| take 100
```

---

## Volume de e-mail por hora (gráfico)

Baseline do fluxo de e-mail, picos podem indicar surto/campanha.

```text
datasource("xdr") with (log_type="messaging")
| where eventTime > ago(1d)
| summarize total = count() by hora = bin(eventTime, 1h)
| sort by hora asc
| render columnchart with (xtitle="Hora", ytitle="E-mails")
```

---

## Ameaças por direção (entrada/saída)

**MITRE ATT&CK:** `T1566`

Ameaça por mailMsgDirection, saída com ameaça pode ser conta comprometida.

```text
datasource("xdr") with (log_type="messaging")
| where eventTime > ago(7d)
| where array_length(mailThreatTypes) > 0
| summarize total = count() by mailMsgDirection
```

---

## Regras de e-mail que mais dispararam

Agrupa por mailRuleId, vê quais políticas estão pegando o quê.

```text
datasource("xdr") with (log_type="messaging")
| where eventTime > ago(7d)
| where array_length(mailRuleId) > 0
| mv-expand regra = mailRuleId
| summarize total = count() by regra = tostring(regra)
| top 30 by total desc
```

