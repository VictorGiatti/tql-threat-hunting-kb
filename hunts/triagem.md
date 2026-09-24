# Triagem · Threat Hunting TQL

[← Índice de hunts](README.md) · [Início da base](../README.md)

> Ative o toggle **"Use Trend Query Language"** no XDR Data Explorer antes de rodar. Zero resultado só vale como "nada encontrado" depois de confirmar que a fonte está reportando: veja o [checklist](../sintaxe-e-performance.md#voltou-vazio-confirme-antes-de-concluir).

## Detecções de alta severidade

O que triar primeiro: severidade >= 8 nas últimas 24h.

```text
datasource("xdr") with (log_type="detection")
| where eventTime > ago(1d)
| where severity >= 8
| project eventTime, pname, endpointHostName, eventName, ruleName, severity
| top 100 by severity desc
```

---

## Detecções que não foram bloqueadas

Ameaça média/alta cujo actionStatus não é 'blocked': pode ter passado.

```text
datasource("xdr") with (log_type="detection")
| where eventTime > ago(1d)
| where severity >= 6
| where not(actionStatus == "blocked")
| project eventTime, pname, endpointHostName, ruleName, severity, actionStatus
| sort by severity desc
| take 100
```

---

## Pivot por técnica MITRE (tags)

**MITRE ATT&CK:** `pivot`

Filtra detecções por técnica MITRE. Troque o T-code.

```text
datasource("xdr") with (log_type="detection")
| where eventTime > ago(7d)
| where tags has "MITRE.T1055"
| project eventTime, endpointHostName, eventName, ruleName, tags
| sort by eventTime desc
| take 100
```

---

## Detecções por severidade (gráfico)

Distribuição das detecções por nível de severidade nos últimos 7 dias.

```text
datasource("xdr") with (log_type="detection")
| where eventTime > ago(7d)
| summarize total = count() by severity
| sort by severity asc
| render columnchart with (xtitle="Severidade", ytitle="Detecções")
```

---

## Regras que mais dispararam

Candidatas a tuning ou a foco, por ruleName.

```text
datasource("xdr") with (log_type="detection")
| where eventTime > ago(7d)
| summarize disparos = count() by ruleName
| top 20 by disparos desc
```

---

## Hosts com mais detecções

Onde concentrar a investigação, por endpoint.

```text
datasource("xdr") with (log_type="detection")
| where eventTime > ago(7d)
| summarize alertas = count() by endpointHostName
| top 20 by alertas desc
```

---

## Detecções por produto

De onde vêm os alertas, por pname.

```text
datasource("xdr") with (log_type="detection")
| where eventTime > ago(7d)
| summarize deteccoes = count() by pname
| top 20 by deteccoes desc
```

---

## Tipos de evento mais frequentes

Ranking de eventName pra entender o ruído dominante.

```text
datasource("xdr") with (log_type="detection")
| where eventTime > ago(7d)
| summarize total = count() by eventName
| top 25 by total desc
```

---

## Detecções por técnica MITRE (ranking)

**MITRE ATT&CK:** `pivot`

Abre o array `tags` e conta detecções e hosts por técnica MITRE: mostra quais técnicas mais aparecem no ambiente.

```text
datasource("xdr") with (log_type="detection")
| where eventTime > ago(7d)
| mv-expand tag = tags
| extend tecnica = tostring(tag)
| where tecnica startswith "MITRE."
| summarize deteccoes = count(), hosts = dcount(endpointHostName) by tecnica
| top 30 by deteccoes desc
```
