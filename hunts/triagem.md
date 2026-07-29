# Triagem · Threat Hunting TQL

[← Índice de hunts](README.md) · [Início da base](../README.md)

> Ative o toggle **"Use Trend Query Language"** no XDR Data Explorer antes de rodar. Zero resultado também é resposta (não achou o padrão).

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
| where tags has_any ("MITRE.T1055")
| project eventTime, endpointHostName, eventName, ruleName, tags
| sort by eventTime desc
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

