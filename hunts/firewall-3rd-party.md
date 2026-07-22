# Firewall (3rd-party) — Threat Hunting TQL

[← Índice de hunts](README.md) · [Início da base](../README.md)

> Ative o toggle **"Use Trend Query Language"** no XDR Data Explorer antes de rodar. Zero resultado também é resposta (não achou o padrão).

## Fortigate — tipos de evento

Atividade do Fortigate agregada (o seu maior volume de terceiro).

```text
datasource("xdr") with (log_type="thirdparty")
| where eventTime > ago(1d)
| where pname == "Fortigate"
| summarize eventos = count() by eventName
| top 20 by eventos desc
```

---

## Fortigate — por ação (vendorParsed)

Usa o campo parseado do fornecedor pra ver allow/deny. Ensina vendorParsed + tostring + extend.

```text
datasource("xdr") with (log_type="thirdparty")
| where eventTime > ago(1d)
| where pname == "Fortigate"
| extend acao = tostring(vendorParsed.action)
| summarize eventos = count() by acao
| top 20 by eventos desc
```

---

## Check Point — tipos de evento

Atividade do Check Point (VPN-1 & FireWall-1).

```text
datasource("xdr") with (log_type="thirdparty")
| where eventTime > ago(1d)
| where pname == "VPN-1 & FireWall-1"
| summarize eventos = count() by eventName
| top 20 by eventos desc
```

---

## Terceiros — volume por vendor e produto

Panorama de todos os terceiros que estão mandando log.

```text
datasource("xdr") with (log_type="thirdparty")
| where eventTime > ago(1d)
| summarize eventos = count() by vendor, pname
| top 30 by eventos desc
```

---

## Fortigate — top IPs de destino (vendorParsed)

Extrai o IP de destino parseado pra ver pra onde o tráfego vai.

```text
datasource("xdr") with (log_type="thirdparty")
| where eventTime > ago(1d)
| where pname == "Fortigate"
| extend destino = tostring(vendorParsed.dstip)
| summarize eventos = count() by destino
| top 20 by eventos desc
```

---

## Terceiros — eventos por coletor

Volume por collectorName — vê quais coletores estão ativos.

```text
datasource("xdr") with (log_type="thirdparty")
| where eventTime > ago(1d)
| summarize eventos = count() by collectorName
| top 30 by eventos desc
```

