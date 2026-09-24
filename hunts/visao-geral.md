# Visão geral · Threat Hunting TQL

[← Índice de hunts](README.md) · [Início da base](../README.md)

> Ative o toggle **"Use Trend Query Language"** no XDR Data Explorer antes de rodar. Zero resultado só vale como "nada encontrado" depois de confirmar que a fonte está reportando: veja o [checklist](../sintaxe-e-performance.md#voltou-vazio-confirme-antes-de-concluir).

## Inventário de fontes de dados

Todas as fontes que estão enviando log, por volume.

```text
datasource("xdr")
| where eventTime > ago(7d)
| summarize eventos = count() by pname
| sort by eventos desc
```

---

## Eventos por produto (productCode)

Volume por produto conectado nas últimas 24h.

```text
datasource("xdr")
| where eventTime > ago(1d)
| summarize eventos = count() by productCode
| top 30 by eventos desc
```

---

## Volume por categoria de evento

Distribuição por eventCategory, o que mais chega.

```text
datasource("xdr")
| where eventTime > ago(1d)
| summarize eventos = count() by eventCategory
| top 30 by eventos desc
```

---

## Ingestão de terceiros por hora (gráfico)

Linha do tempo da ingestão por fornecedor, mostra a agregação viva.

```text
datasource("xdr") with (log_type="thirdparty")
| where eventTime > ago(1d)
| summarize eventos = count() by hora = bin(eventTime, 1h), vendor
| sort by hora asc
| render linechart with (xtitle="Hora", ytitle="Eventos")
```

---

## Terceiros: volume por vendor

Quais fornecedores dominam o volume de terceiros.

```text
datasource("xdr") with (log_type="thirdparty")
| where eventTime > ago(1d)
| summarize eventos = count() by vendor
| top 30 by eventos desc
```

---

## Fontes de terceiros: último log recebido

Qualidade de dados: quem parou de enviar? Ordena pela fonte mais 'silenciosa'.

```text
datasource("xdr") with (log_type="thirdparty")
| where eventTime > ago(30d)
| summarize ultimo_log = max(eventTime), eventos = count() by pname
| sort by ultimo_log asc
```

---

## Volume total por dia (gráfico)

Tendência de ingestão diária, quedas podem indicar fonte parada.

```text
datasource("xdr")
| where eventTime > ago(7d)
| summarize eventos = count() by dia = bin(eventTime, 1d)
| sort by dia asc
| render columnchart with (xtitle="Dia", ytitle="Eventos")
```

---

## Windows (terceiro): eventos por categoria

Explora o que uma fonte Windows de terceiro envia, agrupando pela categoria parseada (vendorParsed + tostring + extend).

```text
datasource("xdr") with (log_type="thirdparty")
| where eventTime > ago(1d)
| where collectorName == "Windows_OS"
| extend VendorCategory = tostring(vendorParsed.Category)
| summarize Total = count() by VendorCategory
| top 10 by Total desc
```

---

## Coletores ativos (todas as fontes)

Volume por `collectorName` em todas as fontes: o jeito mais rápido de ver quais coletores estão vivos.

```text
datasource("xdr")
| where eventTime > ago(1d)
| summarize eventos = count() by collectorName
| top 30 by eventos desc
```
