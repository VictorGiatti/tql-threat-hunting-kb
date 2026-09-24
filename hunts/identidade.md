# Identidade · Threat Hunting TQL

[← Índice de hunts](README.md) · [Início da base](../README.md)

> Ative o toggle **"Use Trend Query Language"** no XDR Data Explorer antes de rodar. Zero resultado só vale como "nada encontrado" depois de confirmar que a fonte está reportando: veja o [checklist](../sintaxe-e-performance.md#voltou-vazio-confirme-antes-de-concluir).

## Sign-ins de identidade (Entra ID)

**MITRE ATT&CK:** `T1078`

Logins de identidade, cruze IP e motivo do status.

```text
datasource("xdr") with (log_type="identitytel", product_code="aad")
| where eventTime > ago(1d)
| where eventName == "IDENTITY_IAM_SIGN_INS"
| project eventTime, principalName, ipAddress, statusReason
| sort by eventTime desc
| take 100
```

---

## Falhas de sign-in por conta (Entra ID)

**MITRE ATT&CK:** `T1110 / T1078`

Agrupa sign-ins por conta e motivo do status, acha conta sob ataque.

```text
datasource("xdr") with (log_type="identitytel", product_code="aad")
| where eventTime > ago(1d)
| where eventName == "IDENTITY_IAM_SIGN_INS"
| where isnotempty(statusReason)
| summarize tentativas = count() by principalName, statusReason
| top 50 by tentativas desc
```

---

## Password spray por IP (Entra ID)

**MITRE ATT&CK:** `T1110.003`

Um IP tentando muitas contas distintas = sinal de spray.

> **Limitação:** conta todos os sign-ins do IP, não só as falhas. IP de saída corporativo (NAT/proxy) tende a dominar o topo: confira o `statusReason` antes de concluir.

```text
datasource("xdr") with (log_type="identitytel", product_code="aad")
| where eventTime > ago(1d)
| where eventName == "IDENTITY_IAM_SIGN_INS"
| summarize sign_ins = count(), contas = dcount(principalName) by ipAddress
| top 50 by contas desc
```

---

## Conta com muitos IPs (viagem impossível)

**MITRE ATT&CK:** `T1078`

Mesma conta autenticando de vários IPs distintos na janela.

> **Limitação:** o TQL não tem geolocalização, então isto é contagem de IPs, não distância. VPN, proxy e rede móvel geram falso positivo.

```text
datasource("xdr") with (log_type="identitytel", product_code="aad")
| where eventTime > ago(1d)
| where eventName == "IDENTITY_IAM_SIGN_INS"
| summarize ips = dcount(ipAddress), sign_ins = count() by principalName
| where ips >= 5
| top 50 by ips desc
```

---

## Top contas por volume de sign-in

**MITRE ATT&CK:** `T1078`

Quem mais autentica na janela, baseline e anomalias.

```text
datasource("xdr") with (log_type="identitytel", product_code="aad")
| where eventTime > ago(1d)
| where eventName == "IDENTITY_IAM_SIGN_INS"
| summarize sign_ins = count() by principalName
| top 50 by sign_ins desc
```

---

## Sign-ins por hora (gráfico)

Linha do tempo dos sign-ins, pra flagrar picos fora do horário.

```text
datasource("xdr") with (log_type="identitytel", product_code="aad")
| where eventTime > ago(1d)
| where eventName == "IDENTITY_IAM_SIGN_INS"
| summarize total = count() by hora = bin(eventTime, 1h)
| sort by hora asc
| render linechart with (xtitle="Hora", ytitle="Sign-ins")
```

---

## Sign-ins por motivo de status

Distribuição dos motivos de status (sucesso/falha/bloqueio).

```text
datasource("xdr") with (log_type="identitytel", product_code="aad")
| where eventTime > ago(1d)
| where eventName == "IDENTITY_IAM_SIGN_INS"
| summarize total = count() by statusReason
| top 20 by total desc
```

---

## IP servindo muitas contas (make_set)

**MITRE ATT&CK:** `T1110.003`

Lista as contas vistas por IP, útil pra confirmar spray/reuso.

```text
datasource("xdr") with (log_type="identitytel", product_code="aad")
| where eventTime > ago(1d)
| where eventName == "IDENTITY_IAM_SIGN_INS"
| summarize contas = make_set(principalName), total = count() by ipAddress
| top 50 by total desc
```

---

## Eventos de identidade por tipo

Panorama de eventName de identidade além do sign-in.

```text
datasource("xdr") with (log_type="identitytel")
| where eventTime > ago(1d)
| summarize total = count() by eventName
| top 30 by total desc
```

