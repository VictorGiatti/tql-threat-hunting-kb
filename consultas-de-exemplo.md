# TQL — Consultas de exemplo (cola de bolso)

**Onde rodar:** Trend Vision One → XDR Data Explorer → ligue o toggle **"Use Trend Query Language"** → cole a query → **Run query**.

> **Regras de ouro:**
> 1. **Cole a query inteira, sem alterar as aspas** — elas são retas (`"`), não curvas. Copie sempre de dentro dos blocos de código.
> 2. **Nenhuma query aqui tem comentário** — é só copiar e rodar. (Comentário no meio da query pode confundir o editor.)
> 3. **Nomes de campo variam por fonte/schema.** Se um campo der erro, apague e deixe o **autocomplete** sugerir o certo daquela fonte.
> 4. Nas queries do bloco 5, **troque** o host / usuário / ID pelo do seu ambiente (indico na linha acima de cada uma).
>
> **Dica de demo:** comece pelo bloco 1 ou 2 (quase sempre retornam dados). No hunting (bloco 4), **zero resultado também é resposta** — quer dizer que não achou o padrão.

---

## 0) A primeira query (para testar que está tudo ok)

As peças da linguagem: `datasource(...)` escolhe a fonte · `where` filtra · `summarize count() by` agrega · `project` escolhe colunas · `sort by` ordena · `take` limita · tempo com `ago(1d)`, `ago(24h)`, `ago(7d)`.

Uma query leve só pra confirmar que o backend responde:
```
datasource("xdr") with (log_type="detection")
| where eventTime > ago(1h)
| take 10
```

> Importante: **não misture `summarize` com `project` de colunas que o summarize já removeu.** Depois de `summarize total = count() by ruleName`, só existem `ruleName` e `total` — então não dá pra dar `project eventTime`. Ou você agrega (bloco A), ou você lista as linhas cruas (bloco B):

**A) Contagem por regra**
```
datasource("xdr") with (log_type="detection", product_code="sao")
| where eventTime > ago(1d)
| where severity >= 8
| summarize total = count() by ruleName
| sort by total desc
| take 100
```

**B) Linhas dos eventos, com colunas**
```
datasource("xdr") with (log_type="detection", product_code="sao")
| where eventTime > ago(1d)
| where severity >= 8
| project eventTime, endpointHostName, ruleName, severity
| sort by eventTime desc
| take 100
```

---

## 1) Aquecimento (comece por aqui — quase sempre retorna dados)

**1.1 — Quantas detecções nos últimos 7 dias**
```
datasource("xdr") with (log_type="detection")
| where eventTime > ago(7d)
| summarize total = count()
```

**1.2 — As 20 detecções mais recentes (colunas úteis)**
```
datasource("xdr") with (log_type="detection")
| where eventTime > ago(1d)
| project eventTime, pname, endpointHostName, eventName, ruleName
| sort by eventTime desc
| take 20
```

**1.3 — Visão geral do que chega, por categoria**
```
datasource("xdr")
| where eventTime > ago(1d)
| summarize total = count() by eventCategory
| sort by total desc
```

---

## 2) Agregação de logs de terceiros (o seu diferencial: o SIEM como agregador)

**2.1 — Distribuição de eventos do Microsoft Defender por categoria** (a query do seu print)
```
datasource("xdr") with (log_type="thirdparty")
| where pname == "Microsoft Defender for Endpoint"
| summarize total = count() by eventCategory
| sort by total desc
```

**2.2 — Quais produtos de terceiros estão mandando log (volume por produto)**
```
datasource("xdr") with (log_type="thirdparty")
| where eventTime > ago(1d)
| summarize eventos = count() by pname
| sort by eventos desc
```

**2.3 — Amostra crua de um log de terceiro (10 linhas do MDE)**
```
datasource("xdr") with (log_type="thirdparty")
| where pname == "Microsoft Defender for Endpoint"
| take 10
```

**2.4 — Nativo + terceiro lado a lado, por produto e host** (mostra o Data Lake único)
```
datasource("xdr")
| where eventTime > ago(24h)
| summarize eventos = count() by pname, endpointHostName
| sort by eventos desc
| take 50
```

---

## 3) Detecções e severidade

**3.1 — Top 100 detecções de alta severidade (>= 8) do Apex One nas últimas 24h** (a query do guia)
```
datasource("xdr") with (log_type="detection", product_code="sao")
| where eventTime > ago(1d)
| where severity >= 8
| project eventTime, productCode, severity, endpointHostName, ruleName
| sort by eventTime desc
| take 100
```

**3.2 — De onde vêm os alertas (detecções por produto)**
```
datasource("xdr") with (log_type="detection")
| where eventTime > ago(7d)
| summarize deteccoes = count() by pname
| sort by deteccoes desc
```

**3.3 — Regras que mais dispararam (candidatas a tuning / ruído)**
```
datasource("xdr") with (log_type="detection")
| where eventTime > ago(7d)
| summarize disparos = count() by ruleName
| sort by disparos desc
| take 20
```

**3.4 — Hosts com mais detecções (onde focar)**
```
datasource("xdr") with (log_type="detection")
| where eventTime > ago(7d)
| summarize alertas = count() by endpointHostName
| sort by alertas desc
| take 20
```

**3.5 — Ranking dos tipos de evento mais frequentes**
```
datasource("xdr") with (log_type="detection")
| where eventTime > ago(7d)
| summarize c = count() by eventName
| sort by c desc
| take 25
```

---

## 4) Threat hunting (podem retornar zero — e tá tudo bem)

**4.1 — PowerShell codificado (-enc): ofuscação clássica** (a query do slide 30)
```
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where processCmd contains "powershell" and processCmd contains "-enc"
| summarize hits = count() by endpointHostName, parentCmd
| sort by hits desc
```

**4.2 — LOLBins comuns (living-off-the-land)**
```
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where processCmd contains "certutil" or processCmd contains "mshta" or processCmd contains "rundll32"
| project eventTime, endpointHostName, processCmd, parentCmd
| sort by eventTime desc
| take 50
```

**4.3 — Possível acesso ao LSASS (dump de credenciais)**
```
datasource("xdr")
| where eventCategory == "DeviceProcessEvents"
| where processCmd contains "lsass"
| project eventTime, endpointHostName, processCmd, parentCmd
| sort by eventTime desc
```

**4.4 — Filtrar por técnica MITRE via tags** (ex.: T1055 – process injection)
```
datasource("xdr") with (log_type="detection")
| where tags has "MITRE.T1055"
| project eventTime, endpointHostName, eventName, ruleName, tags
| sort by eventTime desc
```

**4.5 — Conexões de rede por host (últimas 24h)**
```
datasource("xdr")
| where eventCategory == "DeviceNetworkEvents"
| where eventTime > ago(24h)
| summarize conexoes = count() by endpointHostName
| sort by conexoes desc
| take 50
```

**4.6 — Volume de logon por conta e host (picos suspeitos)**
```
datasource("xdr")
| where eventCategory == "DeviceLogonEvents"
| where eventTime > ago(24h)
| summarize logons = count() by duser, endpointHostName
| sort by logons desc
| take 50
```

---

## 5) Investigação: "quem?" e "onde?"

**5.1 — Timeline de um host** (troque o nome do host na linha `where`)
```
datasource("xdr")
| where endpointHostName == "trendmicro-scout-5n2s5"
| where eventTime > ago(24h)
| project eventTime, eventCategory, eventName, processCmd
| sort by eventTime desc
| take 100
```

**5.2 — Tudo ligado a um usuário** (troque o e-mail na linha `where`)
```
datasource("xdr") with (log_type="detection")
| where duser == "contato@seudominio.com"
| project eventTime, pname, eventName, endpointHostName
| sort by eventTime desc
```

**5.3 — Abrir um evento específico por ID** (troque o eventId na linha `where`)
```
datasource("xdr") with (log_type="detection")
| where eventId == "100119"
| project eventTime, pname, endpointHostName, eventName, eventSubName, ruleName
| sort by eventTime desc
```

**5.4 — Processos executados por host (baseline rápido)**
```
datasource("xdr")
| where eventCategory == "DeviceProcessEvents" and eventTime > ago(24h)
| summarize execucoes = count() by endpointHostName
| sort by execucoes desc
| take 20
```

---

## 6) Plano B (se algo der errado na hora)

- **"Request failed with status code 502" (ou 500/504):** é erro do **servidor/gateway**, não da sua query — geralmente temporário. Clique **Run query** de novo; se persistir, rode a query leve do bloco 0 (`take 10`, `ago(1h)`) pra ver se o backend voltou. Se continuar caindo, é a plataforma — siga a demo por slide e retome depois.
- **Squiggle vermelho / erro de sintaxe:** corrija antes de rodar — query inválida não executa. Passe o mouse no erro pra ver a mensagem.
- **Campo não existe:** apague o nome e deixe o **autocomplete** sugerir o campo certo daquela fonte. (Ex.: não existe `initiatingProcessFileName` — use `parentCmd`.)
- **Campo em array (ex.: `tags`):** use `has`, não `contains` — ex.: `tags has "MITRE.T1055"`. O `contains` só funciona em texto.
- **Campos confirmados no seu ambiente (dos prints):** `eventTime`, `pname`, `productCode`, `endpointHostName`, `processCmd`, `parentCmd`, `tags` (array → `has`), `eventId`, `eventName`, `eventSubName`, `ruleType`, `ruleName`, `duser`, `eventCategory`, `severity`.
- **Voltou vazio:** amplie o tempo (`ago(7d)` → `ago(30d)`), tire um `where`, ou troque `==` por `contains`.
- **Regra de ouro do summarize:** depois de `summarize ... by X`, só existem `X` e a métrica agregada (ex.: `total`). Não dá pra `project` colunas que foram agregadas.
- **Query "à prova de falha" pra salvar a demo:** a 1.2 ou a 2.1 — retornam dados e ficam boas na tabela/gráfico. Troque a visualização pra gráfico de barras nos `summarize ... by ...`.
