# Sintaxe & performance · TQL

[← Início da base](README.md)

Referência rápida da linguagem, campos confirmados no ambiente e como sair de enrascada na hora.

## As peças da linguagem

| Peça | Para quê |
|---|---|
| `datasource("xdr")` | Escolhe a fonte. Refine com `with (log_type="…", product_code="…")`. |
| `where` | Filtra linhas. |
| `summarize <alias> = <métrica> by <campos>` | Agrega (ex.: `count()`, `dcount()`, `avg()`). O alias é **obrigatório**. |
| `project` | Escolhe colunas (substitui o conjunto: o que não está listado é descartado). |
| `extend` | Cria coluna derivada — é aqui que se renomeia (ex.: `extend cat = tostring(vendorParsed.Category)`). |
| `sort by` / `top N by` | Ordena / pega os N maiores. |
| `take N` | Limita a N linhas (amostra). |
| `distinct` | Combinações únicas das colunas listadas. |
| `mv-expand <alias> = <array>` | Explode array em uma linha por elemento. |
| `join` / `let` / `union` | Combina pipelines. Ver "Combinando fontes" abaixo. |
| `render` | Desenha gráfico: `barchart`, `columnchart`, `linechart`, `piechart`, `table`. |
| Tempo | `ago(1h)`, `ago(1d)`, `ago(7d)`, `bin(eventTime, 1h)`. |

## Regras de ouro

- **Filtro "de graça":** sempre que souber, use `with (log_type="…", product_code="…")`. Reduz muito o volume varrido.
- **Janela curta primeiro:** `ago(1h)` → `ago(1d)` → `ago(7d)`. Amplie só se precisar.
- **`project` cedo:** traga apenas as colunas necessárias.
- **Barato antes do caro:** `==` e `in` antes de `contains` / `matches regex`.
- **Array usa `has_any`:** campos como `tags` são arrays. A doc oficial só sanciona `has_any (…)` para array (`has` e `contains` são operadores de string; string em coluna não-string é o erro TQL014). Para um valor só, use a lista de um item: `tags has_any ("MITRE.T1055")`. As outras saídas para array são índice literal (`col[0]`) e `mv-expand`.
- **`summarize` "come" colunas:** depois de `summarize ... by X`, só existem `X` e a métrica (ex.: `total`). Não dá pra `project` uma coluna que foi agregada. Ou você agrega, ou lista linhas cruas: nunca os dois na mesma etapa.
- **Zero resultado é resposta:** num hunt, não achar o padrão também é informação.

## As regras que quebram a query

Estas fazem a consulta falhar ou voltar vazia sem avisar. Valem a leitura antes de escrever a primeira query do zero.

| Regra | Detalhe |
|---|---|
| **Toda agregação precisa de alias** | `summarize count()` é rejeitado. Escreva `summarize total = count() by ruleName`. Expressão dentro do `by` também precisa de nome: `by hora = bin(eventTime, 1h)`. |
| **Só existe `eventTime`** | Não há `timestamp`, `TimeGenerated` nem `_time`. |
| **`ago()` só aceita s, m, h, d** | `ago(1w)`, `ago(1mo)` e `ago(1y)` falham → use `ago(7d)`, `ago(30d)`, `ago(365d)`. |
| **`now()` não existe** | O editor autocompleta, o backend quebra com `Operator 'now' not found`. "Agora" é `ago(0s)`. |
| **`bin()` só aceita 6 valores** | `1s`, `1m`, `1h`, `1d`, `7d`, `30d`. `bin(eventTime, 5m)` é erro. |
| **Tipos são estritos** | `severity == 8` (número, sem aspas) e `productCode == "sao"` (string, com aspas). `severity == "8"` é erro de validação (TQL013), não "não bateu". Converta com `toint()` / `tostring()`. |
| **`null` não compara com `==`** | Use `isnull(x)` e `not(isnull(x))`. **`isnotnull()` não existe.** `isempty()` / `isnotempty()` existem. |
| **Booleanos por extenso** | `and`, `or`, `not(...)`. `&&`, `\|\|` e `!` são só de KQL e não são aceitos. |
| **`has` é case-SENSITIVE** | E é substring, não palavra inteira como no KQL. `contains` é case-insensitive. **Não existe `has_cs`.** |
| **`parse_json()` não funciona** | Não há conversão string → dynamic. Se o dado está em coluna string, trate com `contains` / `has` / `matches regex`. |
| **`let` vai no topo** | Todos os `let` antes do primeiro `datasource(...)`, terminados com `;`. Fora disso é TQL016. |
| **Valor do `with (...)` entre aspas** | `product_code=sao` falha na execução. Lista: `product_code=["sao","xes"]`. |
| **`take` não corta no meio do pipeline** | O motor vira uma única sentença SQL, então os `where` valem antes do limite de linhas, não importa onde o `take` esteja. **Diferente do KQL.** E sem `sort`, quais N linhas voltam é arbitrário. |

### O editor mente

Passam na validação (sem squiggle) e **só falham quando você clica em Run query**:

`now()` · `arg_max` / `arg_min` · `bin()` com intervalo livre · `join kind=fullouter` · agregação dentro de `extend` · `parse_json()` · `tolong` / `tobool` / `toreal` / `todecimal` / `totimespan` / `toguid` · valor sem aspas no `with (...)`.

O editor valida contra o schema achatado (todas as colunas de todos os pares product_code/log_type), então "sem erro no editor" não significa "roda". **Sempre execute antes de considerar um hunt pronto.**

## Combinando fontes

- **Vários produtos na mesma query:** use a forma de array, é mais barato que `union`.
  `with (log_type=["telemetry","detection"], product_code=["xes","sao","sds"])`
- **`join`:** só `inner`, `leftouter` e `rightouter`. O lado direito **precisa ser uma variável `let`** — subquery inline é rejeitada. O `on` só aceita igualdade.
- Não existem `fullouter`, `leftsemi`, `rightsemi` nem `anti`. Para o efeito de `anti`, use `leftouter` + `where isnull(<colDaDireita>)`.
- **`union`** concatena tabelas nomeadas por `let` e só vale como **primeiro segmento** da query.

```
let suspeitos = datasource("xdr") with (log_type="detection", product_code="sao")
  | where eventTime > ago(1d)
  | where severity > 5;
datasource("xdr") with (log_type="detection", product_code="sao")
| where eventTime > ago(1d)
| join kind=inner suspeitos on endpointHostName
```

## Logs de terceiros

- Jeito rápido: `datasource("xdr") with (log_type="thirdparty")` + `where pname == "Fortigate"`.
- Jeito oficial/otimizado: `with (product_code="tlc", log_type="thirdparty")` + `where logRepoId == "…"` (o autocomplete lista os seus conectores **pelo nome**, não pelo ID).
- `logRepoId` é case-sensitive e **só é populado** na fatia `tlc`/`thirdparty`. Usado fora dali não dá erro: volta 0 linhas.
- Filtrar por coletor: além de `pname`, dá pra usar `collectorName` (ex.: `collectorName == "Windows_OS"`).
- **Campos parseados do fornecedor:** pegue subcampos com `vendorParsed.<Campo>` e converta com `tostring(...)`, normalmente via `extend`. Ex.: `extend VendorCategory = tostring(vendorParsed.Category)`. As chaves variam por conector — rode um `take 5` e olhe o valor cru antes de escolher.

## Gráficos

- Só cinco tipos renderizam: `barchart`, `columnchart`, `linechart`, `piechart`, `table`. Os outros 13 nomes (`timechart`, `areachart`, `piechart 3d` etc.) passam na validação e **caem para gráfico de linha**.
- Da query, só `xtitle` e `ytitle` são lidos: `| render linechart with (xtitle="Hora", ytitle="Eventos")`. Legenda, eixos, séries e empilhamento só no painel **Display settings** — que **tem precedência sobre o `render`** depois de alterado.
- **Coluna array/object não fica disponível como eixo.** Query com `make_set()` / `make_list()` é ótima em tabela, mas aquela coluna não vira gráfico.
- Cores são atribuídas automaticamente e não são customizáveis.

## Campos confirmados no ambiente

Vindos dos testes reais no tenant (podem variar por fonte):

`eventTime` · `pname` · `productCode` · `endpointHostName` · `processCmd` · `parentCmd` · `tags` (array → `has_any`) · `eventId` · `eventName` · `eventSubName` · `ruleType` · `ruleName` · `duser` · `eventCategory` · `severity` · `collectorName` · `vendorParsed.<Campo>`

> Não achou a coluna? Apague o nome e deixe o **autocomplete** sugerir o campo certo daquela fonte, ou abra a **tabela de schema** no painel esquerdo do editor. O hover mostra o tipo — use isso antes de escrever a comparação.

## Padrões desta base (importante validar)

- **Hunts de endpoint** usam `where eventCategory == "DeviceProcessEvents"`. Atenção: `DeviceProcessEvents`, `DeviceNetworkEvents` e `DeviceLogonEvents` são nomes de tabela do **Microsoft Defender Advanced Hunting** — no Vision One aparecem em log ingerido do MDE por conector de terceiro. Se o seu tenant não ingere MDE, esses hunts voltam vazios. Nesse caso troque a linha pelo escopo nativo (padrão da doc oficial), que o resto da query continua igual:
  ```
  datasource("xdr") with (log_type="telemetry", product_code=["xes","sao","sds"])
  ```
- Muitos hunts usam `matches regex "(?i)…"` (case-insensitive de propósito). Lembre que `has_any` é **case-sensitive**; se um hunt não retornar nada, tente a versão com regex `(?i)`.
- **E-mail** (`mail*`, `mal*`), **Identidade** (`principalName`, `ipAddress`, `statusReason`) e **Nuvem** (CloudTrail) têm campos que variam por tenant/conector: valide no painel de schema. Os hunts de **Nuvem** dependem do seu conector AWS/CloudTrail estar conectado.

## Troubleshooting (plano B na hora)

| Sintoma | O que fazer |
|---|---|
| **`Request failed with status code 502` (ou 500/504)** | Erro de servidor/gateway, não da sua query. Clique **Run query** de novo; se persistir, rode uma query leve (`take 10`, `ago(1h)`) pra ver se o backend voltou. |
| **Squiggle vermelho / erro de sintaxe** | Query inválida não executa. Passe o mouse no erro pra ver a mensagem e corrija antes de rodar. |
| **Rodou e deu `Operator '<x>' not found`** | Função que o editor autocompleta mas o backend não implementa (`now`, `parse_json`, `isnotnull`, `tolong`…). Ver "O editor mente". |
| **`Type mismatch` (TQL013)** | Literal com o tipo errado. Número sem aspas, string com aspas. Confirme o tipo no hover. |
| **"campo não existe"** | Apague o nome e use o autocomplete. Ex.: não existe `initiatingProcessFileName`, o correto é `parentCmd`. |
| **`contains` reclamando de array** | O campo é array (ex.: `tags`). Troque por `has_any (…)`. |
| **Voltou vazio** | Amplie o tempo (`ago(7d)` → `ago(30d)`), tire um `where`, ou — **se a coluna for string** — troque `==` por `contains`. Em coluna numérica isso dá TQL014; aí o certo é conferir o valor. Confira também a caixa: `has`, `has_any` e `in` são case-sensitive. |
| **Zerou depois de um `toint()` / `todouble()`** | Conversão que falha vira `null` silenciosamente. Blinde com `where not(isnull(<col>))`. |
| **Precisa salvar a demo** | Rode um hunt de "Visão geral" (inventário de fontes), quase sempre retorna dados e fica bom em gráfico de barras. |
