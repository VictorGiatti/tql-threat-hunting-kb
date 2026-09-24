# Sintaxe & performance · TQL

[← Início da base](README.md)

Referência rápida da linguagem, as regras que quebram a query, campos confirmados no ambiente, limites do TQL e como sair de enrascada na hora.

## As peças da linguagem

| Peça | Para quê |
|---|---|
| `datasource("xdr")` | Escolhe a fonte. Refine com `with (log_type="…", product_code="…")`. |
| `where` | Filtra linhas. |
| `summarize <alias> = <métrica> by <campos>` | Agrega (ex.: `count()`, `countif()`, `dcount()`, `avg()`, `make_set()`). O alias é **obrigatório**. |
| `project` | Escolhe colunas (substitui o conjunto: o que não está listado é descartado). |
| `extend` | Cria coluna derivada; é aqui que se renomeia (ex.: `extend cat = tostring(vendorParsed.Category)`). |
| `sort by` / `top N by` | Ordena / pega os N maiores. |
| `take N` | Limita a N linhas (amostra). |
| `distinct` | Combinações únicas das colunas listadas. |
| `mv-expand <alias> = <array>` | Explode array em uma linha por elemento. |
| `join` / `let` / `union` | Combina pipelines. Ver [Combinando fontes](#combinando-fontes). |
| `render` | Desenha gráfico: `barchart`, `columnchart`, `linechart`, `piechart`, `table`. Ver [Gráficos](#gráficos). |
| Tempo | `ago(1h)`, `ago(1d)`, `ago(7d)`, `bin(eventTime, 1h)`. |

### Funciona, mas não está na documentação da Trend

Testado em tenant de produção com TQL ligado (detalhes no dossiê de campo do TQL):

`has_any` · `mv-expand` · `partition by` · `tostring()` · `coalesce()` · `replace_string()` · `split()` · `strcat()` · `array_length()` · `make_set_if()` · `set_intersect()` · `set_union()` · `vendorParsed.<Campo>` · `collectorName` · `logRepoId`

## Regras de ouro

- **Filtro "de graça":** sempre que souber, use `with (log_type="…", product_code="…")`. Reduz muito o volume varrido.
- **Janela curta primeiro:** `ago(1h)` → `ago(1d)` → `ago(7d)`. Amplie só se precisar. Toda query leva janela de tempo.
- **`project` cedo:** traga apenas as colunas necessárias.
- **Barato antes do caro:** `==` e `in` antes de `contains` / `matches regex`.
- **Linha de comando usa regex `(?i)`:** `has` e `has_any` são **case-sensitive**. Em `processCmd`/`parentCmd` quem escolhe a caixa é o atacante (`IEX` ou `iex`, `C$` ou `c$`, `/Create` ou `/create`), então os hunts usam `matches regex "(?i)(…)"`. `has_any` fica para valores de caixa fixa, como `tags has_any ("MITRE.T1055")`.
- **Array usa `has_any`:** campos como `tags` são arrays. Use `has_any (…)`, que serve pra um valor ou vários (`tags has_any ("MITRE.T1055")`), nunca `contains` (que é só pra texto). As outras saídas para array são índice literal (`col[0]`) e `mv-expand`.
- **Regex sem barra invertida:** prefira `[.]` a `\.` e ` +` a `\s+`. Funciona igual e evita problema de escape dentro da string.
- **`summarize` "come" colunas:** depois de `summarize ... by X`, só existem `X` e a métrica (ex.: `total`). Não dá pra `project` uma coluna que foi agregada. Ou você agrega, ou lista linhas cruas: nunca os dois na mesma etapa.
- **Limite o resultado:** query sem `summarize` termina com `take` ou `top`, senão o console corta sem avisar.

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
- **`join`:** só `inner`, `leftouter` e `rightouter`. O lado direito **precisa ser uma variável `let`**: subquery inline é rejeitada. O `on` só aceita igualdade.
- Não existem `fullouter`, `leftsemi`, `rightsemi` nem `anti`. Para o efeito de `anti`, use `leftouter` + `where isnull(<colDaDireita>)`.
- **`union`** concatena tabelas nomeadas por `let` e só vale como **primeiro segmento** da query.

```
let suspeitos = datasource("xdr") with (log_type="detection", product_code="sao")
  | where eventTime > ago(1d)
  | where severity > 5;
datasource("xdr") with (log_type="detection", product_code="sao")
| where eventTime > ago(1d)
| join kind=inner suspeitos on endpointHostName
| take 100
```

## Logs de terceiros

- Jeito rápido: `datasource("xdr") with (log_type="thirdparty")` + `where pname == "Fortigate"`.
- Jeito oficial/otimizado: `with (product_code="tlc", log_type="thirdparty")` + `where logRepoId == "…"` (o autocomplete lista os seus conectores **pelo nome**, não pelo ID).
- `logRepoId` é case-sensitive e **só é populado** na fatia `tlc`/`thirdparty`. Usado fora dali não dá erro: volta 0 linhas.
- Filtrar por coletor: além de `pname`, dá pra usar `collectorName` (ex.: `collectorName == "Windows_OS"`).
- **Campos parseados do fornecedor:** pegue subcampos com `vendorParsed.<Campo>` e converta com `tostring(...)`, normalmente via `extend`. Ex.: `extend VendorCategory = tostring(vendorParsed.Category)`. As chaves variam por conector: rode um `take 5` e olhe o valor cru antes de escolher.

## Gráficos

- Só cinco tipos renderizam: `barchart`, `columnchart`, `linechart`, `piechart`, `table`. Os outros 13 nomes (`timechart`, `areachart`, `piechart 3d` etc.) passam na validação e **caem para gráfico de linha**.
- Da query, só `xtitle` e `ytitle` são lidos: `| render linechart with (xtitle="Hora", ytitle="Eventos")`. Legenda, eixos, séries e empilhamento só no painel **Display settings**, que **tem precedência sobre o `render`** depois de alterado.
- **Coluna array/object não fica disponível como eixo.** Query com `make_set()` / `make_list()` é ótima em tabela, mas aquela coluna não vira gráfico.
- Ordene antes de desenhar (`sort by hora asc`), senão a linha do tempo sai fora de ordem.
- Cores são atribuídas automaticamente e não são customizáveis.

## Campos confirmados no ambiente

Vindos dos testes reais no tenant (podem variar por fonte):

`eventTime` · `pname` · `productCode` · `endpointHostName` · `processCmd` · `parentCmd` · `tags` (array → `has_any`) · `eventId` · `eventName` · `eventSubName` · `ruleType` · `ruleName` · `duser` · `eventCategory` · `severity` · `collectorName` · `vendorParsed.<Campo>`

> Não achou a coluna? Apague o nome e deixe o **autocomplete** sugerir o campo certo daquela fonte, ou abra a **tabela de schema** no painel esquerdo do editor. O hover mostra o tipo: use isso antes de escrever a comparação.

**Dicionário de colunas com tipo de dado:** a Trend publica o schema completo (34 produtos, 3.198 campos), mas não linka a partir da documentação do TQL:

- Por produto, renderizado: <https://trendmicro.github.io/tm-v1-schema/pages/index>
- Por `log_type`, no código-fonte: <https://github.com/trendmicro/tm-v1-schema> (pasta `doc_tql/`, um YAML por log type com `Name`, `Description_EN` e `DL_Type`)

O **tipo** é o que mais importa: `matches regex` não funciona em coluna `dynamic` (ex.: `src`, `dst`, `interestedIp`, `peerIp`, `act`, `tags`) e **volta vazio sem erro**. Nesses campos, use `has_any (…)`.

## Padrões desta base (importante validar)

- **Hunts de endpoint** usam `datasource("xdr")` + `where eventCategory == "DeviceProcessEvents"`. `DeviceProcessEvents`, `DeviceNetworkEvents` e `DeviceLogonEvents` são nomes de tabela do **Microsoft Defender Advanced Hunting**: no Vision One aparecem em log do MDE ingerido por conector de terceiro. Se esse valor não existir no seu tenant, o hunt volta vazio. Nesse caso troque a linha pelo escopo nativo (padrão da doc oficial), que o resto da query continua igual:
  ```
  datasource("xdr") with (log_type="telemetry", product_code=["xes","sao","sds"])
  ```
  Antes de trocar, rode `summarize total = count() by pname` com o filtro de `eventCategory` pra ver quais fontes entram: se aparecer fonte de terceiro, o `with` vai tirá-la do hunt.
- **Linha de comando** é filtrada com `matches regex "(?i)…"` (ver regras de ouro). Não volte para `has_any` nesses campos: o `lint` do repositório recusa.
- **E-mail** (`mail*`, `mal*`), **Identidade** (`principalName`, `ipAddress`, `statusReason`) e **Nuvem** (CloudTrail) têm campos que variam por tenant/conector: valide no painel de schema. Os hunts de **Nuvem** dependem do seu conector AWS/CloudTrail estar conectado.
- Hunts com `> **Limitação:**` dizem o que a query **não** cobre. Leia antes de reportar "nada encontrado".

## Limites da linguagem (diga o que o hunt não cobre)

Coisas que existem em KQL/SPL/CQL e **não** existem no TQL. A query não dá erro: ela simplesmente não faz, ou volta vazia.

| Precisa de | No TQL | O que fazer |
|---|---|---|
| Faixa CIDR (`/22`, `/12`, IPv6) | não existe | `startswith "10."` só é exato em fronteira de octeto (/8, /16, /24). Fora disso, diga que o recorte não é exato. |
| Extrair pedaço de texto (`extract`, `parse`, `rex`) | não existe | `matches regex` só filtra, não captura. Não dá pra agrupar pelo valor de dentro da string. |
| Decodificar base64 / URL | não existe | Ache o blob no TQL e decodifique fora (CyberChef). Não dá pra agendar detecção pelo conteúdo. |
| "Está em A mas não em B" (`leftanti`) | não existe | `join kind=leftouter` + `where isnull(<coluna da direita>)`. Materializa o lado direito inteiro: pode estourar tempo em telemetria. |
| Balde de 5 min, 15 min, 2 h | não existe | `bin()` aceita só `1s`, `1m`, `1h`, `1d`, `7d`, `30d`. Beacon de 5 min não aparece bem em nenhum dos dois. |
| `ago(2w)`, `ago(1mo)` | não existe | `ago()` aceita só `s`, `m`, `h`, `d`: use `ago(14d)`, `ago(30d)`. |
| Busca livre em todas as colunas (`search`) | não existe | Nomeie a coluna. Pra um IP solto, faça `or` entre as colunas candidatas e diga quais cobriu. |
| Tirar aspas com `trim("\"", …)` | defeito do parser | Literal só com aspa escapada falha em silêncio. Filtre com `contains` no texto de dentro. |
| `&&`, `\|\|`, `!` | não existe | `and`, `or`, `not(...)`, `!=`, `!in`. |

## Voltou vazio? Confirme antes de concluir

Vazio é resposta legítima, mas só depois de descartar as causas técnicas. Em ordem de frequência:

1. **`log_type` / `product_code` errado.** Tire o `with (...)` e veja se aparecem linhas.
2. **Coluna que não existe naquela fonte.** Tire os `where` um por um até aparecer linha: o último removido é o culpado.
3. **`matches regex` em coluna `dynamic`** (`src`, `dst`, `tags`, `interestedIp`, `peerIp`, `act`, arrays de e-mail). Troque por `has_any (…)`.
4. **Caixa diferente.** `has`, `has_any` e `in` são case-sensitive; `contains` não.
5. **Janela curta ou sensor fora do ar.** Amplie a janela e rode o hunt "Inventário de fontes de dados" (Visão geral) pra ver se a fonte reportou no período.
6. **`contains` em coluna array.** Use `has_any (…)`.
7. **Conversão que falhou.** `toint()` / `todouble()` que não consegue converter vira `null` sem avisar, e o `where` seguinte descarta a linha. Blinde com `where not(isnull(<col>))` e confira o valor cru.

Reporte o que foi descartado. "Nenhum resultado, e confirmei que a fonte está reportando e as colunas existem" é um achado. "Nenhum resultado" sozinho não é.

## Troubleshooting (plano B na hora)

| Sintoma | O que fazer |
|---|---|
| **`Request failed with status code 502` (ou 500/504)** | Erro de servidor/gateway, não da sua query. Clique **Run query** de novo; se persistir, rode uma query leve (`take 10`, `ago(1h)`) pra ver se o backend voltou. |
| **Squiggle vermelho / erro de sintaxe** | Query inválida não executa. Passe o mouse no erro pra ver a mensagem e corrija antes de rodar. |
| **Rodou e deu `Operator '<x>' not found`** | Função que o editor autocompleta mas o backend não implementa (`now`, `parse_json`, `isnotnull`, `tolong`…). Ver [O editor mente](#o-editor-mente). |
| **`Type mismatch` (TQL013)** | Literal com o tipo errado. Número sem aspas, string com aspas. Confirme o tipo no hover. |
| **"campo não existe"** | Apague o nome e use o autocomplete. Ex.: não existe `initiatingProcessFileName`, o correto é `parentCmd`. |
| **`contains` reclamando de array** | O campo é array (ex.: `tags`). Troque por `has_any (…)`. |
| **Voltou vazio** | Siga o [checklist](#voltou-vazio-confirme-antes-de-concluir) antes de concluir "nada encontrado". Trocar `==` por `contains` só vale em coluna string: em coluna numérica dá TQL014. |
| **Precisa de algo que sempre responde** | Rode um hunt de "Visão geral" (inventário de fontes), quase sempre retorna dados e fica bom em gráfico de barras. |

## Validação automática

O repositório valida as queries antes de entrar (e o CI roda o mesmo em todo push/PR):

```bash
python scripts/kb.py lint    # erros de TQL: função que não existe, bin/ago inválidos, sem janela, sem take, has_any em linha de comando…
python scripts/kb.py test    # amostras de linha de comando (tests/amostras.json) contra os filtros dos hunts
python scripts/kb.py build   # regera índice, contadores e os dados do painel a partir dos .md
```

`scripts/tqlcheck.py` também roda sozinho numa query avulsa: `python scripts/tqlcheck.py minha_query.tql`.
