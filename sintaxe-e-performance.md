# Sintaxe & performance · TQL

[← Início da base](README.md)

Referência rápida da linguagem, campos confirmados no ambiente, limites do TQL e como sair de enrascada na hora.

## As peças da linguagem

| Peça | Para quê |
|---|---|
| `datasource("xdr")` | Escolhe a fonte. Refine com `with (log_type="…", product_code="…")`. |
| `where` | Filtra linhas. |
| `summarize <métrica> by <campos>` | Agrega (ex.: `count()`, `countif()`, `dcount()`, `avg()`, `make_set()`). |
| `project` | Escolhe/renomeia colunas. |
| `extend` | Cria coluna derivada (ex.: `extend cat = tostring(vendorParsed.Category)`). |
| `sort by` / `top N by` | Ordena / pega os N maiores. |
| `take N` | Limita a N linhas (amostra). |
| `render` | Desenha gráfico. Verificados: `linechart`, `columnchart`. |
| Tempo | `ago(1h)`, `ago(24h)`, `ago(7d)`, `bin(eventTime, 1h)`. |

### Funciona, mas não está na documentação da Trend

Testado em tenant de produção com TQL ligado (detalhes no dossiê de campo do TQL):

`has_any` · `mv-expand` · `partition by` · `tostring()` · `coalesce()` · `replace_string()` · `split()` · `strcat()` · `array_length()` · `make_set_if()` · `set_intersect()` · `set_union()` · `vendorParsed.<Campo>` · `collectorName` · `logRepoId`

## Regras de ouro

- **Filtro "de graça":** sempre que souber, use `with (log_type="…", product_code="…")`. Reduz muito o volume varrido.
- **Janela curta primeiro:** `ago(1h)` → `ago(1d)` → `ago(7d)`. Amplie só se precisar. Toda query leva janela de tempo.
- **`project` cedo:** traga apenas as colunas necessárias.
- **Barato antes do caro:** `==` e `in` antes de `contains` / `matches regex`.
- **Linha de comando usa regex `(?i)`:** `has` e `has_any` são **case-sensitive**. Em `processCmd`/`parentCmd` quem escolhe a caixa é o atacante (`IEX` ou `iex`, `C$` ou `c$`, `/Create` ou `/create`), então os hunts usam `matches regex "(?i)(…)"`. `has`/`has_any` ficam para valores de caixa fixa, como `tags has "MITRE.T1055"`.
- **Array usa `has`:** campos como `tags` são arrays, use `has` ou `has_any (…)`, nunca `contains` (que é só pra texto).
- **Regex sem barra invertida:** prefira `[.]` a `\.` e ` +` a `\s+`. Funciona igual e evita problema de escape dentro da string.
- **`summarize` "come" colunas:** depois de `summarize ... by X`, só existem `X` e a métrica (ex.: `total`). Não dá pra `project` uma coluna que foi agregada. Ou você agrega, ou lista linhas cruas: nunca os dois na mesma etapa.
- **Limite o resultado:** query sem `summarize` termina com `take` ou `top`, senão o console corta sem avisar.

## Logs de terceiros

- Jeito rápido: `datasource("xdr") with (log_type="thirdparty")` + `where pname == "Fortigate"`.
- Jeito oficial/otimizado: `with (product_code="tlc", log_type="thirdparty")` + `where logRepoId == "…"` (o autocomplete lista os seus conectores).
- Filtrar por coletor: além de `pname`, dá pra usar `collectorName` (ex.: `collectorName == "Windows_OS"`).
- **Campos parseados do fornecedor:** pegue subcampos com `vendorParsed.<Campo>` e converta com `tostring(...)`, normalmente via `extend`. Ex.: `extend VendorCategory = tostring(vendorParsed.Category)`.

## Campos confirmados no ambiente

Vindos dos testes reais no tenant (podem variar por fonte):

`eventTime` · `pname` · `productCode` · `endpointHostName` · `processCmd` · `parentCmd` · `tags` (array → `has`) · `eventId` · `eventName` · `eventSubName` · `ruleType` · `ruleName` · `duser` · `eventCategory` · `severity` · `collectorName` · `vendorParsed.<Campo>`

> Não achou a coluna? Apague o nome e deixe o **autocomplete** sugerir o campo certo daquela fonte, ou abra a **tabela de schema** no painel esquerdo do editor.

**Dicionário de colunas com tipo de dado:** a Trend publica o schema completo (34 produtos, 3.198 campos), mas não linka a partir da documentação do TQL:

- Por produto, renderizado: <https://trendmicro.github.io/tm-v1-schema/pages/index>
- Por `log_type`, no código-fonte: <https://github.com/trendmicro/tm-v1-schema> (pasta `doc_tql/`, um YAML por log type com `Name`, `Description_EN` e `DL_Type`)

O **tipo** é o que mais importa: `matches regex` não funciona em coluna `dynamic` (ex.: `src`, `dst`, `interestedIp`, `peerIp`, `act`, `tags`) e **volta vazio sem erro**. Nesses campos, use `has` / `has_any`.

## Padrões desta base (importante validar)

- **Hunts de endpoint** usam `datasource("xdr")` + `where eventCategory == "DeviceProcessEvents"`. Se no seu tenant esse valor não existir, troque por escopo de fonte: `datasource("xdr") with (log_type="telemetry")` (padrão da doc oficial). Antes de trocar, rode `summarize count() by pname` com o filtro de `eventCategory` pra ver quais fontes entram: se aparecer fonte de terceiro, o `with` vai tirá-la do hunt.
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
3. **`matches regex` em coluna `dynamic`** (`src`, `dst`, `tags`, `interestedIp`, `peerIp`, `act`, arrays de e-mail). Troque por `has` / `has_any`.
4. **`has` com caixa diferente.** `has` é case-sensitive; `contains` não.
5. **Janela curta ou sensor fora do ar.** Amplie a janela e rode o hunt "Inventário de fontes de dados" (Visão geral) pra ver se a fonte reportou no período.
6. **`contains` em coluna array.** Use `has`.

Reporte o que foi descartado. "Nenhum resultado, e confirmei que a fonte está reportando e as colunas existem" é um achado. "Nenhum resultado" sozinho não é.

## Troubleshooting (plano B na hora)

| Sintoma | O que fazer |
|---|---|
| **`Request failed with status code 502` (ou 500/504)** | Erro de servidor/gateway, não da sua query. Clique **Run query** de novo; se persistir, rode uma query leve (`take 10`, `ago(1h)`) pra ver se o backend voltou. |
| **Squiggle vermelho / erro de sintaxe** | Query inválida não executa. Passe o mouse no erro pra ver a mensagem e corrija antes de rodar. |
| **"campo não existe"** | Apague o nome e use o autocomplete. Ex.: não existe `initiatingProcessFileName`, o correto é `parentCmd`. |
| **`contains` reclamando de array** | O campo é array (ex.: `tags`). Troque por `has` / `has_any`. |
| **Voltou vazio** | Siga o checklist acima antes de concluir "nada encontrado". |
| **Precisa de algo que sempre responde** | Rode um hunt de "Visão geral" (inventário de fontes), quase sempre retorna dados e fica bom em gráfico de barras. |

## Validação automática

O repositório valida as queries antes de entrar (e o CI roda o mesmo em todo push/PR):

```bash
python scripts/kb.py lint    # erros de TQL: função que não existe, bin/ago inválidos, sem janela, sem take, has_any em linha de comando…
python scripts/kb.py test    # amostras de linha de comando (tests/amostras.json) contra os filtros dos hunts
python scripts/kb.py build   # regera índice, contadores e os dados do painel a partir dos .md
```

`scripts/tqlcheck.py` também roda sozinho numa query avulsa: `python scripts/tqlcheck.py minha_query.tql`.
