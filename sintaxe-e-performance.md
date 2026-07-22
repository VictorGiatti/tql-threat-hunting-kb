# Sintaxe & performance · TQL

[← Início da base](README.md)

Referência rápida da linguagem, campos confirmados no ambiente e como sair de enrascada na hora.

## As peças da linguagem

| Peça | Para quê |
|---|---|
| `datasource("xdr")` | Escolhe a fonte. Refine com `with (log_type="…", product_code="…")`. |
| `where` | Filtra linhas. |
| `summarize <métrica> by <campos>` | Agrega (ex.: `count()`, `dcount()`, `avg()`). |
| `project` | Escolhe/renomeia colunas. |
| `extend` | Cria coluna derivada (ex.: `extend cat = tostring(vendorParsed.Category)`). |
| `sort by` / `top N by` | Ordena / pega os N maiores. |
| `take N` | Limita a N linhas (amostra). |
| `render` | Desenha gráfico (`linechart`, `barchart`, `columnchart`). |
| Tempo | `ago(1h)`, `ago(24h)`, `ago(7d)`, `bin(eventTime, 1h)`. |

## Regras de ouro

- **Filtro "de graça":** sempre que souber, use `with (log_type="…", product_code="…")`. Reduz muito o volume varrido.
- **Janela curta primeiro:** `ago(1h)` → `ago(1d)` → `ago(7d)`. Amplie só se precisar.
- **`project` cedo:** traga apenas as colunas necessárias.
- **Barato antes do caro:** `==` e `in` antes de `contains` / `matches regex`.
- **Array usa `has`:** campos como `tags` são arrays, use `has` ou `has_any (…)`, nunca `contains` (que é só pra texto).
- **`summarize` "come" colunas:** depois de `summarize ... by X`, só existem `X` e a métrica (ex.: `total`). Não dá pra `project` uma coluna que foi agregada. Ou você agrega, ou lista linhas cruas: nunca os dois na mesma etapa.
- **Zero resultado é resposta:** num hunt, não achar o padrão também é informação.

## Logs de terceiros

- Jeito rápido: `datasource("xdr") with (log_type="thirdparty")` + `where pname == "Fortigate"`.
- Jeito oficial/otimizado: `with (product_code="tlc", log_type="thirdparty")` + `where logRepoId == "…"` (o autocomplete lista os seus conectores).
- Filtrar por coletor: além de `pname`, dá pra usar `collectorName` (ex.: `collectorName == "Windows_OS"`).
- **Campos parseados do fornecedor:** pegue subcampos com `vendorParsed.<Campo>` e converta com `tostring(...)`, normalmente via `extend`. Ex.: `extend VendorCategory = tostring(vendorParsed.Category)`.

## Campos confirmados no ambiente

Vindos dos testes reais no tenant (podem variar por fonte):

`eventTime` · `pname` · `productCode` · `endpointHostName` · `processCmd` · `parentCmd` · `tags` (array → `has`) · `eventId` · `eventName` · `eventSubName` · `ruleType` · `ruleName` · `duser` · `eventCategory` · `severity` · `collectorName` · `vendorParsed.<Campo>`

> Não achou a coluna? Apague o nome e deixe o **autocomplete** sugerir o campo certo daquela fonte, ou abra a **tabela de schema** no painel esquerdo do editor.

## Padrões desta base (importante validar)

- **Hunts de endpoint** usam `where eventCategory == "DeviceProcessEvents"`. Se no seu tenant esse valor não existir, troque a linha por escopo de fonte: `datasource("xdr") with (log_type="telemetry")` (padrão da doc oficial), o resto da query continua igual.
- Muitos hunts usam `matches regex "(?i)…"` (case-insensitive de propósito). Lembre que `has_any` é **case-sensitive**; se um hunt não retornar nada, tente a versão com regex `(?i)`.
- **E-mail** (`mail*`, `mal*`), **Identidade** (`principalName`, `ipAddress`, `statusReason`) e **Nuvem** (CloudTrail) têm campos que variam por tenant/conector: valide no painel de schema. Os hunts de **Nuvem** dependem do seu conector AWS/CloudTrail estar conectado.

## Troubleshooting (plano B na hora)

| Sintoma | O que fazer |
|---|---|
| **`Request failed with status code 502` (ou 500/504)** | Erro de servidor/gateway, não da sua query. Clique **Run query** de novo; se persistir, rode uma query leve (`take 10`, `ago(1h)`) pra ver se o backend voltou. |
| **Squiggle vermelho / erro de sintaxe** | Query inválida não executa. Passe o mouse no erro pra ver a mensagem e corrija antes de rodar. |
| **"campo não existe"** | Apague o nome e use o autocomplete. Ex.: não existe `initiatingProcessFileName`, o correto é `parentCmd`. |
| **`contains` reclamando de array** | O campo é array (ex.: `tags`). Troque por `has` / `has_any`. |
| **Voltou vazio** | Amplie o tempo (`ago(7d)` → `ago(30d)`), tire um `where`, ou troque `==` por `contains`. |
| **Precisa salvar a demo** | Rode um hunt de "Visão geral" (inventário de fontes), quase sempre retorna dados e fica bom em gráfico de barras. |
