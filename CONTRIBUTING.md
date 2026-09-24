# Como contribuir com hunts

[← Início da base](README.md)

A base cresce com o time. Cada hunt que funcionou no dia a dia vale a pena registrar aqui.

## Adicionar um hunt (Markdown)

1. Abra o arquivo da categoria em [`hunts/`](hunts/) (ex.: `hunts/credenciais.md`). Se a categoria não existir, crie um arquivo novo seguindo o mesmo padrão (título `# <Categoria> · Threat Hunting TQL`) e inclua o nome dele na lista `ORDER` de [`scripts/kb.py`](scripts/kb.py).
2. Cole um bloco no formato abaixo, separando do hunt anterior com `---`:

````markdown
## Título curto e claro do hunt

**MITRE ATT&CK:** `T1078`

Uma linha explicando o que o hunt procura e por quê.

> **Limitação:** (opcional) o que a query não cobre, ex.: "sem CIDR, o recorte por /22 não é exato".

```text
datasource("xdr")
| where eventTime > ago(7d)
| ...
| take 100
```
````

3. Rode a validação e o build (Python 3, sem dependências):

```bash
python scripts/kb.py lint    # tem que terminar com 0 erro(s)
python scripts/kb.py test    # amostras de linha de comando contra os filtros
python scripts/kb.py build   # atualiza hunts/README.md, contadores do README e o painel
```

O `build` regera o índice (`hunts/README.md`), os contadores do `README.md` e os dados do painel HTML a partir dos `.md`. Não edite esses trechos à mão: o CI roda `python scripts/kb.py check` e falha se estiverem desatualizados.

### Padrão de qualidade

- **Título** direto (o que ele acha), não o comando. Títulos são únicos na base.
- **MITRE** quando fizer sentido (`T1059` ou `T1059.001`, vários separados por ` / `); use `—` se não se aplicar.
- **Descrição** de uma linha.
- **Query** testada no console, com aspas retas (`"`), começando por `datasource(...)`, **com janela de tempo** e, se não agrega, **terminando em `take`/`top`**. Sem comentários no meio da query.
- **Linha de comando** (`processCmd`, `parentCmd`) com `matches regex "(?i)(…)"`, não `has`/`has_any`: esses são case-sensitive e o atacante escolhe a caixa. O `lint` recusa.
- **Regex sem barra invertida** quando der: `[.]` em vez de `\.`, ` +` em vez de `\s+`.
- Prefira `with (log_type=…, product_code=…)` e `project` cedo (ver [sintaxe-e-performance.md](sintaxe-e-performance.md)).
- Se o hunt esbarra num limite do TQL (CIDR, extração, decode, anti-join, `bin()`), escreva a linha `> **Limitação:**`. Hunt que cobre 80% e diz isso vale mais que um que parece cobrir 100%.

### Amostras (recomendado para hunts de linha de comando)

Em [`tests/amostras.json`](tests/amostras.json), adicione o título do hunt com exemplos do que **deve** e do que **não deve** casar. O `kb.py test` aplica os filtros `where` do hunt sobre essas linhas, o que pega regex quebrada antes de ela chegar no console:

```json
"Título do hunt": {
  "casa": ["net user hacker P@ss /add"],
  "nao_casa": ["net user bob"]
}
```

## Alternativa: prototipar no painel e exportar

Se preferir montar visualmente antes de escrever o Markdown:

1. Abra [`painel/tql-threat-hunting.html`](painel/tql-threat-hunting.html) no navegador.
2. Clique em **+ Adicionar hunt**, preencha e salve (fica guardado no seu navegador). O formulário aponta na hora os erros de TQL mais comuns.
3. Clique em **Backup / Restaurar** e copie o JSON. Cada hunt tem este formato:

```json
{
  "cat": "Credenciais",
  "mitre": "T1078",
  "titulo": "Título do hunt",
  "desc": "Descrição de uma linha.",
  "q": "datasource(\"xdr\")\n| where ..."
}
```

4. Converta pro formato Markdown acima e abra o Pull Request (ou mande o JSON pro mantenedor).

## Fluxo git sugerido

```bash
git checkout -b hunt/nome-curto
# edite os arquivos
python scripts/kb.py lint && python scripts/kb.py test && python scripts/kb.py build
git add .
git commit -m "hunt: <categoria> - <título>"
git push -u origin hunt/nome-curto
# abra um Pull Request para revisão (o template já traz o checklist)
```

### Mensagens de commit

Prefixo curto, em português, dizendo o que muda:

| Prefixo | Quando usar | Exemplo |
|---|---|---|
| `hunt:` | hunt novo | `hunt: persistência - webshell em w3wp/sqlservr` |
| `fix:` | query corrigida (falso negativo, ruído, erro no console) | `fix(persistencia): net user /add com argumentos no meio` |
| `docs:` | README, sintaxe, cola, CONTRIBUTING | `docs: checklist de voltou vazio` |
| `painel:` | HTML/JS do painel (os dados saem do `build`) | `painel: link MITRE nas técnicas` |
| `ci:` / `chore:` | scripts, CI, arrumação do repositório | `ci: roda uma vez por PR` |

Tem ideia de hunt mas não a query pronta? Abra uma issue com o formulário **Hunt novo**. Hunt que deu erro, voltou vazio sem motivo ou trouxe ruído: formulário **Hunt com problema**.
