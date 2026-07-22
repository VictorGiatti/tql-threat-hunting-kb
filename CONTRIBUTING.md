# Como contribuir com hunts

[← Início da base](README.md)

A base cresce com o time. Cada hunt que funcionou no dia a dia vale a pena registrar aqui.

## Adicionar um hunt (Markdown)

1. Abra o arquivo da categoria em [`hunts/`](hunts/) (ex.: `hunts/credenciais.md`). Se a categoria não existir, crie um arquivo novo seguindo o mesmo padrão e adicione ao índice.
2. Cole um bloco no formato abaixo, separando do hunt anterior com `---`:

````markdown
## Título curto e claro do hunt

**MITRE ATT&CK:** `T1078`

Uma linha explicando o que o hunt procura e por quê.

```text
datasource("xdr")
| where eventTime > ago(7d)
| ...
```
````

3. Atualize a tabela em [`hunts/README.md`](hunts/README.md) (linha na lista "Todos os hunts" e a contagem por categoria).

### Padrão de qualidade

- **Título** direto (o que ele acha), não o comando.
- **MITRE** quando fizer sentido; use `—` se não se aplicar.
- **Descrição** de uma linha.
- **Query** testada, com aspas retas (`"`), começando por `datasource(...)` e com janela de tempo. Sem comentários no meio da query.
- Prefira `with (log_type=…, product_code=…)` e `project` cedo (ver [sintaxe-e-performance.md](sintaxe-e-performance.md)).

## Alternativa: prototipar no painel e exportar

Se preferir montar visualmente antes de escrever o Markdown:

1. Abra [`painel/tql-threat-hunting.html`](painel/tql-threat-hunting.html) no navegador.
2. Clique em **+ Adicionar hunt**, preencha e salve (fica guardado no seu navegador).
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

4. Cole o JSON no Pull Request (ou mande pro mantenedor), dá pra converter em Markdown e embutir na base fixa.

## Fluxo git sugerido

```bash
git checkout -b hunt/nome-curto
# edite os arquivos
git add .
git commit -m "hunt: <categoria> - <título>"
git push -u origin hunt/nome-curto
# abra um Pull Request para revisão
```
