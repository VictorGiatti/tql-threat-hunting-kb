## Resumo

<!-- O que muda e por quê. Hunt novo? Correção de query? Doc? -->

## Hunts afetados

<!-- Título do hunt e arquivo. Ex.: "Tarefa agendada / serviço novo" (hunts/persistencia.md). Apague se não se aplica. -->

## Como foi verificado

- [ ] `python scripts/kb.py lint` terminou com 0 erro(s)
- [ ] `python scripts/kb.py test` terminou com 0 falha(s)
- [ ] `python scripts/kb.py build` rodado (índice, README e painel atualizados)
- [ ] Query executada no console do Vision One (diga o `log_type` e a janela usada)

## Antes de fazer merge

- [ ] Amostras em `tests/amostras.json` para hunts de linha de comando (o que deve e o que não deve casar)
- [ ] Linha `> **Limitação:**` se o hunt esbarra num limite do TQL
- [ ] Entrada no `CHANGELOG.md`, se muda resultado de hunt
