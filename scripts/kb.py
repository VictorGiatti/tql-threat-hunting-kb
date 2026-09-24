#!/usr/bin/env python3
"""
kb.py - ferramentas da base de hunts TQL.

Os arquivos .md em hunts/ são a fonte da verdade. Todo o resto (índice,
contadores do README e os dados do painel HTML) é gerado a partir deles, pra
que Markdown e painel nunca fiquem dessincronizados.

Uso (a partir da raiz do repositório):
    python scripts/kb.py lint    valida todas as queries (tqlcheck + regras da base)
    python scripts/kb.py test    roda tests/amostras.json contra os filtros dos hunts
    python scripts/kb.py build   regera hunts/README.md, contadores do README e dados do painel
    python scripts/kb.py check   igual ao build, mas só verifica (falha se algo estiver desatualizado)

Código de saída: 0 ok, 1 falha, 2 uso incorreto. Só usa a biblioteca padrão.
"""

import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import tqlcheck  # noqa: E402

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# Ordem das categorias no índice e no painel (segue o ciclo MITRE).
ORDER = [
    "execucao", "evasao-de-defesa", "credenciais", "persistencia",
    "escalonamento-de-privilegio", "descoberta", "movimento-lateral", "coleta",
    "rede-c2", "exfiltracao", "impacto-ransomware", "identidade", "e-mail",
    "nuvem", "firewall-3rd-party", "triagem", "visao-geral",
]

# Colunas de linha de comando: o atacante controla a caixa, então has/has_any
# (case-sensitive) deixa passar variações como IEX/iex e C$/c$.
CMD_COLUMNS = ("processCmd", "parentCmd", "objectCmd", "processFilePath", "objectFilePath")

MITRE_TOKEN = re.compile(r"^T\d{4}(\.\d{3})?$")


def path(*parts):
    return os.path.join(ROOT, *parts)


def read(rel):
    with open(path(rel), encoding="utf-8") as fh:
        return fh.read()


def write(rel, text):
    with open(path(rel), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


# ---------------------------------------------------------------------------
# Leitura dos hunts
# ---------------------------------------------------------------------------

def slugify(title):
    """Âncora no mesmo formato que o GitHub gera para um título Markdown."""
    s = title.strip().lower()
    s = re.sub(r"[^\w\- ]", "", s)
    return s.replace(" ", "-")


def category_files():
    names = [f[:-3] for f in os.listdir(path("hunts")) if f.endswith(".md") and f != "README.md"]
    extra = sorted(n for n in names if n not in ORDER)
    return [n for n in ORDER if n in names] + extra


def parse_category(name):
    rel = f"hunts/{name}.md"
    text = read(rel)
    m = re.search(r"^# (.+?) · Threat Hunting TQL\s*$", text, re.M)
    if not m:
        raise SystemExit(f"{rel}: título '# <Categoria> · Threat Hunting TQL' não encontrado")
    cat = m.group(1).strip()

    hunts, seen = [], {}
    sections = re.split(r"^## ", text, flags=re.M)[1:]
    for sec in sections:
        title, _, body = sec.partition("\n")
        title = title.strip()
        slug = slugify(title)
        seen[slug] = seen.get(slug, -1) + 1
        anchor = slug if seen[slug] == 0 else f"{slug}-{seen[slug]}"

        q = re.search(r"```text\n(.*?)\n```", body, re.S)
        mitre = re.search(r"\*\*MITRE ATT&CK:\*\*\s*(?:`([^`]+)`|(—))", body)
        nota = re.search(r"^> \*\*Limitação:\*\*\s*(.+)$", body, re.M)
        desc = ""
        for line in body.split("\n"):
            s = line.strip()
            if not s or s.startswith(("**MITRE", ">", "```", "---", "|")):
                if s.startswith("```"):
                    break
                continue
            desc = s
            break

        hunt = {
            "cat": cat,
            "mitre": (mitre.group(1) or mitre.group(2)).strip() if mitre else "—",
            "titulo": title,
            "desc": desc,
            "q": q.group(1).strip() if q else "",
        }
        if nota:
            hunt["nota"] = nota.group(1).strip()
        hunts.append({"data": hunt, "file": rel, "anchor": anchor})
    return cat, hunts


def load_all():
    cats = []
    for name in category_files():
        cat, hunts = parse_category(name)
        cats.append((name, cat, hunts))
    return cats


# ---------------------------------------------------------------------------
# lint
# ---------------------------------------------------------------------------

def code_blocks(text):
    for m in re.finditer(r"^```[a-z]*\n(.*?)^```", text, re.S | re.M):
        # rótulo mais próximo acima do bloco: título Markdown ou **negrito** no início da linha
        head = re.findall(r"^(?:#+ (.+)|\*\*(.+?)\*\*)", text[:m.start()], re.M)
        label = next((a or b for a, b in reversed(head)), "?")
        yield label.strip(), m.group(1)


def lint_query(q):
    """Devolve [(nível, mensagem)] combinando o tqlcheck com as regras da base."""
    out = []
    for f in tqlcheck.validate(q):
        level = f.level
        if level == "WARN" and "no take/top" in f.message:
            level = "ERROR"  # regra da base: todo hunt de linhas cruas tem limite
        if level == "INFO":
            continue
        loc = f"linha {f.line}: " if f.line else ""
        out.append((level, loc + f.message + (f" ({f.hint})" if f.hint else "")))
    for k, line in enumerate(q.split("\n"), 1):
        for col in CMD_COLUMNS:
            if re.search(rf"\b{col}\s+(has|has_any|has_all)\b", line):
                out.append(("ERROR", f"linha {k}: `has`/`has_any` em `{col}` é case-sensitive e perde "
                                     f"variações de caixa; use matches regex \"(?i)...\""))
    return out


def cmd_lint():
    errors = warns = total = 0
    files = [f"hunts/{n}.md" for n in category_files()] + ["consultas-de-exemplo.md", "sintaxe-e-performance.md"]
    for rel in files:
        for title, q in code_blocks(read(rel)):
            if "datasource" not in q:
                continue
            total += 1
            for level, msg in lint_query(q):
                print(f"{level:5} {rel} | {title} | {msg}")
                errors += level == "ERROR"
                warns += level == "WARN"

    titles = {}
    for _, _, hunts in load_all():
        for h in hunts:
            d = h["data"]
            titles.setdefault(d["titulo"], []).append(h["file"])
            if not d["q"]:
                print(f"ERROR {h['file']} | {d['titulo']} | hunt sem bloco ```text com a query")
                errors += 1
            if not d["desc"]:
                print(f"WARN  {h['file']} | {d['titulo']} | hunt sem descrição")
                warns += 1
            if d["mitre"] not in ("—", "pivot"):
                bad = [t for t in re.split(r"\s*/\s*", d["mitre"]) if not MITRE_TOKEN.match(t)]
                if bad:
                    print(f"WARN  {h['file']} | {d['titulo']} | técnica MITRE fora do padrão: {bad}")
                    warns += 1
    for t, where in titles.items():
        if len(where) > 1:
            print(f"ERROR título duplicado '{t}' em {where}")
            errors += 1

    print(f"\n{total} queries verificadas: {errors} erro(s), {warns} aviso(s)")
    return 1 if errors else 0


# ---------------------------------------------------------------------------
# test: amostras de linha de comando contra os filtros de cada hunt
# ---------------------------------------------------------------------------

STR = r'"(?:[^"\\]|\\.)*"'
CLAUSE = re.compile(
    rf"^\s*(\w+)\s+(contains|startswith|endswith|matches regex|has_any|has|=~|==)\s*"
    rf"({STR}|\((?:\s*{STR}\s*,?)+\))\s*$")


def unquote(lit):
    return lit[1:-1].replace('\\"', '"').replace("\\\\", "\\")


def split_top(expr, word):
    """Divide por ' or ' / ' and ' fora de aspas e parênteses."""
    parts, depth, cur, i, in_str = [], 0, "", 0, False
    token = f" {word} "
    while i < len(expr):
        ch = expr[i]
        if ch == '"' and (i == 0 or expr[i - 1] != "\\"):
            in_str = not in_str
        elif not in_str and ch == "(":
            depth += 1
        elif not in_str and ch == ")":
            depth -= 1
        if not in_str and depth == 0 and expr[i:i + len(token)] == token:
            parts.append(cur)
            cur, i = "", i + len(token)
            continue
        cur += ch
        i += 1
    parts.append(cur)
    return parts


def eval_clause(col, op, arg, value):
    if op == "has_any":
        return any(unquote(x) in value for x in re.findall(STR, arg))
    lit = unquote(arg)
    return {
        "contains": lambda: lit.lower() in value.lower(),
        "startswith": lambda: value.lower().startswith(lit.lower()),
        "endswith": lambda: value.lower().endswith(lit.lower()),
        "matches regex": lambda: re.search(lit, value) is not None,
        "has": lambda: lit in value,
        "=~": lambda: value.lower() == lit.lower(),
        "==": lambda: value == lit,
    }[op]()


def run_filters(q, sample):
    """True se a amostra passa por todos os where aplicáveis; None se nenhum se aplica."""
    applied, ok = 0, True
    for line in q.split("\n"):
        m = re.match(r"\s*\|\s*where\s+(.*)$", line)
        if not m:
            continue
        alts, usable = [], True
        for alt in split_top(m.group(1), "or"):
            conj = []
            for c in split_top(alt, "and"):
                cm = CLAUSE.match(c)
                if not cm or cm.group(1) not in sample:
                    usable = False
                    break
                conj.append(cm.groups())
            if not usable:
                break
            alts.append(conj)
        if not usable:
            continue
        applied += 1
        if not any(all(eval_clause(col, op, arg, sample[col]) for col, op, arg in conj) for conj in alts):
            ok = False
    return ok if applied else None


def cmd_test():
    cases = json.loads(read("tests/amostras.json"))
    hunts = {h["data"]["titulo"]: h["data"] for _, _, hs in load_all() for h in hs}
    cases = {t: s for t, s in cases.items() if not t.startswith("_")}
    fails = checked = 0
    for title, spec in cases.items():
        if title not in hunts:
            print(f"FALHA '{title}': hunt não existe")
            fails += 1
            continue
        q = hunts[title]["q"]
        for expect, key in ((True, "casa"), (False, "nao_casa")):
            for s in spec.get(key, []):
                sample = s if isinstance(s, dict) else {"processCmd": s}
                got = run_filters(q, sample)
                checked += 1
                if got is None:
                    print(f"FALHA '{title}': nenhum filtro se aplica às colunas {list(sample)}")
                    fails += 1
                elif got != expect:
                    verbo = "deveria casar" if expect else "não deveria casar"
                    print(f"FALHA '{title}': {verbo}: {s}")
                    fails += 1
    print(f"\n{checked} amostras em {len(cases)} hunts: {fails} falha(s)")
    return 1 if fails else 0


# ---------------------------------------------------------------------------
# build / check
# ---------------------------------------------------------------------------

def render_index(cats):
    n = sum(len(h) for _, _, h in cats)
    out = [
        "# Base de Hunts · índice",
        "",
        f"**{n} hunts** em **{len(cats)} categorias**. Ative o toggle **\"Use Trend Query Language\"** antes de rodar.",
        "",
        "> Gerado por `python scripts/kb.py build` a partir dos arquivos de cada categoria. Não edite à mão.",
        "",
        "## Por categoria",
        "",
        "| Categoria | Hunts | Arquivo |",
        "|---|--:|---|",
    ]
    for name, cat, hunts in cats:
        out.append(f"| {cat} | {len(hunts)} | [{name}.md]({name}.md) |")
    out += ["", "## Todos os hunts", "", "| Técnica (MITRE) | Hunt | Categoria |", "|---|---|---|"]
    for name, cat, hunts in cats:
        for h in hunts:
            d = h["data"]
            mitre = "—" if d["mitre"] == "—" else f"`{d['mitre']}`"
            titulo = d["titulo"].replace("|", "\\|")
            out.append(f"| {mitre} | [{titulo}]({name}.md#{h['anchor']}) | {cat} |")
    out += ["", "> Para adicionar um hunt, veja o [guia de contribuição](../CONTRIBUTING.md).", ""]
    return "\n".join(out)


def render_panel(html, cats):
    data = [h["data"] for _, _, hs in cats for h in hs]
    payload = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    payload = payload.replace("</", "<\\/")  # nunca fechar o <script> por acidente
    n, c = len(data), len(cats)
    html, k = re.subn(r"^const HUNTS=\[.*?\];$", lambda _: f"const HUNTS={payload};", html, count=1, flags=re.M | re.S)
    if k != 1:
        raise SystemExit("painel: linha 'const HUNTS=[...];' não encontrada")
    html = re.sub(r"\d+ hunts por tática", f"{n} hunts por tática", html)
    html = re.sub(r'(<b id="statHunts">)\d+(</b>)', rf"\g<1>{n}\g<2>", html)
    html = re.sub(r'(<b id="statCats">)\d+(</b>)', rf"\g<1>{c}\g<2>", html)
    return html


def render_readme(text, cats):
    n = sum(len(h) for _, _, h in cats)
    text = re.sub(r"\*\*\d+ hunts · \d+ categorias", f"**{n} hunts · {len(cats)} categorias", text)
    text = re.sub(r"Os \d+ hunts organizados", f"Os {n} hunts organizados", text)
    return text


def targets(cats):
    return {
        "hunts/README.md": render_index(cats),
        "painel/tql-threat-hunting.html": render_panel(read("painel/tql-threat-hunting.html"), cats),
        "README.md": render_readme(read("README.md"), cats),
    }


def cmd_build(check_only):
    cats = load_all()
    stale = []
    for rel, new in targets(cats).items():
        if read(rel) != new:
            stale.append(rel)
            if not check_only:
                write(rel, new)
    n = sum(len(h) for _, _, h in cats)
    if check_only:
        if stale:
            print("Desatualizado (rode `python scripts/kb.py build`):")
            for rel in stale:
                print("  -", rel)
            return 1
        print(f"ok: índice, README e painel em sincronia ({n} hunts, {len(cats)} categorias)")
        return 0
    print(f"{n} hunts em {len(cats)} categorias. Atualizados: {', '.join(stale) or 'nada'}")
    return 0


def main():
    cmds = {"lint": cmd_lint, "test": cmd_test,
            "build": lambda: cmd_build(False), "check": lambda: cmd_build(True)}
    if len(sys.argv) != 2 or sys.argv[1] not in cmds:
        print(__doc__)
        return 2
    return cmds[sys.argv[1]]()


if __name__ == "__main__":
    sys.exit(main())
