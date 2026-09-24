#!/usr/bin/env python3
"""
tqlcheck - static validator for TrendAI Query Language (TQL) queries.

TQL is the query language of Trend Vision One XDR Data Explorer. It looks like
KQL, which is exactly the problem: a model or an analyst who knows KQL will
confidently write operators TQL does not have, and TQL's usual response to a
bad column or an unsupported operation is an empty result set rather than an
error. An empty result reads like "no threat found", so a wrong query is
indistinguishable from a clean environment. That is the failure this script
exists to prevent.

Usage:
    python tqlcheck.py query.tql
    python tqlcheck.py --stdin < query.tql
    echo '<query>' | python tqlcheck.py --stdin
    python tqlcheck.py --self-test        # run built-in cases

Exit codes:
    0  no errors (warnings may still be printed)
    1  at least one ERROR
    2  usage problem
"""

import argparse
import re
import sys

# ---------------------------------------------------------------------------
# Ground truth
# ---------------------------------------------------------------------------

# Pipeline operators that are documented or field-verified as working.
KNOWN_OPERATORS = {
    "where", "project", "extend", "sort", "order", "top", "take", "distinct",
    "summarize", "union", "join", "mv-expand", "partition", "render", "count",
}

# Scalar and aggregation functions that are documented or field-verified.
KNOWN_FUNCTIONS = {
    # documented
    "ago", "datetime", "bin", "isnull", "isempty", "isnotempty", "not",
    "count", "countif", "dcount", "sum", "avg", "min", "max", "minif", "maxif",
    "make_list", "make_set", "take_any",
    # field-verified but undocumented
    "coalesce", "replace_string", "split", "strcat", "array_length",
    "make_set_if", "set_intersect", "set_union", "tostring",
    # structural
    "datasource", "with",
}

# Things that exist in KQL or SPL and do NOT exist in TQL. A model trained on
# KQL will reach for these by reflex. Each maps to what to do instead.
NOT_IN_TQL = {
    "scan": "no stateful row-by-row operator; aggregate with summarize instead",
    "row_window_session": "not available; use summarize with bin()",
    "make-series": "not available; use summarize ... by bin(eventTime, <interval>)",
    "series_outliers": "no anomaly functions; compute the comparison outside TQL",
    "series_fir": "no series functions in TQL",
    "series_stats": "no series functions in TQL",
    "autocluster": "no evaluate/ML plugins in TQL",
    "evaluate": "no plugin operator in TQL",
    "mv-apply": "not available; use mv-expand then where",
    "datatable": "no inline table generation; test against a real dataset with take",
    "print": "no scalar print; test against a real dataset with take",
    "makeresults": "Splunk, not TQL",
    "parse": "no parse operator; TQL cannot extract with regex, only filter",
    "parse_json": "not available",
    "extract": "no regex extraction in TQL; matches regex only filters",
    "extract_all": "no regex extraction in TQL",
    "base64_decode_tostring": "no decoders in TQL",
    "base64_decode": "no decoders in TQL",
    "base64_encode_tostring": "no decoders in TQL",
    "url_decode": "no decoders in TQL",
    "url_encode": "no decoders in TQL",
    "ipv4_is_in_range": "no CIDR support in TQL; enumerate prefixes with startswith or has_any",
    "ipv4_is_private": "no CIDR/IP helpers in TQL",
    "ipv6_is_in_range": "no CIDR support in TQL",
    "cidr": "CQL, not TQL; no CIDR support",
    "cidrmatch": "Splunk, not TQL; no CIDR support",
    "jaro_winkler_similarity": "no fuzzy matching in TQL",
    "levenshtein": "no fuzzy matching in TQL",
    "hash_md5": "no hash functions in TQL",
    "hash_sha256": "no hash functions in TQL",
    "md5": "no hash functions in TQL",
    "sha256": "no hash functions in TQL",
    "fillnull": "Splunk; use coalesce() per column",
    "rex": "Splunk, not TQL",
    "eval": "Splunk; use extend",
    "stats": "Splunk; use summarize",
    "table": "Splunk; use project",
    "lookup": "Splunk; no external lookups in TQL",
    "foreach": "no iteration in TQL",
    "addinfo": "Splunk; TQL does not expose search metadata",
    "chart": "Splunk; no pivot in TQL",
    "map": "Splunk; no parameterised subsearch in TQL",
    "materialize": "not available in TQL",
    "toscalar": "not available in TQL",
    "range": "not available in TQL",
    "externaldata": "not available in TQL",
    "lower": "not verified in TQL; avoid, TQL string matching is already case-insensitive",
    "toupper": "not verified in TQL; use =~ or contains for case-insensitive matching",
    "tolower": "not verified in TQL; use =~ or contains for case-insensitive matching",
    "strlen": "not verified in TQL",
    "substring": "not verified in TQL; use split()",
    "trim": "broken in the TQL parser for a lone escaped quote (see traps.md)",
    "trim_start": "broken in the TQL parser for a lone escaped quote (see traps.md)",
    "trim_end": "broken in the TQL parser for a lone escaped quote (see traps.md)",
}

# join kinds TQL documents. leftanti in particular is the one people assume.
VALID_JOIN_KINDS = {"inner", "leftouter", "rightouter"}

# bin() accepts exactly these six intervals. Anything else is a validation error
# in the product itself, so catching it here saves a round trip to the console.
VALID_BIN_INTERVALS = {"1s", "1m", "1h", "1d", "7d", "30d"}

# ago() accepts these units only.
VALID_AGO_UNITS = {"s", "m", "h", "d"}

# Columns published as type `dynamic` in the Vision One schema, plus clientIp,
# which the schema calls a string but which behaves as dynamic in the field.
# `matches regex` silently returns nothing against these.
DYNAMIC_COLUMNS = {
    "src", "dst", "act", "tags", "archFiles", "interestedIp", "peerIp",
    "clientIp", "endpointIp", "mailThreatTypes", "mailSmtpRecipients",
    "mailSmtpFromAddresses", "objectIp",
}

# Chart types verified with the render operator.
VALID_RENDER_TYPES = {"linechart", "columnchart", "barchart", "piechart", "table", "timechart"}


class Finding:
    def __init__(self, level, line, message, hint=None):
        self.level = level          # "ERROR" | "WARN" | "INFO"
        self.line = line
        self.message = message
        self.hint = hint

    def __str__(self):
        loc = f"line {self.line}" if self.line else "query"
        out = f"  [{self.level}] {loc}: {self.message}"
        if self.hint:
            out += f"\n           -> {self.hint}"
        return out


def strip_strings_and_comments(text):
    """Blank out string literals and // comments so keyword scanning does not
    trip over data. Preserves line and column positions."""
    out = list(text)
    i, n = 0, len(text)
    in_str = False
    while i < n:
        ch = text[i]
        if in_str:
            if ch == "\\" and i + 1 < n:
                out[i] = " "
                out[i + 1] = " "
                i += 2
                continue
            if ch == '"':
                in_str = False
            else:
                out[i] = " "
            i += 1
            continue
        if ch == '"':
            in_str = True
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                out[i] = " "
                i += 1
            continue
        i += 1
    return "".join(out)


def validate(query):
    findings = []
    lines = query.split("\n")
    clean = strip_strings_and_comments(query)
    clean_lines = clean.split("\n")

    def add(level, line, msg, hint=None):
        findings.append(Finding(level, line, msg, hint))

    # --- structural: quotes and parens ---------------------------------------
    if query.count('"') % 2 != 0:
        add("ERROR", None, "unbalanced double quotes",
            "every string literal must open and close with \"")
    depth = clean.count("(") - clean.count(")")
    if depth != 0:
        add("ERROR", None,
            f"unbalanced parentheses ({'+' if depth > 0 else ''}{depth})")
    if clean.count("[") != clean.count("]"):
        add("ERROR", None, "unbalanced square brackets")

    # --- the query must name a dataset ---------------------------------------
    if not re.search(r'\bdatasource\s*\(', clean):
        add("ERROR", 1, "query does not declare a dataset",
            'start with datasource("xdr") with (log_type="...", product_code="...")')
    else:
        first_code = next((k + 1 for k, l in enumerate(clean_lines) if l.strip()), 1)
        if not clean_lines[first_code - 1].lstrip().startswith(("datasource", "let")):
            add("WARN", first_code,
                "datasource() should open the query (let statements may precede it)")
        if not re.search(r'datasource\s*\(\s*"', query):
            add("ERROR", first_code, 'datasource() argument must be a quoted string, e.g. datasource("xdr")')
        if "with" not in clean:
            # A bare datasource("xdr") is a legitimate style when the query
            # narrows by eventCategory instead, which is how most endpoint
            # hunts are written. Still worth mentioning: log_type and
            # product_code are free filters.
            if re.search("eventCategory", clean):
                add("INFO", first_code,
                    "narrowed by eventCategory rather than with (log_type=..., product_code=...)",
                    "fine, but adding log_type/product_code is free and cuts the scan further")
            else:
                add("WARN", first_code,
                    "no with (log_type=..., product_code=...) and no eventCategory filter",
                    "both are optional but they are free filters; without either, the scan is far slower")

    # --- a time filter is not optional in practice ---------------------------
    if not re.search(r'\bago\s*\(|\bbetween\s*\(|\bdatetime\s*\(', clean):
        add("ERROR", None, "no time filter on the query",
            "add | where eventTime > ago(1d); an unbounded scan will time out or be truncated")

    # --- ago() units ---------------------------------------------------------
    for k, line in enumerate(clean_lines, 1):
        for m in re.finditer(r'\bago\s*\(\s*(\d+)\s*([a-zA-Z]+)\s*\)', line):
            unit = m.group(2)
            if unit not in VALID_AGO_UNITS:
                bigger = {"w": "7d", "mo": "30d", "y": "365d"}
                hint = f"use {bigger[unit]}" if unit in bigger else "use s, m, h or d"
                add("ERROR", k, f"ago() unit '{unit}' is not accepted", hint)

    # --- bin() intervals -----------------------------------------------------
    for k, line in enumerate(clean_lines, 1):
        for m in re.finditer(r'\bbin\s*\(([^)]*)\)', line):
            args = m.group(1).split(",")
            if len(args) >= 2:
                iv = args[-1].strip()
                if iv and iv not in VALID_BIN_INTERVALS:
                    add("ERROR", k,
                        f"bin() interval '{iv}' is a validation error in TQL",
                        "bin() accepts only 1s, 1m, 1h, 1d, 7d, 30d")
        # a bin() used as a grouping key must be named
        for m in re.finditer(r'\bby\b([^|]*)', line):
            seg = m.group(1)
            for bm in re.finditer(r'(^|,)\s*bin\s*\(', seg):
                add("WARN", k, "bin() in a `by` list should be given a name",
                    "write: by hour = bin(eventTime, 1h)")

    # --- logical operators ---------------------------------------------------
    for k, line in enumerate(clean_lines, 1):
        if "&&" in line:
            add("ERROR", k, "&& is not a TQL operator", "use `and`")
        if "||" in line:
            add("ERROR", k, "|| is not a TQL operator", "use `or`")
        if re.search(r'(?<![!<>=])!\s*(?=[A-Za-z_(])', line) and not re.search(r'!\s*(in|between)\b', line):
            add("WARN", k, "`!` as negation is not TQL", "use not(...), != or !in")
        if re.search(r'\bGROUP\s+BY\b', line, re.I):
            add("ERROR", k, "TQL has no GROUP BY", "aggregate with summarize ... by ...")

    # --- pipeline operators --------------------------------------------------
    for k, line in enumerate(clean_lines, 1):
        m = re.match(r'\s*\|\s*([A-Za-z_][\w-]*)', line)
        if not m:
            continue
        op = m.group(1)
        if op in NOT_IN_TQL:
            add("ERROR", k, f"`{op}` does not exist in TQL", NOT_IN_TQL[op])
        elif op not in KNOWN_OPERATORS:
            add("WARN", k, f"`{op}` is not a verified TQL operator",
                "if this is real, confirm it in the console before shipping the query")

    # --- function calls ------------------------------------------------------
    for k, line in enumerate(clean_lines, 1):
        for m in re.finditer(r'\b([A-Za-z_][\w]*)\s*\(', line):
            fn = m.group(1)
            # Skip keywords and operators that are followed by a parenthesised
            # list rather than being function calls, plus the join kinds, which
            # appear as `join kind=leftanti (Other)`.
            if fn in ("if", "and", "or", "not", "in", "by", "where", "on", "kind", "with",
                      "render", "has_any", "has_all", "has", "regex", "contains", "between",
                      "inner", "leftouter", "rightouter", "leftanti", "rightanti",
                      "leftsemi", "rightsemi", "anti"):
                continue
            if fn in NOT_IN_TQL:
                add("ERROR", k, f"`{fn}()` does not exist in TQL", NOT_IN_TQL[fn])
            elif fn not in KNOWN_FUNCTIONS:
                add("WARN", k, f"`{fn}()` is not in the verified TQL function list",
                    "verify in the console; TQL returns an empty set rather than an error")

    # --- join kinds ----------------------------------------------------------
    for k, line in enumerate(clean_lines, 1):
        for m in re.finditer(r'\bjoin\s+kind\s*=\s*([A-Za-z]+)', line):
            kind = m.group(1)
            if kind not in VALID_JOIN_KINDS:
                extra = ""
                if kind in ("leftanti", "rightanti", "anti", "leftsemi", "rightsemi"):
                    extra = ("; TQL has no anti/semi join. Emulate with "
                             "join kind=leftouter then | where isnull(<rightColumn>)")
                add("ERROR", k, f"join kind={kind} is not supported by TQL{extra}",
                    "supported: inner, leftouter, rightouter")
        if re.search(r'\bjoin\b', line) and not re.search(r'\bkind\s*=', line):
            add("WARN", k, "join without an explicit kind=", "state kind=inner or kind=leftouter")

    # --- regex against dynamic columns ---------------------------------------
    for k, line in enumerate(clean_lines, 1):
        for m in re.finditer(r'\b([A-Za-z_][\w]*)\s+matches\s+regex\b', line):
            col = m.group(1)
            if col in DYNAMIC_COLUMNS:
                add("ERROR", k,
                    f"`matches regex` does not work on `{col}`, which is a dynamic column",
                    "this returns nothing rather than an error. Use a string-typed column "
                    "(for IPs try eventDataIpAddress), or filter with has / has_any")

    # --- contains on array-ish columns ---------------------------------------
    for k, line in enumerate(clean_lines, 1):
        for m in re.finditer(r'\b([A-Za-z_][\w]*)\s+contains\b', line):
            col = m.group(1)
            if col in DYNAMIC_COLUMNS:
                add("WARN", k, f"`contains` on array column `{col}` is unreliable",
                    "use `has` for a single value or `has_any (...)` for several")

    # --- the quote-escaping defect -------------------------------------------
    if re.search(r'"\s*\\"\s*"', query):
        add("ERROR", None,
            'a string literal containing only an escaped double quote ("\\"") '
            "is mishandled by the TQL parser",
            "known defect: the escape works only when followed by more characters. "
            "Avoid stripping a lone quote; filter with contains instead")

    # --- free-text search reflex ---------------------------------------------
    for k, line in enumerate(clean_lines, 1):
        if re.match(r'\s*search\b', line) or re.match(r'\s*\|\s*search\b', line):
            add("ERROR", k, "TQL has no free-text `search` operator",
                "name the column explicitly, or or-chain the candidate columns")

    # --- render --------------------------------------------------------------
    for k, line in enumerate(clean_lines, 1):
        m = re.search(r'\|\s*render\s+([A-Za-z]+)', line)
        if m and m.group(1) not in VALID_RENDER_TYPES:
            add("WARN", k, f"render type `{m.group(1)}` is not verified",
                "verified: " + ", ".join(sorted(VALID_RENDER_TYPES)))

    # --- result hygiene ------------------------------------------------------
    has_agg = bool(re.search(r'\|\s*(summarize|distinct|render)\b', clean))
    has_cap = bool(re.search(r'\|\s*(take|top)\b', clean))
    if not has_agg and not has_cap:
        add("WARN", None, "no take/top on a non-aggregating query",
            "cap the result, e.g. | take 100, so the console does not truncate silently")

    if re.search(r'\|\s*project\b', clean):
        proj = clean.index("| project") if "| project" in clean else None
        srt = clean.index("| sort") if "| sort" in clean else None
        if proj is not None and srt is not None and srt < proj:
            add("INFO", None, "sorting before project costs more than sorting after",
                "recommended order: filter, project, expensive filters, sort/top")

    return findings


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

GOOD = [
    # straight endpoint hunt
    'datasource("xdr")\n| where eventCategory == "DeviceProcessEvents"\n'
    '| where eventTime > ago(7d)\n| project eventTime, endpointHostName, processCmd\n'
    '| where processCmd has_any ("-enc", "IEX")\n| sort by eventTime desc\n| take 100',
    # aggregation with a named bin and a chart
    'datasource("xdr") with (log_type="identitytel", product_code="aad")\n'
    '| where eventTime > ago(1d)\n| where eventName == "IDENTITY_IAM_SIGN_INS"\n'
    '| summarize total = count() by hora = bin(eventTime, 1h)\n| sort by hora asc\n'
    '| render linechart with (xtitle="Hora", ytitle="Sign-ins")',
    # array expansion
    'datasource("xdr") with (log_type="messaging")\n| where eventTime > ago(7d)\n'
    '| where array_length(mailThreatTypes) > 0\n| mv-expand ameaca = mailThreatTypes\n'
    '| summarize total = count() by tipo = tostring(ameaca)\n| top 20 by total desc',
]

BAD = [
    # KQL reflexes that TQL does not have
    ('datasource("xdr")\n| where eventTime > ago(1d)\n| extend p = base64_decode_tostring(cmd)\n| take 10',
     "base64"),
    ('datasource("xdr")\n| where eventTime > ago(1d)\n| summarize c = count() by bin(eventTime, 5m)',
     "5m"),
    ('datasource("xdr")\n| where eventTime > ago(2w)\n| take 10', "ago"),
    ('datasource("xdr")\n| where eventTime > ago(1d)\n| where src matches regex "^10\\."\n| take 10',
     "dynamic"),
    ('network\n| join kind=leftanti (edr) on endpointHostName\n| where eventTime > ago(1d)', "leftanti"),
    ('datasource("xdr")\n| where eventTime > ago(1d) && severity >= 8\n| take 5', "&&"),
    ('datasource("xdr")\n| where eventTime > ago(1d)\n| take 10\n| GROUP BY host', "GROUP BY"),
    ('search "192.168.1.50"', "search"),
]


def self_test():
    ok = True
    print("== queries that must pass ==")
    for q in GOOD:
        errs = [f for f in validate(q) if f.level == "ERROR"]
        label = "PASS" if not errs else "FAIL"
        if errs:
            ok = False
        print(f"  [{label}] {q.splitlines()[0][:60]}")
        for e in errs:
            print(e)
    print("\n== queries that must be caught ==")
    for q, needle in BAD:
        errs = [f for f in validate(q) if f.level == "ERROR"]
        hit = any(needle.lower() in (e.message + (e.hint or "")).lower() for e in errs)
        if not hit:
            ok = False
        print(f"  [{'PASS' if hit else 'FAIL'}] expected a '{needle}' error -> "
              f"{'caught' if hit else 'MISSED'}")
        if not hit:
            for e in errs:
                print(e)
    print("\nself-test:", "OK" if ok else "FAILURES")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description="Validate a TQL query.")
    ap.add_argument("file", nargs="?", help="file containing the query")
    ap.add_argument("--stdin", action="store_true", help="read the query from stdin")
    ap.add_argument("--self-test", action="store_true", help="run built-in test cases")
    ap.add_argument("--quiet", action="store_true", help="print errors only")
    args = ap.parse_args()

    if args.self_test:
        sys.exit(self_test())

    if args.stdin:
        query = sys.stdin.read()
    elif args.file:
        with open(args.file, encoding="utf-8") as fh:
            query = fh.read()
    else:
        ap.print_help()
        sys.exit(2)

    if not query.strip():
        print("empty query")
        sys.exit(2)

    findings = validate(query)
    errors = [f for f in findings if f.level == "ERROR"]
    warns = [f for f in findings if f.level == "WARN"]
    infos = [f for f in findings if f.level == "INFO"]

    if not findings:
        print("OK - no findings")
        sys.exit(0)

    for f in errors:
        print(f)
    if not args.quiet:
        for f in warns + infos:
            print(f)

    print(f"\n{len(errors)} error(s), {len(warns)} warning(s)")
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
