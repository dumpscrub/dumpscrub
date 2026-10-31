#!/usr/bin/env python3
"""dumpscrub — zero-config, flat-file SQL dump anonymizer (streaming).

Pipe a dump in, get a safe dump out:

    cat prod.sql | dumpscrub > staging.sql
    dumpscrub prod.sql -o staging.sql --report scrub-report.json
    dumpscrub --dry-run --fail-on-pii < prod.sql   # CI gate, writes nothing

Dialects: PostgreSQL (pg_dump, both INSERT and COPY formats), MySQL (mysqldump),
SQLite (.dump). No database connection. No YAML. SQL comments are stripped.

Overrides (no dependencies):

    dumpscrub --ignore users.phone --mask users.middle_name=full_name
    echo '{"ignore":["audit_log.message"]}' > .dumpscrub.json

This is the core engine of the MVP. The paid tier is the audit-evidence report
(`--report`) plus the CI gate — never the algorithm itself.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import random
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

__version__ = "1.0.2"

# --------------------------------------------------------------------------- #
# PII detection (column-name heuristics)
# --------------------------------------------------------------------------- #

_RESERVED = {
    "CONSTRAINT", "PRIMARY", "UNIQUE", "FOREIGN", "KEY", "CHECK", "INDEX", "LIKE",
}

# Boundaries use (?<![a-z0-9]) / (?![a-z0-9]) rather than \b: underscores count as
# separators, so "user_ip" matches `ip` while "ship_address" does NOT (the "ip" is
# glued to a letter), which keeps address columns from being misread as IPs.
_L = r"(?<![a-z0-9])"
_R = r"(?![a-z0-9])"

COLUMN_RULES: List[Tuple[str, "re.Pattern[str]"]] = [
    ("email", re.compile(_L + r"e[-_]?mail" + _R, re.I)),
    ("ssn", re.compile(_L + r"(ssn|social_?security)" + _R, re.I)),
    ("credit_card", re.compile(_L + r"(credit_?card|card_?number|cc_?num|pan)" + _R, re.I)),
    ("phone", re.compile(_L + r"(phone|mobile|cell|telephone|tel_?no)" + _R, re.I)),
    ("ip_address", re.compile(_L + r"(ip|ip_?addr(?:ess)?|last_?ip|remote_?ip)" + _R, re.I)),
    ("first_name", re.compile(_L + r"(first_?name|given_?name|fname)" + _R, re.I)),
    ("last_name", re.compile(_L + r"(last_?name|surname|family_?name|lname)" + _R, re.I)),
    ("full_name", re.compile(r"^(full_?name|name|display_?name|contact_?name|company_?name)$", re.I)),
    ("street_address", re.compile(_L + r"(street|address|addr|line1)" + _R, re.I)),
    ("city", re.compile(_L + r"(city|town)" + _R, re.I)),
    ("postal_code", re.compile(_L + r"(zip|postal|postcode)" + _R, re.I)),
    ("date_of_birth", re.compile(_L + r"(dob|birth_?date|date_?of_?birth)" + _R, re.I)),
    ("username", re.compile(_L + r"(username|user_?name|handle|login)" + _R, re.I)),
    ("secret", re.compile(_L + r"(password|passwd|pwd|secret|token|api_?key|auth_?key)" + _R, re.I)),
]

KNOWN_KINDS = {name for name, _ in COLUMN_RULES}

_FIRST = ["Avery", "Jordan", "Riley", "Casey", "Morgan", "Quinn",
          "Rowan", "Sage", "Emerson", "Finley", "Harper", "Reese"]
_LAST = ["Nakamura", "Okafor", "Delgado", "Bergstrom", "Whitfield",
         "Rasmussen", "Ibarra", "Kowalski", "Bhatt", "Moreau"]
_STREETS = ["Maple", "Cedar", "Birch", "Juniper", "Sycamore", "Alder", "Willow", "Poplar"]
_DOMAINS = ["example.com", "example.org", "example.net", "mail.test"]
_EMAIL_ADJ = ["swift", "calm", "bright", "quiet", "north", "harbor", "atlas", "violet"]
_CITIES = ["Springfield", "Riverton", "Fairview", "Ashland", "Cedar Hill"]


def detect_kind(column: Optional[str]) -> Optional[str]:
    """Return the masking strategy for a column name, or None if not PII-like."""
    if not column:
        return None
    for kind, pattern in COLUMN_RULES:
        if pattern.search(column):
            return kind
    return None


# --------------------------------------------------------------------------- #
# Deterministic fake generation
# --------------------------------------------------------------------------- #

def _digest(table: str, column: str, raw: str, salt: str) -> bytes:
    return hashlib.sha256(f"{salt}\x00{table}\x00{column}\x00{raw}".encode("utf-8")).digest()


def make_fake(kind: str, table: str, column: str, raw: str, salt: str) -> str:
    """Deterministically map a raw value to a synthetic replacement.

    Same (table, column, raw) always yields the same fake, which keeps the output
    reproducible and referentially consistent across tables.
    """
    digest = _digest(table, column, raw, salt)
    rnd = random.Random(int.from_bytes(digest[:8], "big"))

    if kind == "email":
        local = f"{rnd.choice(_EMAIL_ADJ)}.{rnd.choice(_FIRST).lower()}{rnd.randint(1, 99)}"
        return f"{local}@{rnd.choice(_DOMAINS)}"
    if kind == "first_name":
        return rnd.choice(_FIRST)
    if kind == "last_name":
        return rnd.choice(_LAST)
    if kind == "full_name":
        return f"{rnd.choice(_FIRST)} {rnd.choice(_LAST)}"
    if kind == "phone":
        return f"+1555{rnd.randint(1000000, 9999999)}"
    if kind == "ssn":
        # 900-999 area numbers are never issued, so these are provably fake.
        return f"9{rnd.randint(10, 99):02d}{rnd.randint(10, 99):02d}{rnd.randint(1000, 9999)}"
    if kind == "credit_card":
        return "4111111111111111"  # well-known test PAN
    if kind == "ip_address":
        return f"10.{rnd.randint(0, 255)}.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}"
    if kind == "street_address":
        return f"{rnd.randint(1, 9999)} {rnd.choice(_STREETS)} St"
    if kind == "city":
        return rnd.choice(_CITIES)
    if kind == "postal_code":
        return f"{rnd.randint(10000, 99999)}"
    if kind == "date_of_birth":
        return f"{rnd.randint(1950, 2005)}-{rnd.randint(1, 12):02d}-{rnd.randint(1, 28):02d}"
    if kind == "username":
        return f"user_{digest[:4].hex()}"
    if kind == "secret":
        return f"REDACTED_{digest[:6].hex()}"
    return f"REDACTED_{digest[:6].hex()}"


def quote_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def strip_literal(value: str) -> str:
    """Return the inner text of a single- or double-quoted SQL literal."""
    value = value.strip()
    if len(value) >= 2 and value[0] in ("'", '"') and value[-1] == value[0]:
        quote = value[0]
        inner = value[1:-1]
        inner = inner.replace(quote + quote, quote)
        inner = inner.replace("\\" + quote, quote)
        return inner
    return value


# --------------------------------------------------------------------------- #
# COPY (text format) escaping
# --------------------------------------------------------------------------- #

_COPY_UNESCAPE = {"t": "\t", "n": "\n", "r": "\r", "\\": "\\"}


def escape_copy(value: str) -> str:
    """Escape a value for the tab-delimited COPY text format."""
    return (
        value.replace("\\", "\\\\")
        .replace("\t", "\\t")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


def unescape_copy(value: str) -> str:
    return re.sub(
        r"\\(.)",
        lambda m: _COPY_UNESCAPE.get(m.group(1), m.group(1)),
        value,
    )


# --------------------------------------------------------------------------- #
# Low-level SQL tokenizers
# --------------------------------------------------------------------------- #

def split_top_commas(text: str) -> List[str]:
    """Split on commas that are not inside parens, quotes, or backticks."""
    parts: List[str] = []
    current: List[str] = []
    depth = 0
    state: Optional[str] = None
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if state is not None:
            current.append(ch)
            if ch == "\\" and state in ("'", '"') and i + 1 < n:
                current.append(text[i + 1]); i += 2; continue
            if ch == state:
                if i + 1 < n and text[i + 1] == state:
                    current.append(state); i += 2; continue
                state = None
            i += 1
            continue
        if ch in ("'", '"', "`"):
            state = ch; current.append(ch); i += 1; continue
        if ch == "(":
            depth += 1; current.append(ch); i += 1; continue
        if ch == ")":
            depth -= 1; current.append(ch); i += 1; continue
        if ch == "," and depth == 0:
            parts.append("".join(current)); current = []; i += 1; continue
        current.append(ch); i += 1
    if current:
        parts.append("".join(current))
    return parts


def split_tuples(text: str) -> Tuple[List[str], str]:
    """Return the top-level (...) tuples in a VALUES clause plus any trailing text."""
    tuples: List[str] = []
    current: List[str] = []
    depth = 0
    state: Optional[str] = None
    end = 0
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if state is not None:
            current.append(ch)
            if ch == "\\" and state in ("'", '"') and i + 1 < n:
                current.append(text[i + 1]); i += 2; continue
            if ch == state:
                if i + 1 < n and text[i + 1] == state:
                    current.append(state); i += 2; continue
                state = None
            i += 1
            continue
        if ch in ("'", '"', "`"):
            state = ch; current.append(ch); i += 1; continue
        if ch == "(":
            if depth == 0:
                current = []
            else:
                current.append(ch)
            depth += 1; i += 1; continue
        if ch == ")":
            depth -= 1
            if depth == 0:
                tuples.append("".join(current)); end = i + 1
                i += 1; continue
            current.append(ch); i += 1; continue
        if depth > 0:
            current.append(ch)
        i += 1
    return tuples, text[end:]


def split_values(tuple_text: str) -> List[str]:
    """Split a single tuple body into raw value tokens (top-level commas only)."""
    return split_top_commas(tuple_text)


# --------------------------------------------------------------------------- #
# Unit iterator: SQL statements + native COPY blocks
# --------------------------------------------------------------------------- #

COPY_HEADER_RE = re.compile(
    r"^COPY\s+(?P<table>[`\"\w\.]+)\s*(?:\((?P<cols>[^)]*)\))?\s+FROM\s+stdin\s*;?\s*$",
    re.I | re.S,
)


def iter_units(lines: Iterable[str]) -> Iterator[Tuple]:
    """Yield processing units from a stream of text chunks (usually lines).

    Units:
      ("sql", statement_text)
      ("copy_header", statement_text, table, columns_or_None)
      ("copy_row", raw_line)          # streamed one row at a time
      ("copy_end", terminator_line)

    Strips line (`--`, `#`) and block (`/* */`) comments, but COPY data is read
    verbatim so tabs, backslashes, and `--` inside data are never touched.
    """
    it = iter(lines)
    buf: List[str] = []
    state: Optional[str] = None
    block_comment = False
    while True:
        line = next(it, None)
        if line is None:
            break
        i, n = 0, len(line)
        while i < n:
            ch = line[i]
            if block_comment:
                if ch == "*" and i + 1 < n and line[i + 1] == "/":
                    block_comment = False; i += 2
                else:
                    i += 1
                continue
            if state is None:
                if ch == "-" and i + 1 < n and line[i + 1] == "-":
                    buf.append("\n"); break
                if ch == "#":
                    buf.append("\n"); break
                if ch == "/" and i + 1 < n and line[i + 1] == "*":
                    block_comment = True; i += 2; continue
                if ch in ("'", '"', "`"):
                    state = ch; buf.append(ch); i += 1; continue
                if ch == ";":
                    buf.append(ch)
                    statement = "".join(buf); buf = []
                    i += 1
                    match = COPY_HEADER_RE.match(statement.strip())
                    if match:
                        # Keep the header's trailing newline so the emitted block is
                        # still loadable by psql (header and data stay on separate lines).
                        statement += line[i:]
                        i = n
                        table = unquote_ident(match.group("table")).split(".")[-1]
                        cols_raw = match.group("cols")
                        columns = (
                            [unquote_ident(c) for c in split_top_commas(cols_raw) if c.strip()]
                            if cols_raw else None
                        )
                        yield ("copy_header", statement, table, columns)
                        while True:
                            data_line = next(it, None)
                            if data_line is None:
                                break
                            if data_line.rstrip("\n").rstrip("\r") == "\\.":
                                yield ("copy_end", data_line)
                                break
                            yield ("copy_row", data_line)
                    else:
                        yield ("sql", statement)
                    continue
                buf.append(ch); i += 1
            else:
                buf.append(ch)
                if ch == "\\" and state in ("'", '"'):
                    if i + 1 < n:
                        buf.append(line[i + 1]); i += 2; continue
                    i += 1; continue
                if ch == state:
                    if i + 1 < n and line[i + 1] == state:
                        buf.append(state); i += 2; continue
                    state = None
                i += 1
    if buf:
        yield ("sql", "".join(buf))


# --------------------------------------------------------------------------- #
# CREATE TABLE / INSERT / COPY handling
# --------------------------------------------------------------------------- #

CREATE_RE = re.compile(
    r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?P<name>[`\"\w\.]+)\s*\((?P<body>.*)\)",
    re.I | re.S,
)
COLUMN_RE = re.compile(
    r'^[`"\[]?(?P<col>[A-Za-z_][A-Za-z0-9_]*)[`"\]]?\s+(?P<rest>[A-Za-z].*)$',
    re.S,
)
INSERT_RE = re.compile(
    r"^(?P<prefix>INSERT\s+INTO\s+(?P<table>[`\"\w\.]+)(?:\s*\((?P<cols>[^)]*)\))?"
    r"\s+VALUES\s+)(?P<rest>.*)$",
    re.I | re.S,
)


def unquote_ident(ident: str) -> str:
    ident = ident.strip()
    if ident and ident[0] in ("`", '"', "["):
        return ident.strip('`"[]')
    return ident


def register_table(statement: str, schema: Dict[str, List[str]]) -> bool:
    match = CREATE_RE.search(statement)
    if not match:
        return False
    name = unquote_ident(match.group("name")).split(".")[-1]
    columns: List[str] = []
    for part in split_top_commas(match.group("body")):
        col_match = COLUMN_RE.match(part.strip())
        if not col_match:
            continue
        column = col_match.group("col")
        if column.upper() in _RESERVED:
            continue
        columns.append(column)
    schema[name] = columns
    return True


def scrub_insert(
    body: str,
    schema: Dict[str, List[str]],
    salt: str,
    counters: Dict[Tuple[str, str, str], int],
    resolver: "RuleResolver",
) -> Tuple[str, int]:
    """Rewrite one INSERT statement. Returns (new_body, rows_processed)."""
    match = INSERT_RE.match(body)
    if not match:
        return body, 0

    table = unquote_ident(match.group("table")).split(".")[-1]
    cols_raw = match.group("cols")
    if cols_raw:
        columns = [unquote_ident(c) for c in split_top_commas(cols_raw) if c.strip()]
    else:
        columns = schema.get(table, [])

    rest = match.group("rest")
    stripped = rest.rstrip()
    trailing_ws = rest[len(stripped):]
    terminator = ""
    if stripped.endswith(";"):
        terminator = ";"
        stripped = stripped[:-1].rstrip()

    tuples, suffix = split_tuples(stripped)
    if not tuples:
        return body, 0

    new_tuples: List[str] = []
    for tuple_text in tuples:
        values = split_values(tuple_text)
        out: List[str] = []
        for index, value in enumerate(values):
            column = columns[index] if index < len(columns) else None
            kind = resolver.resolve(table, column) if column else None
            if kind and value.strip().upper() != "NULL":
                raw = strip_literal(value)
                fake = make_fake(kind, table, column or "", raw, salt)
                if value.strip()[:1] in ("'", '"'):
                    out.append(quote_literal(fake))
                elif re.fullmatch(r"-?\d+", fake):
                    out.append(fake)
                else:
                    out.append(quote_literal(fake))
                key = (table, column or "", kind)
                counters[key] = counters.get(key, 0) + 1
            else:
                out.append(value.strip())
        new_tuples.append("(" + ", ".join(out) + ")")

    rebuilt = match.group("prefix") + ", ".join(new_tuples) + suffix + terminator + trailing_ws
    return rebuilt, len(new_tuples)


def scrub_copy_row(
    line: str,
    table: str,
    columns: List[str],
    salt: str,
    counters: Dict[Tuple[str, str, str], int],
    resolver: "RuleResolver",
) -> str:
    """Anonymize one tab-delimited COPY row. Preserves `\\N` (NULL) and line ending."""
    if line.endswith("\r\n"):
        content, ending = line[:-2], "\r\n"
    elif line.endswith("\n"):
        content, ending = line[:-1], "\n"
    else:
        content, ending = line, ""

    fields = content.split("\t")
    out: List[str] = []
    for index, field in enumerate(fields):
        column = columns[index] if index < len(columns) else None
        kind = resolver.resolve(table, column) if column else None
        if kind and field != "\\N":
            raw = unescape_copy(field)
            fake = make_fake(kind, table, column or "", raw, salt)
            out.append(escape_copy(fake))
            key = (table, column or "", kind)
            counters[key] = counters.get(key, 0) + 1
        else:
            out.append(field)
    return "\t".join(out) + ending


# --------------------------------------------------------------------------- #
# Config overrides (stdlib only)
# --------------------------------------------------------------------------- #

class RuleResolver:
    """Resolves a column to a masking strategy, honoring user overrides.

    A resolved value is either a strategy name (mask with it) or None (skip).
    """

    def __init__(self) -> None:
        self._exact: Dict[Tuple[str, str], Optional[str]] = {}
        self._by_col: Dict[str, Optional[str]] = {}

    def add(self, selector: str, rule: str) -> None:
        selector = selector.strip()
        if not selector:
            raise ValueError("empty column selector")
        normalized = (rule or "").strip().lower()
        if normalized in ("", "skip", "none", "ignore", "off"):
            kind: Optional[str] = None
        elif normalized in KNOWN_KINDS:
            kind = normalized
        else:
            raise ValueError(
                f"unknown rule {rule!r}; known rules: {', '.join(sorted(KNOWN_KINDS))}, skip"
            )
        if "." in selector:
            table, column = selector.split(".", 1)
            self._exact[(table.strip().lower(), column.strip().lower())] = kind
        else:
            self._by_col[selector.lower()] = kind

    def resolve(self, table: Optional[str], column: Optional[str]) -> Optional[str]:
        if not column:
            return None
        if table:
            key = (table.lower(), column.lower())
            if key in self._exact:
                return self._exact[key]
        if column.lower() in self._by_col:
            return self._by_col[column.lower()]
        return detect_kind(column)


def load_config(path: Optional[str]) -> dict:
    target = path
    if target is None and os.path.exists(".dumpscrub.json"):
        target = ".dumpscrub.json"
    config: dict = {"mask": {}, "ignore": []}
    if not target:
        return config
    with open(target, "r", encoding="utf-8") as handle:
        raw = json.load(handle)
    if isinstance(raw, dict):
        mask = raw.get("mask")
        if isinstance(mask, dict):
            config["mask"].update(mask)
        ignore = raw.get("ignore")
        if isinstance(ignore, list):
            config["ignore"].extend(ignore)
    return config


def build_resolver(config: dict, mask_specs: List[str], ignore_specs: List[str]) -> RuleResolver:
    resolver = RuleResolver()
    for selector, rule in (config.get("mask") or {}).items():
        resolver.add(selector, rule)
    for selector in (config.get("ignore") or []):
        resolver.add(selector, "skip")
    for spec in mask_specs or []:
        if "=" not in spec:
            raise ValueError(f"--mask expects COL=RULE, got {spec!r}")
        selector, rule = spec.split("=", 1)
        resolver.add(selector, rule)
    for selector in ignore_specs or []:
        resolver.add(selector, "skip")
    return resolver


# --------------------------------------------------------------------------- #
# Dialect detection
# --------------------------------------------------------------------------- #

_DIALECT_MARKERS = [
    ("postgres", re.compile(r"pg_catalog|OWNER TO|SET statement_timeout|character varying|nextval|public\.|FROM stdin", re.I)),
    ("mysql", re.compile(r"ENGINE=|LOCK TABLES|AUTO_INCREMENT|/\*!", re.I)),
    ("sqlite", re.compile(r"sqlite_sequence|AUTOINCREMENT|BEGIN TRANSACTION", re.I)),
]


# --------------------------------------------------------------------------- #
# License validation (Polar.sh online + offline signed key fallback)
# --------------------------------------------------------------------------- #

POLAR_VALIDATE_URL = "https://api.polar.sh/v1/customer-portal/license-keys/validate"
LICENSE_CACHE_TTL = 24 * 60 * 60  # 24 hours
OFFLINE_TOKEN_PREFIX = "DSED1."
# Public Polar organization id. Safe to embed: it is not a secret, and baking it in
# means customers only need to set DUMPSCRUB_LICENSE_KEY (org id is not a credential).
DEFAULT_ORG_ID = "95a7b33d-a57b-45b3-830e-8271d494df3e"
# Ed25519 PUBLIC key (32 bytes hex) used to verify offline license tokens.
# The matching PRIVATE key lives only on your machine / signing service.
# Set via DUMPSCRUB_PUBLIC_KEY at runtime, or paste your hex key here before
# building release binaries. Empty = offline tokens are rejected.
EMBEDDED_PUBLIC_KEY_HEX = "e4962a277b63000f930cf5ba8b6a22cc16a44dc9d787fe59b48dde22ffe6be2a"


# --- Ed25519 verification (vendored, verify-only; RFC 8032) -----------------
# No third-party dependency, no network, works air-gapped. We only ever verify;
# signing is done seller-side by tools/sign_license.py.
_ED_P = 2**255 - 19
_ED_Q = 2**252 + 27742317777372353535851937790883648493
_ED_D = (-121665 * pow(121666, _ED_P - 2, _ED_P)) % _ED_P
_ED_I = pow(2, (_ED_P - 1) // 4, _ED_P)


def _ed_inv(x: int) -> int:
    return pow(x, _ED_P - 2, _ED_P)


def _ed_xrecover(y: int) -> int:
    xx = (y * y - 1) * _ed_inv(_ED_D * y * y + 1) % _ED_P
    x = pow(xx, (_ED_P + 3) // 8, _ED_P)
    if (x * x - xx) % _ED_P != 0:
        x = (x * _ED_I) % _ED_P
    if x % 2 != 0:
        x = _ED_P - x
    return x


_ED_BY = (4 * _ed_inv(5)) % _ED_P
_ED_BX = _ed_xrecover(_ED_BY)
_ED_B = [_ED_BX % _ED_P, _ED_BY % _ED_P, 1, (_ED_BX * _ED_BY) % _ED_P]


def _ed_add(P: List[int], Q: List[int]) -> List[int]:
    x1, y1, z1, _ = P
    x2, y2, z2, _ = Q
    x3 = (x1 * y2 + x2 * y1) * _ed_inv(1 + _ED_D * x1 * x2 * y1 * y2) % _ED_P
    y3 = (y1 * y2 + x1 * x2) * _ed_inv(1 - _ED_D * x1 * x2 * y1 * y2) % _ED_P
    z3 = (z1 * z2) % _ED_P
    return [x3 % _ED_P, y3 % _ED_P, z3 % _ED_P, (x3 * y3) % _ED_P]


def _ed_mul(P: List[int], e: int) -> List[int]:
    if e == 0:
        return [0, 1, 1, 0]
    Q = _ed_mul(P, e // 2)
    Q = _ed_add(Q, Q)
    if e & 1:
        Q = _ed_add(Q, P)
    return Q


def _ed_decode_point(raw: bytes) -> List[int]:
    y = int.from_bytes(raw, "little") & ((1 << 255) - 1)
    x = _ed_xrecover(y)
    if (x & 1) != (raw[31] >> 7):
        x = _ED_P - x
    if (-x * x + y * y - 1 - _ED_D * x * x * y * y) % _ED_P != 0:
        raise ValueError("point is not on the curve")
    return [x, y, 1, (x * y) % _ED_P]


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature (RFC 8032). Returns False on any malformed input."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    try:
        A = _ed_decode_point(public_key)
        R = _ed_decode_point(signature[:32])
    except (ValueError, IndexError):
        return False
    S = int.from_bytes(signature[32:], "little")
    if S >= _ED_Q:
        return False
    h = int.from_bytes(
        hashlib.sha512(signature[:32] + public_key + message).digest(), "little"
    ) % _ED_Q
    return _ed_mul(_ED_B, S) == _ed_add(R, _ed_mul(A, h))


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _offline_public_key() -> Optional[bytes]:
    value = os.environ.get("DUMPSCRUB_PUBLIC_KEY") or EMBEDDED_PUBLIC_KEY_HEX
    if not value:
        return None
    try:
        raw = bytes.fromhex(value.strip())
    except ValueError:
        return None
    return raw if len(raw) == 32 else None


def verify_offline_token(token: str) -> Optional[Tuple[bool, Optional[str]]]:
    """Return (valid, subject) for an offline Ed25519 token, or None if it isn't one."""
    if not token.startswith(OFFLINE_TOKEN_PREFIX):
        return None
    public_key = _offline_public_key()
    if public_key is None:
        return False, None
    try:
        _, payload_b64, signature_b64 = token.split(".", 2)
        payload = _b64d(payload_b64)
        signature = _b64d(signature_b64)
    except Exception:
        return False, None
    if not ed25519_verify(public_key, payload, signature):
        return False, None
    try:
        data = json.loads(payload.decode("utf-8"))
    except Exception:
        return False, None
    expires = data.get("exp")
    if expires and time.time() > float(expires):
        return False, data.get("sub")
    return True, data.get("sub")


def _license_cache_path(key: str) -> str:
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    directory = os.path.join(base, "dumpscrub")
    os.makedirs(directory, exist_ok=True)
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
    return os.path.join(directory, f"license-{digest}.json")


def _interpret_validation(data: dict) -> dict:
    """Interpret a 200-range ValidatedLicenseKey payload.

    Polar returns 200 for a valid key and 404 for invalid/revoked/disabled/expired,
    so a reachable 200 is valid unless the payload explicitly says otherwise.
    """
    status = str(data.get("status", "")).lower()
    valid = status not in ("revoked", "disabled", "expired")
    expires_at = data.get("expires_at")
    if valid and expires_at:
        try:
            when = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            if when < datetime.now(timezone.utc):
                valid = False
        except ValueError:
            pass
    licensed_to = None
    customer = data.get("customer")
    if isinstance(customer, dict):
        licensed_to = customer.get("email") or customer.get("name")
    return {"valid": valid, "licensed_to": licensed_to}


def _try_online(key: str, org_id: str, url: str = POLAR_VALIDATE_URL) -> Optional[dict]:
    body = json.dumps({"key": key, "organization_id": org_id}).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": f"dumpscrub/{__version__}",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        # urllib will not follow a 307/308 on POST (it keeps the body), so do it
        # ourselves in case Polar ever canonicalizes the URL differently.
        location = exc.headers.get("Location") if exc.headers else None
        if exc.code in (307, 308) and location and location != url:
            return _try_online(key, org_id, url=location)
        # 404 = a definitive "not valid" (missing/revoked/expired); anything else
        # (e.g. 5xx, rate limit) is treated as "unknown" so we don't cache a lie.
        if exc.code == 404:
            return {"valid": False, "licensed_to": None}
        return None
    except (urllib.error.URLError, OSError, ValueError):
        return None
    return _interpret_validation(data)


def check_license(
    key: Optional[str] = None,
    org_id: Optional[str] = None,
    use_cache: bool = True,
) -> Tuple[bool, Optional[str]]:
    """Validate a license key.

    Order: offline signed token -> local 24h cache -> Polar.sh online validation.
    A network failure with no offline token yields (False, None) rather than crashing.
    """
    key = key or os.environ.get("DUMPSCRUB_LICENSE_KEY") or os.environ.get("DUMPScrub_LICENSE")
    org_id = org_id or os.environ.get("DUMPSCRUB_ORG_ID") or DEFAULT_ORG_ID
    if not key:
        return False, None

    offline = verify_offline_token(key)
    if offline is not None:
        return offline

    if not org_id:
        return False, None

    cache_path = _license_cache_path(key)
    now = time.time()
    if use_cache and os.path.exists(cache_path):
        try:
            with open(cache_path, "r", encoding="utf-8") as handle:
                cached = json.load(handle)
            if now - float(cached.get("checked_at", 0)) < LICENSE_CACHE_TTL:
                return bool(cached.get("valid")), cached.get("licensed_to")
        except (OSError, ValueError):
            pass

    result = _try_online(key, org_id)
    if result is None:
        return False, None

    if use_cache:
        try:
            with open(cache_path, "w", encoding="utf-8") as handle:
                json.dump(
                    {"checked_at": now, "valid": result["valid"], "licensed_to": result.get("licensed_to")},
                    handle,
                )
        except OSError:
            pass
    return bool(result["valid"]), result.get("licensed_to")


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #

def _hashing_chunks(chunks: Iterable[str], hasher: "hashlib._Hash") -> Iterator[str]:
    for chunk in chunks:
        hasher.update(chunk.encode("utf-8", "surrogateescape"))
        yield chunk


def run(
    input_stream: Iterable[str],
    output_write,
    salt: str = "",
    dry_run: bool = False,
    resolver: Optional[RuleResolver] = None,
) -> dict:
    resolver = resolver or RuleResolver()
    input_hasher = hashlib.sha256()
    output_hasher = hashlib.sha256()
    schema: Dict[str, List[str]] = {}
    counters: Dict[Tuple[str, str, str], int] = {}
    dialect_scores = {name: 0 for name, _ in _DIALECT_MARKERS}
    stats = {"insert": 0, "create_table": 0, "copy": 0, "rows": 0}
    copy_table: Optional[str] = None
    copy_columns: Optional[List[str]] = None

    def emit(text: str) -> None:
        nonlocal output_hasher
        if not dry_run:
            output_write(text)
            output_hasher.update(text.encode("utf-8", "surrogateescape"))

    def score_dialect(text: str) -> None:
        for name, pattern in _DIALECT_MARKERS:
            if pattern.search(text):
                dialect_scores[name] += 1

    for unit in iter_units(_hashing_chunks(input_stream, input_hasher)):
        kind = unit[0]

        if kind == "copy_header":
            _, header_text, table, columns = unit
            copy_table = table
            copy_columns = columns if columns is not None else schema.get(table)
            stats["copy"] += 1
            score_dialect(header_text)
            emit(header_text)
            continue

        if kind == "copy_row":
            line = unit[1]
            if copy_columns is None:
                emit(line)
                continue
            stats["rows"] += 1
            emit(scrub_copy_row(line, copy_table or "", copy_columns, salt, counters, resolver))
            continue

        if kind == "copy_end":
            emit(unit[1])
            copy_table = None
            copy_columns = None
            continue

        statement = unit[1]
        if not statement.strip():
            emit(statement)
            continue

        score_dialect(statement)
        leading = statement[: len(statement) - len(statement.lstrip())]
        body = statement[len(leading):]

        if register_table(body, schema) or re.match(r"CREATE\s+TABLE", body, re.I):
            stats["create_table"] += 1
            emit(statement)
            continue

        if re.match(r"INSERT\s+INTO", body, re.I):
            new_body, rows = scrub_insert(body, schema, salt, counters, resolver)
            stats["insert"] += 1
            stats["rows"] += rows
            emit(leading + new_body)
            continue

        emit(statement)

    dialect = max(dialect_scores, key=lambda name: dialect_scores[name])
    if dialect_scores[dialect] == 0:
        dialect = "unknown"

    return {
        "dialect": dialect,
        "schema": schema,
        "counters": counters,
        "stats": stats,
        "input_sha256": input_hasher.hexdigest(),
        "output_sha256": output_hasher.hexdigest() if not dry_run else None,
    }


def build_report(result: dict, licensed: bool, licensed_to: Optional[str]) -> dict:
    """Build the audit report. Entitlement gates the evidentiary detail.

    Free reports are deliberately reduced (no hashes, no per-column detail) and
    watermarked, so the Pro tier sells an outcome rather than a warning line.
    """
    masked = [
        {"table": t, "column": c, "strategy": k, "rows": n}
        for (t, c, k), n in sorted(result["counters"].items())
    ]
    report = {
        "tool": "dumpscrub",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dialect": result["dialect"],
        "tables_seen": sorted(result["schema"].keys()),
        "total_rows_masked": sum(result["counters"].values()),
        "statements": result["stats"],
        "licensed": licensed,
        "licensed_to": licensed_to if licensed else None,
    }

    if not licensed:
        report.update({
            "watermark": (
                "UNLICENSED — the Pro report adds input/output SHA-256, "
                "per-column masking detail, and the CI gate."
            ),
            "masked_columns": [],
        })
        return report

    report.update({
        "input_sha256": result["input_sha256"],
        "output_sha256": result["output_sha256"],
        "masked_columns": masked,
        "note": (
            "Audit-evidence artifact, NOT an attestation. Reproduce by running this tool "
            "on the same input and matching input_sha256/output_sha256."
        ),
    })
    body = dict(report)
    report["report_sha256"] = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return report


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="dumpscrub",
        description="Zero-config, flat-file SQL dump anonymizer (Postgres/MySQL/SQLite).",
    )
    parser.add_argument("input", nargs="?", help="SQL dump file (default: stdin)")
    parser.add_argument("-o", "--output", help="output file (default: stdout)")
    parser.add_argument("--report", help="write JSON audit-evidence report to PATH")
    parser.add_argument("--dry-run", action="store_true", help="analyze only; write no dump")
    parser.add_argument("--fail-on-pii", action="store_true", help="exit 1 if anything is masked")
    parser.add_argument("--config", help="path to JSON config (default: ./.dumpscrub.json)")
    parser.add_argument("--mask", action="append", default=[], metavar="COL=RULE",
                        help="force a column to a rule, e.g. users.middle_name=full_name")
    parser.add_argument("--ignore", action="append", default=[], metavar="COL",
                        help="skip a column, e.g. users.phone or phone")
    parser.add_argument("--license", help="license key (or set DUMPSCRUB_LICENSE_KEY)")
    parser.add_argument("--no-license-cache", action="store_true", help="bypass the 24h license cache")
    parser.add_argument("--seed-salt", default="", help="extra salt for deterministic fakes")
    parser.add_argument("--version", action="version", version=f"dumpscrub {__version__}")
    args = parser.parse_args(argv)

    try:
        config = load_config(args.config)
        resolver = build_resolver(config, args.mask, args.ignore)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        parser.error(str(exc))

    licensed, licensed_to = check_license(
        args.license,
        os.environ.get("DUMPSCRUB_ORG_ID"),
        use_cache=not args.no_license_cache,
    )

    # Entitlement gate: the CI gate is the Pro feature. Scrubbing stays free.
    if args.fail_on_pii and not licensed:
        sys.stderr.write(
            "dumpscrub: --fail-on-pii is a Pro feature (CI gate). "
            "Set DUMPSCRUB_LICENSE_KEY or buy a license at "
            "https://buy.polar.sh/polar_cl_WlECVcFLOwxaPlWPxAcODCABC3cyBCB6hqZ9S12KD34\n"
        )
        return 2

    if args.input:
        input_stream = open(args.input, "r", encoding="utf-8", errors="surrogateescape")
    else:
        input_stream = sys.stdin

    output_stream = sys.stdout
    should_close = False
    if args.output and not args.dry_run:
        output_stream = open(args.output, "w", encoding="utf-8", errors="surrogateescape")
        should_close = True

    if args.dry_run:
        output_write = lambda _s: None  # noqa: E731
    else:
        output_write = output_stream.write

    try:
        result = run(input_stream, output_write, salt=args.seed_salt,
                     dry_run=args.dry_run, resolver=resolver)
    finally:
        if args.input:
            input_stream.close()
        if should_close:
            output_stream.close()

    report = build_report(result, licensed, licensed_to)
    if args.report:
        with open(args.report, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)
            handle.write("\n")

    if args.report and not licensed:
        sys.stderr.write(
            "dumpscrub: free tier — report is watermarked and reduced. Pro unlocks "
            "input/output SHA-256, per-column detail, and the CI gate.\n"
        )

    masked = report["total_rows_masked"]
    if args.fail_on_pii and masked > 0:
        sys.stderr.write(f"dumpscrub: FAIL — {masked} PII value(s) found in dump.\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
