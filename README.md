# dumpscrub

[![PyPI](https://img.shields.io/pypi/v/dumpscrub?color=2ecc71)](https://pypi.org/project/dumpscrub/)
[![Python versions](https://img.shields.io/pypi/pyversions/dumpscrub)](https://pypi.org/project/dumpscrub/)
[![CI](https://github.com/dumpscrub/dumpscrub/actions/workflows/ci.yml/badge.svg)](https://github.com/dumpscrub/dumpscrub/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Elastic%202.0-blue)](LICENSE)

**Zero-config, flat-file SQL dump anonymizer.** Pipe a production dump in, get a
staging-safe dump out. No database connection, no YAML, no vendor onboarding.

```bash
cat prod.sql | dumpscrub > staging.sql
```

Works with MySQL (`mysqldump`) and SQLite (`.dump`), and with PostgreSQL in **both**
formats: `pg_dump --inserts --column-inserts` *and* the native default
`COPY ... FROM stdin;` blocks (streamed row-by-row).

## Why this exists

Free OSS anonymizers exist — Greenmask, pg_anonymizer — but they require a **live
database connection and heavy YAML configuration**. dumpscrub is the opposite: it
operates on a **flat file**, streams it, and needs **zero config** to mask the obvious
PII columns it detects by name.

## Install

**Users (recommended — from PyPI):**

```bash
pipx install dumpscrub     # or: uv tool install dumpscrub
```

**Or the standalone binary (no Python runtime required):**

```bash
curl -fsSL https://raw.githubusercontent.com/dumpscrub/dumpscrub/main/install.sh -o install.sh
sh install.sh
```

**Local development (from a clone):**

```bash
pipx install .
# or just run it directly
python dumpscrub.py --help
```

## Usage

```bash
# 1. Write a scrubbed dump
dumpscrub prod.sql -o staging.sql

# 2. Audit-evidence report (free: reduced + watermarked; Pro: full detail + hashes)
dumpscrub prod.sql -o staging.sql --report scrub-report.json

# 3. CI gate (Pro) — exit 1 if PII remains, exit 2 if unlicensed
dumpscrub --dry-run --fail-on-pii < prod.sql
```

## What gets masked

Columns are matched by name against a heuristic ruleset: `email`, `ssn`,
`credit_card`, `phone`, `ip_address`, `first_name`, `last_name`, `full_name`,
`street_address`, `city`, `postal_code`, `date_of_birth`, `username`, `secret`
(passwords/tokens/API keys).

Replacements are **deterministic**: the same `(table, column, value)` always yields the
same fake, so the output is reproducible and referentially consistent across tables.
`NULL` is preserved.

## Overrides (no dependencies)

False positives and negatives can be corrected without touching code:

```bash
# Skip a column entirely, or force a rule onto a mis-detected one
dumpscrub --ignore users.phone --mask users.middle_name=full_name < prod.sql > staging.sql
```

Or drop a `.dumpscrub.json` in the working directory (or pass `--config`):

```json
{
  "mask": { "orders.ship_address": "street_address" },
  "ignore": ["audit_log.message", "users.company_name"]
}
```

Selectors are `column` (all tables) or `table.column` (that table only), case-insensitive.
Rules are the same names reported in `--report`: `email`, `ssn`, `credit_card`, `phone`,
`ip_address`, `first_name`, `last_name`, `full_name`, `street_address`, `city`,
`postal_code`, `date_of_birth`, `username`, `secret`, or `skip`.

## Licensing

The scrubbing engine is free forever. The **full audit-evidence report** and the
**CI gate** (`--fail-on-pii`) are the Pro tier. Online keys are validated against
**Polar.sh** with a **24-hour local cache** so CI doesn't hammer the API:

```bash
# The Polar org id is baked into the binary; customers only set their key.
export DUMPSCRUB_LICENSE_KEY="<polar-license-key>"
```

Org id (for reference / overriding): `95a7b33d-a57b-45b3-830e-8271d494df3e`.

**Air-gapped runners** use an **Ed25519-signed offline token**. Signing happens
seller-side only (`tools/sign_license.py`); the CLI ships only a public key and
verifies signatures offline. Generate a keypair and mint a token:

```bash
python -m pip install cryptography
python tools/sign_license.py --new-key
python tools/sign_license.py --seed <seed-hex> --sub buyer@example.com --days 365
```

Paste the printed public key into `EMBEDDED_PUBLIC_KEY_HEX` (or set
`DUMPSCRUB_PUBLIC_KEY`) before building release binaries. Validation order is
offline token → cache → Polar. A network failure never crashes the run.

**Entitlement behavior**
| | Free | Pro |
|---|---|---|
| Scrub dumps | ✅ | ✅ |
| `--report` | reduced, watermarked (no hashes/detail) | full: hashes + per-column detail + `report_sha256` |
| `--fail-on-pii` | exits `2` (license required) | exits `1` when PII remains, `0` when clean |

## The audit-evidence report

A **Pro** `--report` emits JSON with the dialect, every table/column scanned, the
masking strategy applied per column, row counts, **input/output SHA-256 hashes**, and a
`report_sha256` over the report body — so an auditor can verify the exact
transformation without ever seeing production data.

An **unlicensed** `--report` still writes a reduced summary (dialect, table names,
counts) but omits the hashes and per-column detail and carries a `watermark`.

> **It is not an attestation.** Attestations are issued by auditors, not tools. This
> report is an *evidence artifact* that makes your scrubbing reproducible.

## GitHub Actions

```yaml
- uses: ./
  with:
    input: prod.sql
    output: staging.sql
    report: scrub-report.json
    fail-on-pii: "true"
```

## Known limitations (v1.0)

- PostgreSQL `COPY` is supported in text format (`FROM stdin`); `COPY` in `BINARY`
  or `CSV` mode is not.
- One SQL statement is buffered at a time; `COPY` rows stream individually, so memory
  stays flat even on very large COPY blocks.
- Column detection is name-based; use `--mask` / `--ignore` or `.dumpscrub.json` to
  correct it.

## License

Licensed under the **Elastic License 2.0** (source-available) — see [LICENSE](LICENSE).
You may use, modify, and self-host the engine; you may not offer it as a hosted or
managed service, or circumvent the license-key checks.

The scrubbing engine is free. Pro (the full audit-evidence report and the CI gate)
requires a license key. Online keys are issued via Polar.sh; air-gapped keys are
Ed25519 tokens minted with `tools/sign_license.py`. See `check_license()` in `dumpscrub.py`.
