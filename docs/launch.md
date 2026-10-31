# DumpScrub — launch copy (HN + Reddit + more)

Ready-to-paste posts. **Post on a weekday morning, US Eastern (Tue–Thu, ~8–10am ET).**
Post from your own account, then stay in the thread for 4–6 hours to reply.

## Links to use
- Repo: https://github.com/dumpscrub/dumpscrub
- PyPI: https://pypi.org/project/dumpscrub/
- Landing: https://dumpscrub.github.io/dumpscrub/
- Install: `pipx install dumpscrub`

**Rule of thumb:** link to the **GitHub repo**, not the checkout. HN/Reddit punish
hard sells. Let the README/landing do the selling.

---

## 1. Show HN

### Title (pick one)
- `Show HN: DumpScrub – Zero-config SQL dump scrubbing from a flat file`
- `Show HN: I built a flat-file SQL dump scrubber that runs in CI`
- `Show HN: Scrub production data into staging without a DB connection or YAML`

### First comment (paste immediately after posting)
> Author here. I kept hitting the same thing: you need realistic data in staging,
> but you can't restore a production dump with real emails/phones/SSNs in it — especially
> with GDPR/HIPAA reviewers asking how you handled it.
>
> The existing tools (Greenmask, pg_anonymizer) are good, but they want a **live
> database connection and a YAML config**. I wanted the opposite: take the dump *file*
> you already have and pipe it through something.
>
> ```
> pg_dump prod | dumpscrub > staging.sql
> ```
>
> What it does:
> - Works on a flat file — no DB connection, nothing uploaded, runs air-gapped.
> - Handles Postgres `pg_dump` in **both** formats: `--inserts` and the default native
>   `COPY ... FROM stdin` blocks (streamed row by row).
> - Also MySQL (`mysqldump`) and SQLite (`.dump`).
> - Detects PII columns by name (email, phone, ssn, address, name, tokens…), replaces
>   values **deterministically** (same input → same output, referentially consistent).
> - Zero config, but you can override false positives: `--ignore users.phone` or
>   `--mask orders.ship_address=street_address`.
>
> The engine is free and MIT-ish in spirit; the paid bit ($49 one-time) is a full
> audit-evidence report (input/output SHA-256 + per-column detail) and a CI gate
> (`--fail-on-pii`). No telemetry, no phone-home; license checks work offline.
>
> Repo + install: https://github.com/dumpscrub/dumpscrub
>
> Happy to answer anything — especially if you've solved staging-data anonymization
> differently or hit a dump format it doesn't handle yet.

**Timing tip:** if it takes off, reply fast and technically. Don't argue with critics —
thank them and note the trade-off you chose.

---

## 2. Reddit

Post these on a **different day** than the HN post. Read each sub's self-promo rules
first (some require a flair like "Show and Tell", some restrict link posts).
Prefer a **text post** with a code snippet, repo link at the end.

### r/devops
**Title:** `I got tired of YAML+live-DB anonymizers, so I built a flat-file SQL dump scrubber for CI`
> We needed prod-shaped data in staging without real PII, and every tool I tried wanted
> a live DB connection and a big YAML config. I wanted `cat dump.sql | scrub > staging.sql`.
>
> Built DumpScrub — single binary/PyPI, no DB connection, runs in CI:
> ```
> pipx install dumpscrub
> pg_dump prod | dumpscrub --report scrub-report.json > staging.sql
> dumpscrub --dry-run --fail-on-pii < prod.sql   # CI gate
> ```
> Handles Postgres (INSERT + native COPY), MySQL, SQLite. Deterministic output,
> zero-config with `--ignore`/`--mask` overrides. No telemetry.
> Repo: https://github.com/dumpscrub/dumpscrub — feedback welcome, especially edge
> cases in your dumps.

### r/postgres
**Title:** `Scrubbing pg_dump output to staging — including the default COPY format`
> Most anonymizers assume you can connect to the DB. I wanted to work off the dump file
> itself, including `pg_dump`'s default `COPY ... FROM stdin` blocks.
> ```
> pg_dump --format=plain prod | dumpscrub > staging.sql
> ```
> It streams COPY rows, preserves `\N` NULLs, masks PII columns by name, and output is
> deterministic. Also does `--inserts` and `--column-inserts`.
> Repo: https://github.com/dumpscrub/dumpscrub

### r/SQL
**Title:** `A flat-file SQL dump anonymizer (Postgres/MySQL/SQLite) that runs in CI`
> Sharing a tool I built: pipe any SQL dump in, get a staging-safe dump out. No DB
> connection, no YAML, deterministic fakes. Postgres INSERT + COPY, MySQL, SQLite.
> ```
> pipx install dumpscrub
> cat prod.sql | dumpscrub > staging.sql
> ```
> Repo: https://github.com/dumpscrub/dumpscrub

---

## 3. Other channels

### Lobsters (https://lobste.rs) — submit the repo link
Title: `DumpScrub: zero-config SQL dump anonymizer for CI`
Tag: `devops` or `databases`. Add a short explanatory comment.

### dev.to — cross-post a tutorial
Title: `How to anonymize a Postgres dump for staging (without a DB connection)`
Walk through `pg_dump | dumpscrub`, the COPY format, overrides, and a GitHub Action.
End with a link to the repo. (Full tutorial can be adapted from the SEO page
`pg-dump-copy-anonymize`.)

### X / Twitter — short thread
> You need prod data in staging, minus the PII.
> You don't want a live DB connection or 200 lines of YAML.
>
> `pg_dump prod | dumpscrub > staging.sql`
>
> Flat-file, deterministic, works on native COPY format. Runs in CI.
> github.com/dumpscrub/dumpscrub

---

## 4. Objection handling (answer these calmly)

| Comment | Reply |
|---|---|
| "Why not Greenmask / pg_anonymizer?" | Great tools if you have a live DB and a YAML file. DumpScrub targets the flat-file / CI / air-gapped case they don't. Free engine; Pro is the report + CI gate. |
| "The license check is client-side, I can bypass it." | Yep — it's a $49 tool with an Ed25519 check, not DRM. The gated features are worth paying for, not worth fighting. |
| "How do I know it's safe / what does it send?" | Nothing. No telemetry, no upload. It reads the pipe and writes the pipe, locally. |
| "Does it handle X format?" | Postgres INSERT + COPY, MySQL, SQLite. If not, file an issue with a sample — formats are easy to add. |
| "False positives/negatives?" | `--ignore table.col` and `--mask table.col=rule` override the heuristics; `.dumpscrub.json` for teams. |
| "Isn't this just Faker with extra steps?" | The value is the SQL/COPY-aware streaming + schema detection so you don't hand-write it. |
| "$49 for a script?" | It's a maintained, tested, multi-dialect tool with a CI gate and evidence report; refundable if it doesn't fit. |

---

## 5. Pre-post checklist
- [ ] Weekday, ~8–10am US Eastern
- [ ] Post from your own account; be free for the next 4–6 hours
- [ ] Link the **repo**, not the shop
- [ ] First comment ready to paste the second it's live
- [ ] Landing + PyPI + install all working (✅ done)
- [ ] Do **not** ask for upvotes or coordinate votes (ban risk)
- [ ] Reddit posts scheduled for a **later day**, per-sub rules checked
- [ ] Watch GitHub stars / PyPI downloads / checkout clicks after
