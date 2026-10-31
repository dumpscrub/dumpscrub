"""Tests for the dumpscrub core engine.

Run: python -m pytest tests/   (or: python tests/test_dumpscrub.py)
"""
import hashlib
import io
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import dumpscrub  # noqa: E402

# Throwaway Ed25519 test keypair + tokens (generated with tools/sign_license.py).
# These verify against TEST_PUBKEY_HEX only; they are worthless for production.
TEST_PUBKEY_HEX = "96ab2d3895aacfa0bda03243872ffac2def414d327a0dc02cee3ce7689764e38"
VALID_TOKEN = (
    "DSED1.eyJleHAiOjIxMDg3NjM4NzcuMzA2NDQxNSwib3JnIjpudWxsLCJzdWIiOiJvcHNAYWNtZS5jb20iLCJ2IjoxfQ"
    ".wxApWBEjnK4gRoUCdZn0JFHIfCvkb0sFb8XjP3LgESyKqruD8HGAUrPpoYbkt17TWKXbeGo8a_q9iJQuGXUhCw"
)
OTHER_TOKEN = (
    "DSED1.eyJleHAiOjIxMDg3NjM4NzcuNTc1ODM1LCJvcmciOm51bGwsInN1YiI6Im90aGVyQGFjbWUuY29tIiwidiI6MX0"
    ".JUry1pBu9JIsUGLGnLmKeOT83Dsh33wKJ_gYIjV2YEpLwtX0pyedPbZI8QOyNP6VmNR5KR_jGb-oL8otF5s5CA"
)
EXPIRED_TOKEN = (
    "DSED1.eyJleHAiOjE3OTMzMTc0NzcuNDY5NTU4LCJvcmciOm51bGwsInN1YiI6Im9wc0BhY21lLmNvbSIsInYiOjF9"
    ".--2-APjwtuvTUEwtSQhICkLU65rSP1szb4-ztj381i2zG3CaybQTxsCk5RIC_BNMEuSpXUb7IzqCZfczp-02Bg"
)

dumpscrub.EMBEDDED_PUBLIC_KEY_HEX = TEST_PUBKEY_HEX


INSERT_SAMPLE = """-- a comment
CREATE TABLE "users" (
    "id" integer NOT NULL,
    "email" character varying(255) NOT NULL,
    "first_name" text,
    "phone" text
);
INSERT INTO "users" ("id", "email", "first_name", "phone") VALUES
    (1, 'jane.doe@acme.com', 'Jane', '+1-415-555-0199'),
    (2, 'bob@example.org', 'Bob', '555.867.5309');
"""

COPY_SAMPLE = """CREATE TABLE public.users (
    id integer,
    email character varying(255),
    first_name text,
    ship_address text,
    phone text
);
COPY public.users (id, email, first_name, ship_address, phone) FROM stdin;
1\tjane.doe@acme.com\tJane\t742 Evergreen Terrace\t+1-415-555-0199
2\tbob@example.org\tBob\t\\N\t555.867.5309
\\.
"""


def _scrub(sql, salt="", resolver=None):
    out = io.StringIO()
    result = dumpscrub.run(io.StringIO(sql).readlines(), out.write, salt=salt, resolver=resolver)
    return out.getvalue(), result


# --------------------------------------------------------------------------- #
# INSERT
# --------------------------------------------------------------------------- #

def test_pii_is_removed():
    output, result = _scrub(INSERT_SAMPLE)
    assert "jane.doe@acme.com" not in output
    assert "bob@example.org" not in output
    assert "+1-415-555-0199" not in output
    assert "555.867.5309" not in output
    assert result["counters"], "expected some columns to be masked"


def test_non_pii_preserved():
    output, _ = _scrub(INSERT_SAMPLE)
    assert "CREATE TABLE" in output
    assert "integer NOT NULL" in output
    assert "character varying(255)" in output


def test_deterministic():
    first, _ = _scrub(INSERT_SAMPLE)
    second, _ = _scrub(INSERT_SAMPLE)
    assert first == second


def test_salt_changes_output():
    first, _ = _scrub(INSERT_SAMPLE, salt="a")
    second, _ = _scrub(INSERT_SAMPLE, salt="b")
    assert first != second


def test_column_classification_boundaries():
    # Regression: "ship_address" must be a street address, never an IP address.
    assert dumpscrub.detect_kind("ship_address") == "street_address"
    assert dumpscrub.detect_kind("billing_addr") == "street_address"
    assert dumpscrub.detect_kind("user_ip") == "ip_address"
    assert dumpscrub.detect_kind("ip_address") == "ip_address"
    assert dumpscrub.detect_kind("company_name") == "full_name"
    assert dumpscrub.detect_kind("user_id") is None
    assert dumpscrub.detect_kind("total") is None


def test_report_hashes():
    _, result = _scrub(INSERT_SAMPLE)
    report = dumpscrub.build_report(result, licensed=True, licensed_to="ops@acme.com")
    assert report["input_sha256"] and report["output_sha256"]
    assert report["input_sha256"] != report["output_sha256"]
    assert report["licensed"] is True
    assert report["licensed_to"] == "ops@acme.com"


def test_free_report_is_reduced_and_watermarked():
    _, result = _scrub(INSERT_SAMPLE)
    report = dumpscrub.build_report(result, licensed=False, licensed_to=None)
    assert report["licensed"] is False
    assert "watermark" in report
    assert "input_sha256" not in report
    assert "output_sha256" not in report
    assert report["masked_columns"] == []
    assert report["total_rows_masked"] > 0  # still tells you something was scrubbed


def test_pro_report_is_full_and_self_hashed():
    _, result = _scrub(INSERT_SAMPLE)
    report = dumpscrub.build_report(result, licensed=True, licensed_to="ops@acme.com")
    assert report["masked_columns"]
    assert report["report_sha256"]
    body = {k: v for k, v in report.items() if k != "report_sha256"}
    expected = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    assert report["report_sha256"] == expected


# --------------------------------------------------------------------------- #
# COPY FROM stdin
# --------------------------------------------------------------------------- #

def test_copy_block_masks_and_preserves_nulls():
    output, result = _scrub(COPY_SAMPLE)
    assert "jane.doe@acme.com" not in output
    assert "bob@example.org" not in output
    assert "742 Evergreen Terrace" not in output
    assert "+1-415-555-0199" not in output
    # \N (NULL) must survive untouched.
    assert "\t\\N\t" in output
    # The terminator and COPY header round-trip.
    assert "COPY public.users (id, email, first_name, ship_address, phone) FROM stdin;" in output
    assert output.rstrip().endswith("\\.")
    # ship_address must be classified as a street address inside COPY.
    strategies = {(c["table"], c["column"]): c["strategy"] for c in
                  dumpscrub.build_report(result, True, "ops@acme.com")["masked_columns"]}
    assert strategies[("users", "ship_address")] == "street_address"
    assert result["stats"]["copy"] == 1
    assert result["stats"]["rows"] == 2


def test_copy_header_newline_preserved():
    # Regression: the header's newline must survive so the COPY block stays loadable.
    output, _ = _scrub(COPY_SAMPLE)
    assert "FROM stdin;\n" in output
    assert output.endswith("\\.\n")
    assert not output.endswith("\\\n\n")  # no stray trailing blank line
    lines = output.splitlines()
    header = next(i for i, l in enumerate(lines) if l.startswith("COPY"))
    assert lines[header].endswith("FROM stdin;")
    assert lines[header + 1].startswith("1\t")


def test_copy_without_column_list_uses_schema():
    sql = (
        "CREATE TABLE t (id integer, email text, phone text);\n"
        "COPY t FROM stdin;\n"
        "1\tjane@acme.com\t+1-415-555-0199\n"
        "\\.\n"
    )
    output, result = _scrub(sql)
    assert "jane@acme.com" not in output
    assert "+1-415-555-0199" not in output
    assert result["counters"].get(("t", "email", "email")) == 1


def test_copy_escaped_tabs_and_newlines_round_trip():
    # A field containing a literal newline is encoded as \n in COPY text.
    fake = dumpscrub.escape_copy("line1\nline2\twith\\stuff")
    assert fake == "line1\\nline2\\twith\\\\stuff"
    assert dumpscrub.unescape_copy(fake) == "line1\nline2\twith\\stuff"


def test_copy_cells_count_in_fail_on_pii_totals():
    _, result = _scrub(COPY_SAMPLE)
    report = dumpscrub.build_report(result, True, "ops@acme.com")
    assert report["total_rows_masked"] == sum(
        c["rows"] for c in report["masked_columns"]
    )
    assert report["total_rows_masked"] >= 6


# --------------------------------------------------------------------------- #
# Config / CLI overrides
# --------------------------------------------------------------------------- #

def test_ignore_override_keeps_value():
    resolver = dumpscrub.build_resolver({}, [], ["users.phone"])
    output, _ = _scrub(INSERT_SAMPLE, resolver=resolver)
    assert "+1-415-555-0199" in output  # phone untouched
    assert "jane.doe@acme.com" not in output  # email still masked


def test_ignore_override_by_bare_column():
    resolver = dumpscrub.build_resolver({}, [], ["phone"])
    output, _ = _scrub(INSERT_SAMPLE, resolver=resolver)
    assert "+1-415-555-0199" in output


def test_mask_override_forces_masking():
    resolver = dumpscrub.build_resolver({}, ["users.id=username"], [])
    output, _ = _scrub(INSERT_SAMPLE, resolver=resolver)
    assert "user_" in output  # the id column was force-masked


def test_unknown_rule_raises():
    try:
        dumpscrub.build_resolver({}, ["users.x=bogus"], [])
    except ValueError:
        return
    raise AssertionError("expected ValueError for an unknown rule")


def test_config_file_is_loaded():
    config = {"mask": {"users.first_name": "skip"}, "ignore": ["users.phone"]}
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, ".dumpscrub.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(config, handle)
        loaded = dumpscrub.load_config(path)
    resolver = dumpscrub.build_resolver(loaded, [], [])
    output, _ = _scrub(INSERT_SAMPLE, resolver=resolver)
    assert "Jane" in output  # first_name skipped
    assert "+1-415-555-0199" in output  # phone ignored
    assert "jane.doe@acme.com" not in output


# --------------------------------------------------------------------------- #
# License validation
# --------------------------------------------------------------------------- #

def test_license_offline_token_valid():
    assert dumpscrub.check_license(VALID_TOKEN) == (True, "ops@acme.com")


def test_license_offline_token_second_subject():
    assert dumpscrub.check_license(OTHER_TOKEN) == (True, "other@acme.com")


def test_license_offline_token_expired():
    assert dumpscrub.check_license(EXPIRED_TOKEN) == (False, "ops@acme.com")


def test_license_tampered_token_rejected():
    header, payload, signature = VALID_TOKEN.split(".")
    tampered = f"{header}.{payload}.{signature[:-2]}AA"
    assert dumpscrub.check_license(tampered) == (False, None)


def test_license_requires_public_key():
    original = dumpscrub.EMBEDDED_PUBLIC_KEY_HEX
    dumpscrub.EMBEDDED_PUBLIC_KEY_HEX = ""
    try:
        assert dumpscrub.check_license(VALID_TOKEN) == (False, None)
    finally:
        dumpscrub.EMBEDDED_PUBLIC_KEY_HEX = original


def test_ed25519_verify_primitive():
    import base64

    _, payload_b64, sig_b64 = VALID_TOKEN.split(".")
    payload = base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4))
    signature = base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
    public_key = bytes.fromhex(TEST_PUBKEY_HEX)
    assert dumpscrub.ed25519_verify(public_key, payload, signature) is True
    assert dumpscrub.ed25519_verify(public_key, payload + b"x", signature) is False


# -- CLI entitlement gating ---------------------------------------------------

def _clean_env():
    """Context manager: temporarily remove license env vars."""
    import contextlib

    @contextlib.contextmanager
    def _inner():
        keys = ("DUMPSCRUB_LICENSE_KEY", "DUMPSCRUB_ORG_ID", "DUMPScrub_LICENSE")
        saved = {k: os.environ.pop(k) for k in keys if k in os.environ}
        try:
            yield
        finally:
            os.environ.update(saved)

    return _inner()


def test_cli_ci_gate_requires_license():
    with _clean_env(), tempfile.TemporaryDirectory() as directory:
        src = os.path.join(directory, "dump.sql")
        with open(src, "w", encoding="utf-8") as handle:
            handle.write(INSERT_SAMPLE)
        code = dumpscrub.main([src, "--dry-run", "--fail-on-pii", "--no-license-cache"])
    assert code == 2


def test_cli_ci_gate_with_license_detects_pii():
    with _clean_env(), tempfile.TemporaryDirectory() as directory:
        src = os.path.join(directory, "dump.sql")
        with open(src, "w", encoding="utf-8") as handle:
            handle.write(INSERT_SAMPLE)
        code = dumpscrub.main([
            src, "--dry-run", "--fail-on-pii",
            "--license", VALID_TOKEN, "--no-license-cache",
        ])
    assert code == 1  # gate open (licensed) and PII was found


def test_cli_free_report_is_reduced():
    with _clean_env(), tempfile.TemporaryDirectory() as directory:
        src = os.path.join(directory, "dump.sql")
        out = os.path.join(directory, "staging.sql")
        rep = os.path.join(directory, "report.json")
        with open(src, "w", encoding="utf-8") as handle:
            handle.write(INSERT_SAMPLE)
        code = dumpscrub.main([src, "-o", out, "--report", rep, "--no-license-cache"])
        with open(rep, "r", encoding="utf-8") as handle:
            report = json.load(handle)
    assert code == 0
    assert report["licensed"] is False
    assert "watermark" in report
    assert report["masked_columns"] == []


def test_cli_pro_report_is_full():
    with _clean_env(), tempfile.TemporaryDirectory() as directory:
        src = os.path.join(directory, "dump.sql")
        out = os.path.join(directory, "staging.sql")
        rep = os.path.join(directory, "report.json")
        with open(src, "w", encoding="utf-8") as handle:
            handle.write(INSERT_SAMPLE)
        code = dumpscrub.main([
            src, "-o", out, "--report", rep,
            "--license", VALID_TOKEN, "--no-license-cache",
        ])
        with open(rep, "r", encoding="utf-8") as handle:
            report = json.load(handle)
    assert code == 0
    assert report["licensed"] is True
    assert report["input_sha256"] and report["output_sha256"]
    assert report["masked_columns"]
    assert report["report_sha256"]


def test_license_online_uses_cache():
    calls = {"n": 0}

    def fake_online(key, org):
        calls["n"] += 1
        return {"valid": True, "licensed_to": "ops@acme.com"}

    original = dumpscrub._try_online
    old_cache = os.environ.get("XDG_CACHE_HOME")
    dumpscrub._try_online = fake_online
    try:
        with tempfile.TemporaryDirectory() as directory:
            os.environ["XDG_CACHE_HOME"] = directory
            first = dumpscrub.check_license("POLAR-KEY-123", "org_1")
            second = dumpscrub.check_license("POLAR-KEY-123", "org_1")
    finally:
        dumpscrub._try_online = original
        if old_cache is None:
            os.environ.pop("XDG_CACHE_HOME", None)
        else:
            os.environ["XDG_CACHE_HOME"] = old_cache
    assert first == (True, "ops@acme.com")
    assert second == (True, "ops@acme.com")
    assert calls["n"] == 1  # second call served from cache


def test_license_online_failure_is_graceful():
    original = dumpscrub._try_online
    dumpscrub._try_online = lambda key, org: None
    try:
        assert dumpscrub.check_license("POLAR-KEY-123", "org_1", use_cache=False) == (False, None)
    finally:
        dumpscrub._try_online = original


def test_interpret_validation_200_is_valid_by_default():
    assert dumpscrub._interpret_validation({"status": "granted"})["valid"] is True
    assert dumpscrub._interpret_validation({})["valid"] is True  # reachable 200 => valid
    assert dumpscrub._interpret_validation(
        {"customer": {"email": "buyer@acme.com"}}
    )["licensed_to"] == "buyer@acme.com"


def test_interpret_validation_rejects_revoked_disabled_expired():
    assert dumpscrub._interpret_validation({"status": "revoked"})["valid"] is False
    assert dumpscrub._interpret_validation({"status": "disabled"})["valid"] is False
    assert dumpscrub._interpret_validation(
        {"status": "granted", "expires_at": "2000-01-01T00:00:00Z"}
    )["valid"] is False
    assert dumpscrub._interpret_validation(
        {"status": "granted", "expires_at": "2999-01-01T00:00:00Z"}
    )["valid"] is True


def test_try_online_404_is_invalid_not_unknown():
    import urllib.error

    def fake_urlopen(request, timeout=5):
        raise urllib.error.HTTPError(request.full_url, 404, "Not Found", {}, None)

    original = dumpscrub.urllib.request.urlopen
    dumpscrub.urllib.request.urlopen = fake_urlopen
    try:
        assert dumpscrub._try_online("bad-key", "org") == {"valid": False, "licensed_to": None}
    finally:
        dumpscrub.urllib.request.urlopen = original


def test_try_online_network_error_is_unknown():
    import urllib.error

    def fake_urlopen(request, timeout=5):
        raise urllib.error.URLError("no route")

    original = dumpscrub.urllib.request.urlopen
    dumpscrub.urllib.request.urlopen = fake_urlopen
    try:
        assert dumpscrub._try_online("k", "org") is None
    finally:
        dumpscrub.urllib.request.urlopen = original


def test_try_online_follows_307_redirect():
    import urllib.error

    calls = {"n": 0}

    class FakeResponse:
        def __init__(self, payload):
            self._payload = payload

        def read(self):
            return self._payload

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def fake_urlopen(request, timeout=5):
        calls["n"] += 1
        if calls["n"] == 1:
            raise urllib.error.HTTPError(
                request.full_url, 307, "Temporary Redirect",
                {"Location": "https://api.polar.sh/redirected"}, None,
            )
        return FakeResponse(b'{"status":"granted","customer":{"email":"buyer@acme.com"}}')

    original = dumpscrub.urllib.request.urlopen
    dumpscrub.urllib.request.urlopen = fake_urlopen
    try:
        result = dumpscrub._try_online("k", "org")
    finally:
        dumpscrub.urllib.request.urlopen = original
    assert calls["n"] == 2  # followed the redirect
    assert result == {"valid": True, "licensed_to": "buyer@acme.com"}


def test_default_org_id_is_used_when_unset():
    seen = {}

    def fake_online(key, org):
        seen["org"] = org
        return {"valid": True, "licensed_to": "buyer@acme.com"}

    original = dumpscrub._try_online
    dumpscrub._try_online = fake_online
    try:
        with _clean_env():
            result = dumpscrub.check_license("POLAR-KEY-ABC", None, use_cache=False)
    finally:
        dumpscrub._try_online = original
    assert result == (True, "buyer@acme.com")
    assert seen["org"] == dumpscrub.DEFAULT_ORG_ID


def test_no_license_returns_unlicensed():
    assert dumpscrub.check_license(None) == (False, None)


if __name__ == "__main__":
    tests = [value for name, value in sorted(globals().items()) if name.startswith("test_")]
    for test in tests:
        test()
    print(f"all {len(tests)} tests passed")
