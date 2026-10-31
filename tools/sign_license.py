#!/usr/bin/env python3
"""Mint an offline Ed25519 license token for dumpscrub.

This is a SELLER-SIDE tool. It needs the private key and is never shipped to
customers. The CLI only ever sees the public key.

Setup:
    python -m pip install cryptography

First run (generate a keypair; keep the seed secret and back it up):
    python tools/sign_license.py --new-key

Mint a token:
    python tools/sign_license.py --seed <64-hex-seed> --sub buyer@example.com --days 365
    python tools/sign_license.py --seed <64-hex-seed> --sub buyer@example.com --days 0   # never expires

Then ship the printed `public_key_hex` with your binaries (paste into
EMBEDDED_PUBLIC_KEY_HEX in dumpscrub.py, or set DUMPSCRUB_PUBLIC_KEY) and send
the `token` to the customer for air-gapped use.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:  # pragma: no cover
    sys.exit("this tool needs the 'cryptography' package: python -m pip install cryptography")


def b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Mint dumpscrub offline license tokens.")
    parser.add_argument("--new-key", action="store_true", help="generate a new Ed25519 keypair and exit")
    parser.add_argument("--seed", help="Ed25519 private seed, 32 bytes hex")
    parser.add_argument("--sub", help="license subject (customer email or id)")
    parser.add_argument("--org", default=None, help="optional organization id to embed")
    parser.add_argument("--days", type=int, default=365, help="validity in days; 0 = never expires")
    args = parser.parse_args(argv)

    if args.new_key:
        seed = os.urandom(32)
        key = Ed25519PrivateKey.from_private_bytes(seed)
        public = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        print("seed_hex:       ", seed.hex())
        print("public_key_hex: ", public.hex())
        print()
        print("Keep seed_hex secret. Paste public_key_hex into EMBEDDED_PUBLIC_KEY_HEX.")
        return 0

    if not args.seed or not args.sub:
        parser.error("--seed and --sub are required unless --new-key is used")

    seed = bytes.fromhex(args.seed)
    if len(seed) != 32:
        parser.error("--seed must be exactly 32 bytes of hex (64 characters)")

    key = Ed25519PrivateKey.from_private_bytes(seed)
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )

    expires = None if args.days == 0 else time.time() + args.days * 86400
    payload = json.dumps(
        {"sub": args.sub, "exp": expires, "org": args.org, "v": 1},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    signature = key.sign(payload)
    token = f"DSED1.{b64e(payload)}.{b64e(signature)}"

    print("public_key_hex: ", public.hex())
    print("subject:        ", args.sub)
    print("expires:        ", "never" if expires is None else time.strftime("%Y-%m-%d", time.gmtime(expires)))
    print("token:          ", token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
