#!/usr/bin/env python3
"""A stand-in for the Mycelia Signal price oracle, for testnet demos only.

It signs BTC/USD price statements in Mycelia Signal's exact format (its docs/DEMO.md):
a pipe-separated canonical string, signed with secp256k1 ECDSA over sha256(canonical),
returned as the same JSON the paid API endpoint returns. The key is a local test key,
so nothing here is a real price.

It also turns a statement into the --params file for an oracle_demo action. The
covenant cannot split a string, so the canonical string is handed to it already cut into
its fields, each as a SimplicityHL literal.

Needs the `ecdsa` package (pip install ecdsa).
"""

import argparse
import base64
import hashlib
import json
import sys
import time
from decimal import Decimal, InvalidOperation
from pathlib import Path

from ecdsa import SECP256k1, SigningKey, VerifyingKey
from ecdsa.util import sigdecode_der, sigencode_der

DOMAIN = "BTCUSD"
QUOTE = "USD"
DECIMALS = 2
DEFAULT_SOURCES = "binance,bitstamp,coinbase,kraken,okx"
DEFAULT_METHOD = "median"

# Bounds of the program's witness lists. A `List<u8, N>` holds at most N - 1 elements.
MAX_PRICE_DIGITS = 15
MAX_SOURCES_LEN = 127
MAX_METHOD_LEN = 15
MAX_TIMESTAMP_DIGITS = 15
MAX_NONCE_LEN = 31

N = SECP256k1.order

# Written into every key file, so nobody mistakes one for a real key.
TEST_KEY_NOTE = "Test key made by fake_oracle.py. Testnet only: never use it for anything of value."


def load_key(path):
    data = json.loads(Path(path).read_text())
    return SigningKey.from_string(bytes.fromhex(data["secret"]), curve=SECP256k1)


def compressed_pubkey(vk):
    return vk.to_string("compressed").hex()


def canonical_string(price, timestamp, nonce, sources, method):
    return "|".join(
        ["v1", "PRICE", DOMAIN, price, QUOTE, str(DECIMALS), sources, method, str(timestamp), str(nonce)]
    )


def format_price(raw):
    try:
        value = Decimal(raw)
    except InvalidOperation:
        sys.exit(f"not a price: {raw!r}")
    if value <= 0:
        sys.exit("price must be positive")
    return f"{value.quantize(Decimal(1).scaleb(-DECIMALS))}"


def sign(sk, canonical):
    digest = hashlib.sha256(canonical.encode()).digest()
    sig = sk.sign_digest_deterministic(digest, hashfunc=hashlib.sha256, sigencode=sigencode_der)
    r, s = sigdecode_der(sig, N)
    # libsecp256k1, which the DEMO.md check uses through coincurve, rejects high-S.
    if s > N // 2:
        sig = sigencode_der(r, N - s, N)
    return base64.b64encode(sig).decode()


def verify(statement):
    """The check from Mycelia Signal's DEMO.md, step 4."""
    canonical = statement["canonical"]
    msg_hash = hashlib.sha256(canonical.encode()).digest()
    vk = VerifyingKey.from_string(bytes.fromhex(statement["pubkey"]), curve=SECP256k1)
    sig = base64.b64decode(statement["signature"])
    _, s = sigdecode_der(sig, N)
    if s > N // 2:
        return False
    try:
        return vk.verify_digest(sig, msg_hash, sigdecode=sigdecode_der)
    except Exception:
        return False


def parse_canonical(canonical):
    fields = canonical.split("|")
    if len(fields) != 10:
        sys.exit(f"expected 10 fields in the canonical string, found {len(fields)}")
    version, kind, domain, price, quote, decimals, sources, method, timestamp, nonce = fields
    expected = ("v1", "PRICE", DOMAIN, QUOTE, str(DECIMALS))
    if (version, kind, domain, quote, decimals) != expected:
        sys.exit(f"the covenant only accepts v1|PRICE|{DOMAIN}|<price>|{QUOTE}|{DECIMALS}|…")
    integer, dot, fraction = price.partition(".")
    if not dot or len(fraction) != DECIMALS or not (integer + fraction).isdigit():
        sys.exit(f"price {price!r} is not <digits>.<{DECIMALS} digits>")
    if not timestamp.isdigit():
        sys.exit(f"timestamp {timestamp!r} is not decimal digits")
    for name, value, limit in [
        ("price", integer, MAX_PRICE_DIGITS),
        ("sources", sources, MAX_SOURCES_LEN),
        ("method", method, MAX_METHOD_LEN),
        ("timestamp", timestamp, MAX_TIMESTAMP_DIGITS),
        ("nonce", nonce, MAX_NONCE_LEN),
    ]:
        if len(value) > limit:
            sys.exit(f"{name} is {len(value)} bytes; the covenant takes at most {limit}")
    return {
        "price_int": integer,
        "price_frac": fraction,
        "price_cents": int(integer + fraction),
        "sources": sources,
        "method": method,
        "timestamp": int(timestamp),
        "timestamp_digits": timestamp,
        "nonce": nonce,
    }


def simf_list(text):
    return "list![" + ", ".join(str(b) for b in text.encode()) + "]"


def statement_params(statement):
    """The STATEMENT_* witness params for one signed statement."""
    if not verify(statement):
        sys.exit("the statement's signature does not verify")
    fields = parse_canonical(statement["canonical"])
    r, s = sigdecode_der(base64.b64decode(statement["signature"]), N)
    frac = fields["price_frac"].encode()
    return fields, {
        "STATEMENT_PRICE_INT": simf_list(fields["price_int"]),
        "STATEMENT_PRICE_FRAC": f"({frac[0]}, {frac[1]})",
        "STATEMENT_SOURCES": simf_list(fields["sources"]),
        "STATEMENT_METHOD": simf_list(fields["method"]),
        "STATEMENT_TIMESTAMP": simf_list(fields["timestamp_digits"]),
        "STATEMENT_NONCE": simf_list(fields["nonce"]),
        "STATEMENT_SIG": f"(0x{r:064x}, 0x{s:064x})",
    }


def write_json(obj, out):
    text = json.dumps(obj, indent=2) + "\n"
    if out:
        Path(out).write_text(text)
        print(f"wrote {out}", file=sys.stderr)
    else:
        sys.stdout.write(text)


def cmd_keygen(args):
    if Path(args.out).exists() and not args.force:
        sys.exit(f"{args.out} exists; pass --force to replace it")
    sk = SigningKey.generate(curve=SECP256k1)
    pubkey = compressed_pubkey(sk.get_verifying_key())
    write_json({"note": TEST_KEY_NOTE, "secret": sk.to_string().hex(), "pubkey": pubkey}, args.out)
    print(f"ORACLE_PUBKEY_PREFIX={int(pubkey[:2], 16)}  ORACLE_PUBKEY_X={pubkey[2:]}", file=sys.stderr)


def cmd_sign(args):
    sk = load_key(args.key)
    timestamp = args.timestamp if args.timestamp is not None else int(time.time())
    nonce = args.nonce if args.nonce is not None else timestamp % 1000000
    canonical = canonical_string(format_price(args.price), timestamp, nonce, args.sources, args.method)
    statement = {
        "domain": DOMAIN,
        "canonical": canonical,
        "signature": sign(sk, canonical),
        "pubkey": compressed_pubkey(sk.get_verifying_key()),
        "signing_scheme": "secp256k1_ecdsa",
    }
    assert verify(statement)
    write_json(statement, args.out)


def cmd_verify(args):
    statement = json.loads(Path(args.statement).read_text())
    if not verify(statement):
        sys.exit("INVALID: the signature does not verify")
    fields = parse_canonical(statement["canonical"])
    print(f"valid: {DOMAIN} {fields['price_cents'] / 100:.2f} at {fields['timestamp']}")


def cmd_request_params(args):
    statement = json.loads(Path(args.statement).read_text())
    fields, params = statement_params(statement)
    params.update(
        {
            "REQUEST_PRICE": str(fields["price_cents"]),
            "REQUEST_TIMESTAMP": str(fields["timestamp"]),
            "REQUEST_LBTC_AMOUNT": str(args.lbtc_amount),
            "REQUEST_RECIPIENT": args.recipient,
        }
    )
    write_json(params, args.out)


def cmd_challenge_params(args):
    request = json.loads(Path(args.request).read_text())
    statement = json.loads(Path(args.statement).read_text())
    fields, params = statement_params(statement)
    if fields["timestamp"] <= int(request["REQUEST_TIMESTAMP"]):
        print("warning: this statement is not newer than the request, so the covenant will refuse it", file=sys.stderr)
    params.update({k: v for k, v in request.items() if k.startswith("REQUEST_")})
    write_json(params, args.out)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("keygen", help="create the test oracle key")
    p.add_argument("--out", default="data/example_oracle_key.json")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("sign", help="sign a BTC/USD price statement")
    p.add_argument("--key", default="data/example_oracle_key.json")
    p.add_argument("--price", required=True, help="BTC/USD price, e.g. 84231.50")
    p.add_argument("--timestamp", type=int, help="unix seconds (default: now)")
    p.add_argument("--nonce", type=int)
    p.add_argument("--sources", default=DEFAULT_SOURCES)
    p.add_argument("--method", default=DEFAULT_METHOD)
    p.add_argument("--out")
    p.set_defaults(func=cmd_sign)

    p = sub.add_parser("verify", help="check a statement the way DEMO.md does")
    p.add_argument("statement")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("request-params", help="params for RequestMint (and later Finalize)")
    p.add_argument("statement")
    p.add_argument("--lbtc-amount", type=int, required=True, help="L-BTC to burn, in satoshis")
    p.add_argument("--recipient", required=True, help="address that receives the tUSDT (or the refund)")
    p.add_argument("--out")
    p.set_defaults(func=cmd_request_params)

    p = sub.add_parser("challenge-params", help="params for Challenge")
    p.add_argument("request", help="the request's params file")
    p.add_argument("statement", help="a newer statement whose price differs")
    p.add_argument("--out")
    p.set_defaults(func=cmd_challenge_params)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
