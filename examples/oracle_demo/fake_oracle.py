#!/usr/bin/env python3
"""A stand-in for the Mycelia Signal price oracle, for testnet demos only.

It signs BTC/USD price statements in Mycelia Signal's exact format (its docs/DEMO.md):
a pipe-separated canonical string, signed with secp256k1 ECDSA over sha256(canonical),
returned as the same JSON the paid API endpoint returns. The key is a local test key,
so nothing here is a real price.

It also plays the cold key that certifies oracle keys: a BIP340 signature over the
oracle's compressed pubkey and the range of statement timestamps it may sign. The
oracle doesn't take part, so a real oracle's published key can be certified the same way.

And it turns a statement and its certificate into the --params file for an oracle_demo
action. The covenant cannot split a string, so the canonical string is handed to it
already cut into its fields, each as a SimplicityHL literal.

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

CERT_TAG = "oracle-demo/oracle-cert/v1"


# ---------------------------------------------------------------------------
# BIP340 Schnorr, after the BIP's reference implementation. `ecdsa` has no Schnorr.
# ---------------------------------------------------------------------------

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def tagged_hash(tag, msg):
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()


def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if p1[0] == p2[0] and p1[1] != p2[1]:
        return None
    if p1 == p2:
        lam = 3 * p1[0] * p1[0] * pow(2 * p1[1], P - 2, P) % P
    else:
        lam = (p2[1] - p1[1]) * pow(p2[0] - p1[0], P - 2, P) % P
    x3 = (lam * lam - p1[0] - p2[0]) % P
    return (x3, (lam * (p1[0] - x3) - p1[1]) % P)


def point_mul(point, n):
    result = None
    for i in range(256):
        if (n >> i) & 1:
            result = point_add(result, point)
        point = point_add(point, point)
    return result


def lift_x(x):
    if x >= P:
        return None
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if pow(y, 2, P) != y_sq:
        return None
    return (x, y if y % 2 == 0 else P - y)


def int_from(b):
    return int.from_bytes(b, "big")


def bytes_from(n):
    return n.to_bytes(32, "big")


def schnorr_pubkey(secret):
    return bytes_from(point_mul(G, int_from(secret))[0])


def schnorr_verify(msg, pubkey, sig):
    point = lift_x(int_from(pubkey))
    r, s = int_from(sig[:32]), int_from(sig[32:])
    if point is None or r >= P or s >= N:
        return False
    e = int_from(tagged_hash("BIP0340/challenge", sig[:32] + pubkey + msg)) % N
    R = point_add(point_mul(G, s), point_mul(point, N - e))
    return R is not None and R[1] % 2 == 0 and R[0] == r


def schnorr_sign(msg, secret):
    # Zero auxiliary randomness keeps signatures, and so the test fixtures, deterministic.
    d0 = int_from(secret)
    point = point_mul(G, d0)
    d = d0 if point[1] % 2 == 0 else N - d0
    t = bytes_from(d ^ int_from(tagged_hash("BIP0340/aux", bytes(32))))
    k0 = int_from(tagged_hash("BIP0340/nonce", t + bytes_from(point[0]) + msg)) % N
    R = point_mul(G, k0)
    k = k0 if R[1] % 2 == 0 else N - k0
    e = int_from(tagged_hash("BIP0340/challenge", bytes_from(R[0]) + bytes_from(point[0]) + msg)) % N
    sig = bytes_from(R[0]) + bytes_from((k + e * d) % N)
    assert schnorr_verify(msg, bytes_from(point[0]), sig)
    return sig


# ---------------------------------------------------------------------------
# Certificates
# ---------------------------------------------------------------------------


def cert_message(oracle_pubkey, valid_from, valid_until):
    body = bytes.fromhex(oracle_pubkey) + valid_from.to_bytes(8, "big") + valid_until.to_bytes(8, "big")
    return tagged_hash(CERT_TAG, body)


def verify_cert(cert):
    msg = cert_message(cert["oracle_pubkey"], cert["valid_from"], cert["valid_until"])
    return schnorr_verify(msg, bytes.fromhex(cert["cold_pubkey"]), bytes.fromhex(cert["signature"]))


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


def statement_params(statement, cert):
    """The STATEMENT_* and CERT_* witness params for one signed statement."""
    if not verify(statement):
        sys.exit("the statement's signature does not verify")
    if not verify_cert(cert):
        sys.exit("the cold key did not sign this certificate")
    if cert["oracle_pubkey"] != statement["pubkey"]:
        sys.exit("the certificate is for a different oracle key than the one that signed the statement")
    fields = parse_canonical(statement["canonical"])
    if not cert["valid_from"] <= fields["timestamp"] <= cert["valid_until"]:
        sys.exit("the statement's timestamp is outside the certificate's range")
    r, s = sigdecode_der(base64.b64decode(statement["signature"]), N)
    frac = fields["price_frac"].encode()
    key = cert["oracle_pubkey"]
    return fields, {
        "STATEMENT_PRICE_INT": simf_list(fields["price_int"]),
        "STATEMENT_PRICE_FRAC": f"({frac[0]}, {frac[1]})",
        "STATEMENT_SOURCES": simf_list(fields["sources"]),
        "STATEMENT_METHOD": simf_list(fields["method"]),
        "STATEMENT_TIMESTAMP": simf_list(fields["timestamp_digits"]),
        "STATEMENT_NONCE": simf_list(fields["nonce"]),
        "STATEMENT_SIG": f"(0x{r:064x}, 0x{s:064x})",
        "CERT_ORACLE_KEY": f"({int(key[:2], 16)}, 0x{key[2:]})",
        "CERT_VALID_FROM": str(cert["valid_from"]),
        "CERT_VALID_UNTIL": str(cert["valid_until"]),
        "CERT_SIG": "0x" + cert["signature"],
    }


def load_json(path):
    return json.loads(Path(path).read_text())


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
    print(f"oracle pubkey: {pubkey}; certify it with `certify`", file=sys.stderr)


def cmd_cold_keygen(args):
    if Path(args.out).exists() and not args.force:
        sys.exit(f"{args.out} exists; pass --force to replace it")
    secret = SigningKey.generate(curve=SECP256k1).to_string()
    pubkey = schnorr_pubkey(secret).hex()
    write_json({"note": TEST_KEY_NOTE, "secret": secret.hex(), "pubkey": pubkey}, args.out)
    print(f"COLD_PUBKEY={pubkey}", file=sys.stderr)


def cmd_certify(args):
    cold = json.loads(Path(args.cold_key).read_text())
    oracle_pubkey = args.oracle_pubkey
    if oracle_pubkey is None:
        oracle_pubkey = compressed_pubkey(load_key(args.oracle_key).get_verifying_key())
    if len(bytes.fromhex(oracle_pubkey)) != 33 or oracle_pubkey[:2] not in ("02", "03"):
        sys.exit("--oracle-pubkey must be a 33-byte compressed key")
    valid_from = args.valid_from if args.valid_from is not None else int(time.time())
    valid_until = args.valid_until if args.valid_until is not None else valid_from + args.days * 86400
    if valid_until < valid_from:
        sys.exit("--valid-until is before --valid-from")
    msg = cert_message(oracle_pubkey, valid_from, valid_until)
    cert = {
        "oracle_pubkey": oracle_pubkey,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "cold_pubkey": cold["pubkey"],
        "signature": schnorr_sign(msg, bytes.fromhex(cold["secret"])).hex(),
        "scheme": "bip340",
        "tag": CERT_TAG,
    }
    assert verify_cert(cert)
    write_json(cert, args.out)


def cmd_verify_cert(args):
    cert = json.loads(Path(args.cert).read_text())
    if not verify_cert(cert):
        sys.exit("INVALID: the cold key did not sign this certificate")
    print(f"valid: {cert['oracle_pubkey']} may sign statements from {cert['valid_from']} to {cert['valid_until']}")


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
    statement = load_json(args.statement)
    fields, params = statement_params(statement, load_json(args.cert))
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
    request = load_json(args.request)
    statement = load_json(args.statement)
    fields, params = statement_params(statement, load_json(args.cert))
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

    p = sub.add_parser("cold-keygen", help="create the test cold key, which certifies oracle keys")
    p.add_argument("--out", default="data/example_cold_key.json")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_cold_keygen)

    p = sub.add_parser("certify", help="certify an oracle key for a range of statement timestamps")
    p.add_argument("--cold-key", default="data/example_cold_key.json")
    p.add_argument("--oracle-key", default="data/example_oracle_key.json", help="key file to certify")
    p.add_argument("--oracle-pubkey", help="compressed pubkey to certify, instead of --oracle-key")
    p.add_argument("--valid-from", type=int, help="unix seconds (default: now)")
    p.add_argument("--valid-until", type=int, help="unix seconds (default: --days after --valid-from)")
    p.add_argument("--days", type=int, default=30)
    p.add_argument("--out")
    p.set_defaults(func=cmd_certify)

    p = sub.add_parser("verify-cert", help="check the cold key signed a certificate")
    p.add_argument("cert")
    p.set_defaults(func=cmd_verify_cert)

    p = sub.add_parser("request-params", help="params for RequestMint (and later Finalize)")
    p.add_argument("statement")
    p.add_argument("--cert", required=True, help="the certificate for the key that signed the statement")
    p.add_argument("--lbtc-amount", type=int, required=True, help="L-BTC to burn, in satoshis")
    p.add_argument("--recipient", required=True, help="address that receives the tUSDT (or the refund)")
    p.add_argument("--out")
    p.set_defaults(func=cmd_request_params)

    p = sub.add_parser("challenge-params", help="params for Challenge")
    p.add_argument("request", help="the request's params file")
    p.add_argument("statement", help="a newer statement whose price differs")
    p.add_argument("--cert", required=True, help="the certificate for the key that signed it")
    p.add_argument("--out")
    p.set_defaults(func=cmd_challenge_params)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
