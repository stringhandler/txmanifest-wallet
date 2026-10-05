#!/usr/bin/env bash
#
# Mine blocks on the local Simplicity regtest.
#
# Nothing confirms on regtest until a block is mined, so this is what you run after
# broadcasting. Blocks go to an unspendable address by default, so mining never quietly
# adds coins to a wallet you are testing with — use `faucet.sh` when you want funds.
#
#   ./contrib/regtest/mine.sh                 # one block
#   ./contrib/regtest/mine.sh 6               # six
#   ./contrib/regtest/mine.sh --txid <txid>   # one block, then report that tx
#   ./contrib/regtest/mine.sh 144 --to bcrt1p…  # to a specific address
#
set -euo pipefail
# Resolved before the cd, or `$0` stops naming this file.
SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
. "$(dirname "$SELF")/_common.sh"

blocks=1 target="" txid=""

while [ $# -gt 0 ]; do
  case "$1" in
    --to)      target="${2:-}"; shift 2 ;;
    --txid)    txid="${2:-}"; shift 2 ;;
    -h|--help) print_help "$SELF"; exit 0 ;;
    -*)        die "unknown argument: $1 (try --help)" ;;
    *)         blocks="$1"; shift ;;
  esac
done

case "$blocks" in (*[!0-9]*|"") die "block count must be a whole number, got '$blocks'" ;; esac
[ "$blocks" -ge 1 ] || die "block count must be at least 1"

require_node

if [ -n "$target" ]; then
  case "$target" in
    bcrt1*) ;;
    *) die "'$target' is not a regtest address (expected bcrt1…)" ;;
  esac
else
  target="$BURN"
fi

# Checked before mining: a txid that does not exist is almost always a typo or a
# transaction that was never broadcast, and mining first would hide which.
if [ -n "$txid" ] && ! cli getrawtransaction "$txid" true >/dev/null 2>&1; then
  die "transaction $txid is not known to this node — was it broadcast?"
fi

before=$(cli getblockcount)
cli generatetoaddress "$blocks" "$target" >/dev/null
after=$(cli getblockcount)
ok "mined $blocks block(s) — height $before → $after"

if [ -n "$txid" ]; then
  tx_json="$(mktemp)"
  trap 'rm -f "$tx_json"' EXIT
  cli getrawtransaction "$txid" true > "$tx_json" 2>/dev/null \
    || die "transaction $txid disappeared after mining"
  # The file is passed by path, not piped: the heredoc already occupies stdin.
  python3 - "$txid" "$tx_json" <<'PY'
import json, sys
with open(sys.argv[2]) as f:
    d = json.load(f)
conf = d.get("confirmations", 0)
if conf:
    print(f"\033[32m✓\033[0m {sys.argv[1][:16]}… confirmed ({conf} confirmation(s))")
else:
    # Mined a block and it is still unconfirmed: it never reached the mempool, which is a
    # different problem from "not yet mined" and worth saying so.
    print(f"\033[31m✗\033[0m {sys.argv[1][:16]}… still unconfirmed — not in the mempool?")
for i, o in enumerate(d.get("vout", [])):
    spk = o.get("scriptPubKey", {})
    print(f"  out[{i}] {o.get('value')} BTC -> {spk.get('address', spk.get('type', '?'))}")
PY
fi
