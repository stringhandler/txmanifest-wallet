#!/usr/bin/env bash
#
# Fund a wallet on the local Simplicity regtest.
#
# Mining is how a regtest wallet gets money, and a block reward cannot be spent until it is
# 100 blocks deep. Mining 101 blocks to your own address therefore leaves you one spendable
# coin and a hundred you have to wait on — and every later scan has to walk all of them.
#
# So this mines the coins you asked for to your address, then matures them by mining 100
# blocks to a throwaway address instead. You end up with exactly the UTXOs you wanted, all
# spendable, and nothing extra in your wallet.
#
#   ./contrib/regtest/faucet.sh --wallet /tmp/txm-regtest/wallet.json
#   ./contrib/regtest/faucet.sh --wallet w.json --utxos 5
#   ./contrib/regtest/faucet.sh --address bcrt1p...
#
set -euo pipefail
# Resolved before the cd, or `$0` stops naming this file.
SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
. "$(dirname "$SELF")/_common.sh"

MATURITY=100

wallet="" address="" config="" utxos=1


while [ $# -gt 0 ]; do
  case "$1" in
    --wallet)  wallet="${2:-}"; shift 2 ;;
    --address) address="${2:-}"; shift 2 ;;
    --config)  config="${2:-}"; shift 2 ;;
    --utxos)   utxos="${2:-}"; shift 2 ;;
    -h|--help) print_help "$SELF"; exit 0 ;;
    *) die "unknown argument: $1 (try --help)" ;;
  esac
done


# --- checks, before anything is mined ---------------------------------------
require_node

case "$utxos" in (*[!0-9]*|"") die "--utxos must be a whole number, got '$utxos'" ;; esac
[ "$utxos" -ge 1 ] || die "--utxos must be at least 1"

# --- resolve the address ----------------------------------------------------
if [ -n "$address" ] && [ -n "$wallet" ]; then
  die "pass --wallet or --address, not both"
elif [ -z "$address" ]; then
  [ -n "$wallet" ] || die "need --wallet <file> or --address <addr> (try --help)"
  [ -f "$wallet" ] || die "wallet file not found: $wallet"
  # Derived through the wallet itself rather than read from the file, so the address is
  # the one the wallet will actually scan for — including the network it is configured on.
  note "deriving receive address from $wallet…"
  cfg_args=()
  [ -n "$config" ] && cfg_args=(--config "$config")
  address=$(cargo run -q -p tx-manifest-wallet -- "${cfg_args[@]}" \
              info --wallet "$wallet" 2>/dev/null \
            | awk '/Receive Address/{getline; gsub(/ /,""); print; exit}')
  [ -n "$address" ] || die "could not derive an address. Is the config pointing at a Bitcoin network?
  Try: cargo run -p tx-manifest-wallet -- ${config:+--config $config }info --wallet $wallet"
fi

case "$address" in
  bcrt1*) ;;
  *) die "'$address' is not a regtest address (expected bcrt1…). Check the config's default_network." ;;
esac

# --- mine -------------------------------------------------------------------
before=$(cli getblockcount)
echo
echo "Funding $address"
note "  $utxos coin(s), then $MATURITY blocks to mature them"

cli generatetoaddress "$utxos" "$address" >/dev/null
cli generatetoaddress "$MATURITY" "$BURN"  >/dev/null
after=$(cli getblockcount)

ok "mined $((after - before)) blocks (height $before → $after)"

# --- report -----------------------------------------------------------------
spk=$(cli validateaddress "$address" | sed -n 's/.*"scriptPubKey": "\([0-9a-f]*\)".*/\1/p')
total=$(cli scantxoutset start "[{\"desc\":\"raw($spk)\"}]" \
        | sed -n 's/.*"total_amount": \([0-9.]*\).*/\1/p')
ok "address now holds ${total:-0} BTC, all spendable"
echo
note "check it with:"
note "  cargo run -p tx-manifest-wallet -- ${config:+--config $config }sync --wallet ${wallet:-<wallet>}"
echo
