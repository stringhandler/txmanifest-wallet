# Shared plumbing for the regtest helpers. Sourced, not executed.
#
# Extracted rather than copied into each script: these two must agree about which container
# they talk to, how they report a failure, and where they mine throwaway blocks. Two copies
# agree on the day they are written.

CONTAINER="${FAUCET_CONTAINER:-simplicity-regtest}"
RPCUSER="${FAUCET_RPCUSER:-tx}"
RPCPASS="${FAUCET_RPCPASS:-manifest}"

# A P2TR output paying the BIP341 NUMS point — a key nobody holds. Blocks mined here are
# real blocks whose reward is unspendable by anyone, which is what makes it safe to mine
# hundreds of them just to advance the chain.
BURN="bcrt1p2zffkaxp5py4fdutfdsrt6t6tcrc5ks09rkfd428hlhf4n5q8tqq5az5cr"

die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
note() { printf '\033[2m%s\033[0m\n' "$*"; }
ok()   { printf '\033[32m✓\033[0m %s\n' "$*"; }

cli() {
  docker exec "$CONTAINER" bitcoin-cli -regtest \
    -rpcuser="$RPCUSER" -rpcpassword="$RPCPASS" "$@"
}

# Fail before doing anything, with the command that fixes it.
require_node() {
  docker inspect "$CONTAINER" >/dev/null 2>&1 \
    || die "container '$CONTAINER' not found. Start it:
    docker run -d --name $CONTAINER -p 18443:18443 simplicity-regtest \\
      -regtest -server -rpcbind=0.0.0.0 -rpcallowip=0.0.0.0/0 \\
      -rpcuser=$RPCUSER -rpcpassword=$RPCPASS -fallbackfee=0.0001 -txindex=1"
  [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER")" = "true" ] \
    || die "container '$CONTAINER' exists but is not running: docker start $CONTAINER"
  cli getblockcount >/dev/null 2>&1 \
    || die "cannot reach bitcoind in '$CONTAINER' over RPC"
}

# The header comment block, for --help. Reads the comment rather than a line range, so it
# cannot drift out of step with what it documents.
print_help() {
  awk 'NR>1 { if ($0 ~ /^#/) { sub(/^# ?/, ""); print } else exit }' "$1"
}
