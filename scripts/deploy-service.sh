#!/bin/bash
# deploy-service.sh - deploy a corevm guest to romio testnet
#
# usage: ./scripts/deploy-service.sh [guest.corevm] [gas_limit]
#
# examples:
#   ./scripts/deploy-service.sh                                    # deploy blc-vm with defaults
#   ./scripts/deploy-service.sh corevm-guests/blc-vm/blc-vm.corevm # deploy blc-vm explicitly
#   ./scripts/deploy-service.sh my-guest.corevm 50000000           # custom guest and gas

set -e

GUEST="${1:-corevm-guests/blc-vm/blc-vm.corevm}"
GAS="${2:-100000000}"
RPC="${RPC_URL:-ws://127.0.0.1:19800}"

if [ ! -f "$GUEST" ]; then
    echo "error: guest file not found: $GUEST"
    exit 1
fi

if [ ! -f "./bin/jamt" ]; then
    echo "jamt not found, installing..."
    ./scripts/install-jamt.sh
fi

echo "deploying service to romio testnet"
echo "  guest: $GUEST"
echo "  gas:   $GAS"
echo "  rpc:   $RPC"
echo ""

./bin/jamt --rpc "$RPC" vm new "$GUEST" "$GAS"
