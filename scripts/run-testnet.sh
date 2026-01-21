#!/bin/bash
# run-testnet.sh - launch romio multi-node JAM testnet
#
# usage: ./scripts/run-testnet.sh [num_nodes] [base_rpc_port] [base_quic_port]
#
# defaults:
#   num_nodes=6 (like polkajam-testnet)
#   base_rpc_port=19800
#   base_quic_port=40000
#
# requires: julia --threads for QUIC networking

set -e
cd "$(dirname "$0")/.."

NUM_NODES=${1:-6}
BASE_RPC_PORT=${2:-19800}
BASE_QUIC_PORT=${3:-40000}

echo "============================================================"
echo "Romio JAM Testnet (QUIC)"
echo "============================================================"
echo "Nodes:      $NUM_NODES validators"
echo "RPC Ports:  $BASE_RPC_PORT - $((BASE_RPC_PORT + NUM_NODES - 1)) (TCP)"
echo "QUIC Ports: $BASE_QUIC_PORT - $((BASE_QUIC_PORT + NUM_NODES - 1)) (UDP)"
echo "Slot:       6 seconds"
echo "============================================================"
echo ""

# run the julia testnet with threads for QUIC receive
exec julia --threads=auto --project=. -e "
    include(\"src/testnet/multinode.jl\")
    using .MultiNodeTestnet
    run_multinode_testnet(
        num_nodes=$NUM_NODES,
        base_rpc_port=UInt16($BASE_RPC_PORT),
        base_quic_port=UInt16($BASE_QUIC_PORT)
    )
"
