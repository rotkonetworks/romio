#!/bin/bash
# run-blc-service.sh - start standalone blc service rpc
#
# usage: ./scripts/run-blc-service.sh [port]
#
# this service provides blc-specific rpc methods and can run
# independently of any jam node. connect via ws://localhost:19801
#
# methods:
#   blc_eval    - evaluate blc term
#   blc_parse   - parse hex/lambda notation
#   blc_encode  - encode term to hex
#   blc_prelude - get standard combinators

set -e
cd "$(dirname "$0")/.."

PORT=${1:-19801}

echo "============================================================"
echo "BLC Service RPC"
echo "============================================================"
echo "Port: $PORT (WebSocket)"
echo "Methods: blc_eval, blc_parse, blc_encode, blc_prelude"
echo "============================================================"
echo ""

exec julia --project=. -e "
    include(\"src/services/blc_rpc.jl\")
    using .BLCService
    start_blc_service(UInt16($PORT))
"
