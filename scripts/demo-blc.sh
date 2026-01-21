#!/bin/bash
# demo-blc.sh - demonstrate blc cli with jam testnet
#
# architecture:
#   - jam node rpc (port 19800): jip-2 standard + romio_refine
#   - blc service rpc (port 19801): blc_eval, blc_parse, blc_encode, blc_prelude

set -e
cd "$(dirname "$0")/.."

BLC=./bin/blc

echo "=== BLC CLI Demo ==="
echo ""

echo "--- Local Operations (no network needed) ---"
echo ""

echo "1. Parse BLC from hex (identity function):"
$BLC parse 0x20
echo ""

echo "2. Show Church TRUE from prelude:"
$BLC prelude true
echo ""

echo "3. Encode lambda notation to hex:"
echo "   Input: \\.0 (identity)"
$BLC encode '\\.0'
echo ""

echo "--- Network Evaluation (via BLC Service RPC) ---"
echo ""
echo "Note: requires blc service running on port 19801"
echo "      start with: ./scripts/run-blc-service.sh"
echo ""

echo "4. Evaluate identity function:"
$BLC eval 0x20
echo ""

echo "5. Evaluate (I I) -> I (identity applied to identity):"
$BLC eval '(\\.0 \\.0)'
echo ""

echo "6. Evaluate Church TRUE:"
$BLC eval 0x0C
echo ""

echo "7. Evaluate Church FALSE:"
$BLC eval 0x08
echo ""

echo "=== Demo Complete ==="
echo ""
echo "Architecture:"
echo "  BLC Service RPC: ws://localhost:19801 (blc_eval, blc_parse, etc)"
echo "  JAM Node RPC:    ws://localhost:19800 (jip-2 + romio_refine)"
