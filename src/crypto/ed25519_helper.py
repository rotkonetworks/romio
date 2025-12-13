#!/usr/bin/env python3
"""
Ed25519 signature verification helper.
Uses PyNaCl (libsodium) for Ed25519 operations.
"""
import sys
import json
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError


def verify_ed25519(public_key_hex: str, message_hex: str, signature_hex: str) -> bool:
    """
    Verify an Ed25519 signature.

    Args:
        public_key_hex: 32-byte public key as hex string
        message_hex: Message bytes as hex string
        signature_hex: 64-byte signature as hex string

    Returns:
        True if signature is valid, False otherwise
    """
    # Remove 0x prefix if present
    if public_key_hex.startswith("0x"):
        public_key_hex = public_key_hex[2:]
    if message_hex.startswith("0x"):
        message_hex = message_hex[2:]
    if signature_hex.startswith("0x"):
        signature_hex = signature_hex[2:]

    try:
        public_key = bytes.fromhex(public_key_hex)
        message = bytes.fromhex(message_hex)
        signature = bytes.fromhex(signature_hex)

        # Create verify key from public key bytes
        verify_key = VerifyKey(public_key)

        # Verify signature (raises BadSignature on failure)
        verify_key.verify(message, signature)
        return True
    except BadSignatureError:
        return False
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return False


def batch_verify(verifications: list) -> list:
    """
    Verify a batch of Ed25519 signatures.

    Args:
        verifications: List of {"public_key": hex, "message": hex, "signature": hex}

    Returns:
        List of boolean results
    """
    results = []
    for v in verifications:
        result = verify_ed25519(v["public_key"], v["message"], v["signature"])
        results.append(result)
    return results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: ed25519_helper.py <command> [args...]", file=sys.stderr)
        print("Commands:", file=sys.stderr)
        print("  verify <public_key_hex> <message_hex> <signature_hex>", file=sys.stderr)
        print("  batch_verify  (reads JSON from stdin)", file=sys.stderr)
        sys.exit(1)

    command = sys.argv[1]

    if command == "verify":
        if len(sys.argv) < 5:
            print("Usage: ed25519_helper.py verify <public_key_hex> <message_hex> <signature_hex>", file=sys.stderr)
            sys.exit(1)
        public_key_hex = sys.argv[2]
        message_hex = sys.argv[3]
        signature_hex = sys.argv[4]

        result = verify_ed25519(public_key_hex, message_hex, signature_hex)
        print("true" if result else "false")

    elif command == "batch_verify":
        # Read verification data from stdin (JSON array)
        data = json.loads(sys.stdin.read())
        results = batch_verify(data)
        print(json.dumps(results))

    else:
        print(f"Unknown command: {command}", file=sys.stderr)
        sys.exit(1)
