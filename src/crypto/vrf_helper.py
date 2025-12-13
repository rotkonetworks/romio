#!/usr/bin/env python3
"""
VRF helper for computing ticket IDs from ring VRF signatures.
Uses the jam-vrf library for Bandersnatch VRF operations.
"""
import sys
import json
import jam_vrf

def compute_ticket_id(signature_hex: str) -> str:
    """
    Compute the ticket ID from a ring VRF signature.

    Args:
        signature_hex: Hex string of signature (with or without 0x prefix)

    Returns:
        Hex string of the 32-byte ticket ID
    """
    # Remove 0x prefix if present
    if signature_hex.startswith("0x"):
        signature_hex = signature_hex[2:]

    sig_bytes = bytes.fromhex(signature_hex)

    # Extract VRF output point (first 32 bytes)
    vrf_output_bytes = sig_bytes[:32]

    # Compute hash (ticket ID)
    vrf_output = jam_vrf.VRFOutput(vrf_output_bytes)
    ticket_id_full = vrf_output.hash()

    # Return first 32 bytes as hex
    return ticket_id_full[:32].hex()


def verify_ring_signature(
    commitment_hex: str,
    ring_size: int,
    entropy_hex: str,
    attempt: int,
    signature_hex: str
) -> tuple[bool, str]:
    """
    Verify a ring VRF signature for a Safrole ticket.

    Args:
        commitment_hex: Ring commitment (gamma_z from state)
        ring_size: Number of validators in ring
        entropy_hex: Epoch entropy (eta_2)
        attempt: Ticket attempt number (0, 1, or 2)
        signature_hex: Ring VRF signature

    Returns:
        Tuple of (is_valid, ticket_id_hex)
    """
    # Remove 0x prefix if present
    if commitment_hex.startswith("0x"):
        commitment_hex = commitment_hex[2:]
    if entropy_hex.startswith("0x"):
        entropy_hex = entropy_hex[2:]
    if signature_hex.startswith("0x"):
        signature_hex = signature_hex[2:]

    commitment = bytes.fromhex(commitment_hex)
    entropy = bytes.fromhex(entropy_hex)
    signature = bytes.fromhex(signature_hex)

    # Construct VRF input: "jam_ticket_seal" + entropy + attempt
    data = b"jam_ticket_seal" + entropy + bytes([attempt])

    # Create verifier
    try:
        verifier = jam_vrf.RingVerifier(commitment, ring_size)

        # Verify signature
        verifier.verify([(data, b"", signature)])

        # If we get here, signature is valid - compute ticket ID
        ticket_id = compute_ticket_id(signature_hex)
        return (True, ticket_id)
    except Exception as e:
        # Verification failed
        return (False, str(e))


if __name__ == "__main__":
    # Command-line interface
    if len(sys.argv) < 2:
        print("Usage: vrf_helper.py <command> [args...]", file=sys.stderr)
        print("Commands:", file=sys.stderr)
        print("  ticket_id <signature_hex>", file=sys.stderr)
        print("  verify <commitment_hex> <ring_size> <entropy_hex> <attempt> <signature_hex>", file=sys.stderr)
        sys.exit(1)

    command = sys.argv[1]

    if command == "ticket_id":
        if len(sys.argv) < 3:
            print("Usage: vrf_helper.py ticket_id <signature_hex>", file=sys.stderr)
            sys.exit(1)
        signature_hex = sys.argv[2]
        ticket_id = compute_ticket_id(signature_hex)
        print(ticket_id)

    elif command == "verify":
        if len(sys.argv) < 7:
            print("Usage: vrf_helper.py verify <commitment_hex> <ring_size> <entropy_hex> <attempt> <signature_hex>", file=sys.stderr)
            sys.exit(1)
        commitment_hex = sys.argv[2]
        ring_size = int(sys.argv[3])
        entropy_hex = sys.argv[4]
        attempt = int(sys.argv[5])
        signature_hex = sys.argv[6]

        is_valid, result = verify_ring_signature(
            commitment_hex, ring_size, entropy_hex, attempt, signature_hex
        )
        print(json.dumps({"valid": is_valid, "result": result}))

    elif command == "batch_ticket_ids":
        # Read signatures from stdin (JSON array)
        signatures = json.loads(sys.stdin.read())
        results = []
        for sig in signatures:
            try:
                ticket_id = compute_ticket_id(sig)
                results.append({"ok": ticket_id})
            except Exception as e:
                results.append({"error": str(e)})
        print(json.dumps(results))

    elif command == "batch_verify":
        # Read verification data from stdin (JSON object)
        # Format: {"commitment": hex, "ring_size": int, "entropy": hex, "tickets": [{attempt, signature}]}
        data = json.loads(sys.stdin.read())

        commitment_hex = data["commitment"]
        ring_size = data["ring_size"]
        entropy_hex = data["entropy"]
        tickets = data["tickets"]

        # Remove 0x prefix if present
        if commitment_hex.startswith("0x"):
            commitment_hex = commitment_hex[2:]
        if entropy_hex.startswith("0x"):
            entropy_hex = entropy_hex[2:]

        commitment = bytes.fromhex(commitment_hex)
        entropy = bytes.fromhex(entropy_hex)

        # Create verifier
        try:
            verifier = jam_vrf.RingVerifier(commitment, ring_size)
        except Exception as e:
            # Invalid commitment - all tickets fail
            results = [{"error": f"Invalid commitment: {e}"} for _ in tickets]
            print(json.dumps(results))
            sys.exit(0)

        results = []
        for t in tickets:
            sig_hex = t["signature"]
            if sig_hex.startswith("0x"):
                sig_hex = sig_hex[2:]
            signature = bytes.fromhex(sig_hex)
            attempt = t["attempt"]

            # Construct VRF input: "jam_ticket_seal" + entropy + attempt
            vrf_data = b"jam_ticket_seal" + entropy + bytes([attempt])

            try:
                # Verify single signature
                verifier.verify([(vrf_data, b"", signature)])
                # If valid, compute ticket ID
                ticket_id = compute_ticket_id(sig_hex)
                results.append({"ok": ticket_id})
            except Exception as e:
                results.append({"error": str(e)})

        print(json.dumps(results))

    else:
        print(f"Unknown command: {command}", file=sys.stderr)
        sys.exit(1)
