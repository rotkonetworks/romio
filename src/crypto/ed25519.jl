# Ed25519 signature verification using libsodium
# Native Julia implementation via libsodium_jll

using libsodium_jll

"""
    verify_ed25519(public_key::Vector{UInt8}, message::Vector{UInt8}, signature::Vector{UInt8}) -> Bool

Verify an Ed25519 signature.
- public_key: 32-byte Ed25519 public key
- message: arbitrary-length message bytes
- signature: 64-byte Ed25519 signature
Returns true if signature is valid, false otherwise.
"""
function verify_ed25519(public_key::Vector{UInt8}, message::Vector{UInt8}, signature::Vector{UInt8})::Bool
    if length(public_key) != 32
        @warn "Invalid public key length: $(length(public_key)), expected 32"
        return false
    end
    if length(signature) != 64
        @warn "Invalid signature length: $(length(signature)), expected 64"
        return false
    end

    result = ccall((:crypto_sign_verify_detached, libsodium), Cint,
        (Ptr{UInt8}, Ptr{UInt8}, Culonglong, Ptr{UInt8}),
        signature, message, length(message), public_key)

    return result == 0
end

"""
    verify_ed25519_hex(public_key_hex::String, message_hex::String, signature_hex::String) -> Bool

Verify an Ed25519 signature with hex-encoded inputs.
"""
function verify_ed25519_hex(public_key_hex::String, message_hex::String, signature_hex::String)::Bool
    # Remove 0x prefix if present
    pk_hex = startswith(public_key_hex, "0x") ? public_key_hex[3:end] : public_key_hex
    msg_hex = startswith(message_hex, "0x") ? message_hex[3:end] : message_hex
    sig_hex = startswith(signature_hex, "0x") ? signature_hex[3:end] : signature_hex

    # Pad to even length
    if length(pk_hex) % 2 != 0
        pk_hex = "0" * pk_hex
    end
    if length(msg_hex) % 2 != 0
        msg_hex = "0" * msg_hex
    end
    if length(sig_hex) % 2 != 0
        sig_hex = "0" * sig_hex
    end

    # Parse hex to bytes
    public_key = [parse(UInt8, pk_hex[i:i+1], base=16) for i in 1:2:length(pk_hex)]
    message = [parse(UInt8, msg_hex[i:i+1], base=16) for i in 1:2:length(msg_hex)]
    signature = [parse(UInt8, sig_hex[i:i+1], base=16) for i in 1:2:length(sig_hex)]

    return verify_ed25519(public_key, message, signature)
end

export verify_ed25519, verify_ed25519_hex
