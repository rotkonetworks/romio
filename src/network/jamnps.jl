# JAM Simple Networking Protocol (JAMNP-S)
#
# Implements the networking protocol for JAM nodes as specified in the JAM graypaper.
# - TLS 1.3 with Ed25519 self-signed certificates
# - Alternative name derived from Ed25519 public key (base32)
# - ALPN: jamnp-s/V/H where V=version, H=genesis hash prefix
# - UP (Unique Persistent) and CE (Common Ephemeral) stream protocols

module JAMNPS

using Quic.Ed25519
using Quic.X509
using Random

const PROTOCOL_VERSION = 0
const BASE32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"

# Stream protocol kinds per graypaper
module StreamKind
    const BLOCK_ANNOUNCEMENT = 0x00
    const BLOCK_REQUEST = 0x80
    const STATE_REQUEST = 0x81
    const SAFROLE_TICKET_PROXY = 0x83
    const SAFROLE_TICKET_DIST = 0x84
    const WORK_PACKAGE_SUBMIT = 0x85
    const WORK_PACKAGE_SHARE = 0x86
    const WORK_REPORT_DIST = 0x87
    const WORK_REPORT_REQUEST = 0x88
    const SHARD_DIST = 0x89
    const AUDIT_SHARD_REQUEST = 0x8a
    const SEGMENT_SHARD_REQUEST_NOJUST = 0x8b
    const SEGMENT_SHARD_REQUEST_JUST = 0x8c
    const ASSURANCE_DIST = 0x8d
    const PREIMAGE_ANNOUNCE = 0x8e
    const PREIMAGE_REQUEST = 0x8f
    const AUDIT_ANNOUNCE = 0x90
    const JUDGMENT_PUBLISH = 0x91
    const WORK_BUNDLE_SUBMIT = 0x92
    const BUNDLE_REQUEST = 0x93
    const SEGMENT_REQUEST = 0x94
end

"""
    derive_alt_name(pubkey::Vector{UInt8}) -> String

Derive X.509 alternative name from Ed25519 public key.
Returns 53-char string: 'e' + 52 base32 characters.
"""
function derive_alt_name(pubkey::Vector{UInt8})::String
    @assert length(pubkey) == 32 "Public key must be 32 bytes"

    n = BigInt(0)
    for i in 32:-1:1
        n = (n << 8) | pubkey[i]
    end

    chars = Char[]
    for _ in 1:52
        idx = Int(n % 32)
        push!(chars, BASE32_ALPHABET[idx + 1])
        n = n ÷ 32
    end

    return "e" * String(chars)
end

"""
    pubkey_from_alt_name(alt_name::String) -> Vector{UInt8}

Recover Ed25519 public key from X.509 alternative name.
"""
function pubkey_from_alt_name(alt_name::String)::Vector{UInt8}
    @assert length(alt_name) == 53 "Alternative name must be 53 characters"
    @assert alt_name[1] == 'e' "Alternative name must start with 'e'"

    n = BigInt(0)
    chars = alt_name[2:end]

    for i in 52:-1:1
        c = chars[i]
        idx = findfirst(==(c), BASE32_ALPHABET) - 1
        n = n * 32 + idx
    end

    pubkey = zeros(UInt8, 32)
    for i in 1:32
        pubkey[i] = UInt8(n & 0xff)
        n >>= 8
    end

    return pubkey
end

"""
    make_alpn(genesis_hash::Vector{UInt8}; builder::Bool=false) -> String

Create ALPN protocol identifier: jamnp-s/V/H or jamnp-s/V/H/builder
"""
function make_alpn(genesis_hash::Vector{UInt8}; builder::Bool=false)::String
    @assert length(genesis_hash) >= 4 "Genesis hash must be at least 4 bytes"
    hash_prefix = bytes2hex(genesis_hash[1:4])
    alpn = "jamnp-s/$PROTOCOL_VERSION/$hash_prefix"
    builder && (alpn *= "/builder")
    return alpn
end

"""
    parse_alpn(alpn::String) -> NamedTuple

Parse JAMNP-S ALPN protocol identifier.
"""
function parse_alpn(alpn::String)
    parts = split(alpn, '/')
    length(parts) < 3 && parts[1] != "jamnp-s" && error("Invalid JAMNP-S ALPN: $alpn")
    version = parse(Int, parts[2])
    genesis_prefix = parts[3]
    is_builder = length(parts) >= 4 && parts[4] == "builder"
    return (version=version, genesis_prefix=genesis_prefix, is_builder=is_builder)
end

"""
    preferred_initiator(key_a::Vector{UInt8}, key_b::Vector{UInt8}) -> Symbol

Determine which peer initiates connection per graypaper spec.
P(a,b) = a when (a[31] > 127) XOR (b[31] > 127) XOR (a < b)
"""
function preferred_initiator(key_a::Vector{UInt8}, key_b::Vector{UInt8})::Symbol
    @assert length(key_a) == 32 && length(key_b) == 32
    a_high = key_a[32] > 127
    b_high = key_b[32] > 127
    a_less = key_a < key_b
    return xor(xor(a_high, b_high), a_less) ? :a : :b
end

# JAMNP-S Identity
mutable struct JAMNPSIdentity
    keypair::Ed25519.KeyPair
    alt_name::String
    certificate::Vector{UInt8}

    function JAMNPSIdentity(keypair::Ed25519.KeyPair)
        alt_name = derive_alt_name(keypair.public_key)
        certificate = X509.generate_x509_certificate(
            keypair;
            subject_cn="JAMNPS",
            issuer_cn="JAMNPS",
            alt_name=alt_name
        )
        new(keypair, alt_name, certificate)
    end
end

generate_identity() = JAMNPSIdentity(Ed25519.generate_keypair())
identity_from_seed(seed::Vector{UInt8}) = JAMNPSIdentity(Ed25519.keypair_from_seed(seed))
identity_from_keypair(keypair::Ed25519.KeyPair) = JAMNPSIdentity(keypair)

function validate_peer_certificate(cert::Vector{UInt8})::Union{Vector{UInt8}, Nothing}
    try
        pubkey = X509.extract_public_key(cert)
        _ = derive_alt_name(pubkey)  # Validate derivation works
        return pubkey
    catch e
        @warn "Failed to validate peer certificate: $e"
        return nothing
    end
end

extract_peer_identity(cert::Vector{UInt8}) = try X509.extract_public_key(cert) catch; nothing end

# Message encoding (4-byte LE length prefix)
function encode_message(content::Vector{UInt8})::Vector{UInt8}
    len = UInt32(length(content))
    buf = Vector{UInt8}(undef, 4 + length(content))
    buf[1] = len & 0xff
    buf[2] = (len >> 8) & 0xff
    buf[3] = (len >> 16) & 0xff
    buf[4] = (len >> 24) & 0xff
    buf[5:end] = content
    return buf
end

function decode_message_header(data::Vector{UInt8})::UInt32
    @assert length(data) >= 4
    return UInt32(data[1]) | (UInt32(data[2]) << 8) | (UInt32(data[3]) << 16) | (UInt32(data[4]) << 24)
end

# Block announcement structures
struct BlockAnnouncement
    header::Vector{UInt8}
    finalized_hash::Vector{UInt8}
    finalized_slot::UInt32
end

struct BlockAnnouncementHandshake
    finalized_hash::Vector{UInt8}
    finalized_slot::UInt32
    leaves::Vector{Tuple{Vector{UInt8}, UInt32}}
end

function encode_handshake(hs::BlockAnnouncementHandshake)::Vector{UInt8}
    buf = UInt8[]
    append!(buf, hs.finalized_hash)
    append!(buf, reinterpret(UInt8, [htol(hs.finalized_slot)]))
    append!(buf, reinterpret(UInt8, [htol(UInt32(length(hs.leaves)))]))
    for (hash, slot) in hs.leaves
        append!(buf, hash)
        append!(buf, reinterpret(UInt8, [htol(slot)]))
    end
    return buf
end

"""
    parse_validator_endpoint(metadata::Vector{UInt8}) -> Tuple{UInt128, UInt16}

Parse validator endpoint from first 18 bytes of metadata.
Returns (IPv6 as UInt128, port).
"""
function parse_validator_endpoint(metadata::Vector{UInt8})
    @assert length(metadata) >= 18 "Metadata must be at least 18 bytes"
    ipv6_bytes = metadata[1:16]
    port = UInt16(metadata[17]) | (UInt16(metadata[18]) << 8)
    ip_val = UInt128(0)
    for i in 1:16
        ip_val = (ip_val << 8) | ipv6_bytes[i]
    end
    return (ip_val, port)
end

export StreamKind
export derive_alt_name, pubkey_from_alt_name
export make_alpn, parse_alpn
export preferred_initiator
export JAMNPSIdentity, generate_identity, identity_from_seed, identity_from_keypair
export validate_peer_certificate, extract_peer_identity
export encode_message, decode_message_header
export BlockAnnouncement, BlockAnnouncementHandshake, encode_handshake
export parse_validator_endpoint

end # module JAMNPS
