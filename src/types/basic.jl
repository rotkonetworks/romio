# src/types/basic.jl
# Basic type definitions

using StaticArrays

# Numeric types
const Balance = UInt64
const Gas = UInt64
const ServiceId = UInt32
const TimeSlot = UInt32
const CoreId = UInt16
const ValidatorId = UInt16

# Fixed-size arrays
const Hash = SVector{32, UInt8}
const Ed25519Key = SVector{32, UInt8}
const Ed25519Sig = SVector{64, UInt8}
const BandersnatchKey = SVector{32, UInt8}
const BandersnatchSig = SVector{96, UInt8}
const BlsKey = SVector{144, UInt8}
const BlsSig = SVector{96, UInt8}

# Dynamic arrays
const Blob = Vector{UInt8}

# Create hash from bytes
function make_hash(bytes::Vector{UInt8})::Hash
    @assert length(bytes) == 32 "Hash must be 32 bytes"
    return SVector{32}(bytes)
end

# Zero hash constant
const H0 = make_hash(zeros(UInt8, 32))
