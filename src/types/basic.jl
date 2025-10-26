# src/types/basic.jl
using StaticArrays

# numeric types
const Balance = UInt64
const Gas = UInt64
const ServiceId = UInt32
const TimeSlot = UInt32
const CoreId = UInt16
const ValidatorId = UInt16

# hash types
const Hash = SVector{32, UInt8}
const Ed25519Key = SVector{32, UInt8}
const Ed25519Sig = SVector{64, UInt8}
const BandersnatchKey = SVector{32, UInt8}
const BandersnatchSig = SVector{96, UInt8}
const BandersnatchRingRoot = SVector{144, UInt8}
const BandersnatchRingProof = SVector{784, UInt8}
const BlsKey = SVector{144, UInt8}
const BlsSig = SVector{96, UInt8}

# dynamic arrays
const Blob = Vector{UInt8}

# zero hash
const H0 = Hash(zeros(UInt8, 32))

# tagged union for imports
struct Tagged{T}
    value::T
end

# generic encoding function
function encode(x)::Vector{UInt8}
    # simplified encoding - serialize struct to bytes
    io = IOBuffer()
    # write type fields sequentially
    for field in fieldnames(typeof(x))
        value = getfield(x, field)
        if isa(value, Vector{UInt8})
            write(io, value)
        elseif isa(value, Integer)
            write(io, value)
        elseif isa(value, SVector)
            write(io, value)
        else
            # recursively encode complex types
            write(io, encode(value))
        end
    end
    return take!(io)
end
