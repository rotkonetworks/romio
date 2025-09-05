# src/crypto/hash.jl
using Blake2
using Keccak

# blake2b 256-bit hash (primary hash in JAM)
function H(data::Vector{UInt8})::Hash
    out = zeros(UInt8, 32)
    Blake2.Blake2b!(out, 32, UInt8[], 0, data, length(data))
    return Hash(out)
end

# keccak-256 (Ethereum-compatibility)
function HK(data::Vector{UInt8})::Hash
    sponge = Keccak.KeccakSponge{17, UInt64}(Keccak.KeccakPad(0x01))
    sponge = Keccak.absorb(sponge, data)
    sponge = Keccak.pad(sponge)
    result = Keccak.squeeze(sponge, Val(32))[2]
    return Hash(collect(result))
end

# for merkle roots if needed
H0 = Hash(zeros(UInt8, 32))
