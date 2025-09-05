# src/crypto/hash.jl
using SHA
using Keccak

# blake2b 256-bit hash (primary hash in JAM)
function H(data::Vector{UInt8})::Hash
    result = SHA.blake2b_256(data)
    return Hash(result)
end

# keccak-256 (Ethereum-compatible, used for compatibility)
function HK(data::Vector{UInt8})::Hash
    sponge = Keccak.KeccakSponge{17, UInt64}(Keccak.KeccakPad(0x01))
    sponge = Keccak.absorb(sponge, data)
    sponge = Keccak.pad(sponge)
    result = Keccak.squeeze(sponge, Val(32))[2]
    return Hash(collect(result))
end

# for merkle roots if needed
H0 = Hash(zeros(UInt8, 32))
