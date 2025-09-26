# src/crypto/hash.jl
using Keccak
using StaticArrays

# Include Blake2b implementation
include("Blake2b.jl")

# blake2b 256-bit hash (primary hash in JAM)
function H(data::Union{Vector{UInt8}, Base.CodeUnits{UInt8, String}})::Hash
  input = Vector{UInt8}(data)
  output = zeros(UInt8, 32)
  Blake2b!(output, 32, UInt8[], 0, input, length(input))
  return Hash(output)
end

# keccak-256 (Ethereum-compatibility)
function HK(data::Union{Vector{UInt8}, Base.CodeUnits{UInt8, String}})::Hash
  sponge = Keccak.KeccakSponge{17, UInt64}(Keccak.KeccakPad(0x01))
  sponge = Keccak.absorb(sponge, Vector{UInt8}(data))
  sponge = Keccak.pad(sponge)
  result = Keccak.squeeze(sponge, Val(32))[2]
  return Hash(collect(result))
end

# for merkle roots if needed
const H0 = Hash(zeros(UInt8, 32))
