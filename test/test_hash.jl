# test_hash.jl
using Pkg
Pkg.activate(".")

include("../src/JAM.jl")
using .JAM

# Test Blake2b hash
test_data = b"hello jam"
h = JAM.H(test_data)
println("Blake2b hash: ", bytes2hex(h))
println("Hash length: ", length(h))

# Test with empty data
h_empty = JAM.H(UInt8[])
println("Empty hash: ", bytes2hex(h_empty))

# Test H0 constant
println("H0: ", bytes2hex(JAM.H0))
println("H0 is zeros: ", JAM.H0 == JAM.Hash(zeros(UInt8, 32)))

# Test Keccak
hk = JAM.HK(test_data)
println("Keccak hash: ", bytes2hex(hk))
