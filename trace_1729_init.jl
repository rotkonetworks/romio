#!/usr/bin/env julia
include("src/stf/accumulate.jl")

# Manually trace what service 1729 reads from the stack
println("Service 1729 reads from stack:")
println("  [r1 + 32] -> r10")
println("  [r1 + 40] -> r7")
println("  [r1 + 48] -> r9")
println("  [r1 + 56] -> r8")
println()

# Calculate what we write
sp = UInt32(UInt64(2^32) - UInt64(2)*UInt64(65536) - UInt64(16777216))
input_addr = UInt64(2^32 - 65536 - 16777216)
input_len = UInt64(12)

println("Stack pointer (r1): 0x$(string(sp, base=16))")
println()
println("We write:")
println("  [SP + 40] = input_addr = 0x$(string(input_addr, base=16))")
println("  [SP + 56] = input_len = $input_len")
println()
println("So r7 = 0x$(string(input_addr, base=16)) (input address)")
println("   r8 = $input_len (input length)")
println()
println("But r8 might need to be a pointer, not length.")
println("Let's see what the program does with these values...")
