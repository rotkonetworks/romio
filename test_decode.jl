#!/usr/bin/env julia
# Test decode_immediate and decode_offset

# Simulate decode_immediate
function decode_immediate_test(bytes::Vector{UInt8}, len::Int)
    val = UInt64(0)
    for i in 0:len-1
        if i + 1 <= length(bytes)
            val |= UInt64(bytes[i + 1]) << (8*i)
        end
    end

    # sign extend if MSB is set
    if len > 0 && (val >> (8*len - 1)) & 1 == 1
        val |= ~((UInt64(1) << (8*len)) - 1)
    end

    return val
end

# Simulate decode_offset
function decode_offset_test(bytes::Vector{UInt8}, len::Int)
    val = decode_immediate_test(bytes, len)
    # For small lengths, don't extend to 64 bits
    if len <= 4
        # Truncate to actual bit width
        mask = (UInt64(1) << (8*len)) - 1
        val = val & mask
        # Sign extend from actual width
        if len > 0 && (val >> (8*len - 1)) & 1 == 1
            # It's negative, extend the sign
            sign_bits = ~mask
            val = val | sign_bits
        end
    end
    # Convert to Int32 by taking low 32 bits (% gives unchecked truncation) and reinterpreting
    return reinterpret(Int32, val % UInt32)
end

println("Testing immediate/offset decoding:")
println()

# Test case 1: Single byte 0xf8 (negative)
bytes = UInt8[0xf8]
imm = decode_immediate_test(bytes, 1)
off = decode_offset_test(bytes, 1)
println("Bytes: [0xf8]")
println("  decode_immediate: 0x$(string(imm, base=16, pad=16)) = $(reinterpret(Int64, imm))")
println("  decode_offset: $(off)")
println()

# Test case 2: Two bytes 0x00, 0x01 (256)
bytes = UInt8[0x00, 0x01]
imm = decode_immediate_test(bytes, 2)
off = decode_offset_test(bytes, 2)
println("Bytes: [0x00, 0x01]")
println("  decode_immediate: 0x$(string(imm, base=16, pad=16)) = $(reinterpret(Int64, imm))")
println("  decode_offset: $(off)")
println()

# Test case 3: Single byte 0x1e (30)
bytes = UInt8[0x1e]
imm = decode_immediate_test(bytes, 1)
off = decode_offset_test(bytes, 1)
println("Bytes: [0x1e]")
println("  decode_immediate: 0x$(string(imm, base=16, pad=16)) = $(reinterpret(Int64, imm))")
println("  decode_offset: $(off)")
println()
