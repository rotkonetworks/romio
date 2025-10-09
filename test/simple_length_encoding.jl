# Test simpler length encoding approach
using JSON

const TEST_VECTORS_PATH = joinpath(@__DIR__, "../jamtestvectors")

function hex_to_bytes(hex_str::String)::Vector{UInt8}
    if startswith(hex_str, "0x")
        hex_str = hex_str[3:end]
    end
    return [parse(UInt8, hex_str[i:i+1], base=16) for i in 1:2:length(hex_str)]
end

"""
Simple length encoding - just the length byte for small arrays
"""
function encode_length_simple(len::Integer)::Vector{UInt8}
    if len < 64
        return [UInt8(len)]
    else
        error("Complex length encoding not implemented yet for length $len")
    end
end

"""
Test simple encoding approach
"""
function test_simple_encoding()
    println("🚀 Testing Simple Length Encoding")
    println("=" ^ 50)

    # Load test vector
    json_path = joinpath(TEST_VECTORS_PATH, "codec", "tiny", "work_item.json")
    bin_path = joinpath(TEST_VECTORS_PATH, "codec", "tiny", "work_item.bin")

    json_data = JSON.parsefile(json_path)
    official_binary = read(bin_path)

    println("Building encoding step by step...")

    result = UInt8[]

    # 1. Service ID (4 bytes)
    service_id = UInt32(json_data["service"])
    append!(result, reinterpret(UInt8, [service_id]))
    println("After service ID: $(length(result)) bytes")

    # 2. Code hash (32 bytes)
    code_hash = hex_to_bytes(json_data["code_hash"])
    append!(result, code_hash)
    println("After code hash: $(length(result)) bytes")

    # 3. Refine gas limit (8 bytes)
    refine_gas = UInt64(json_data["refine_gas_limit"])
    append!(result, reinterpret(UInt8, [refine_gas]))
    println("After refine gas: $(length(result)) bytes")

    # 4. Accumulate gas limit (8 bytes)
    accumulate_gas = UInt64(json_data["accumulate_gas_limit"])
    append!(result, reinterpret(UInt8, [accumulate_gas]))
    println("After accumulate gas: $(length(result)) bytes")

    # 5. Export count (1 byte)
    export_count = UInt8(json_data["export_count"])
    push!(result, export_count)
    println("After export count: $(length(result)) bytes")

    # Check against official binary up to this point
    println("\nChecking first $(length(result)) bytes...")
    first_part_matches = result == official_binary[1:length(result)]
    println("First part matches: $first_part_matches")

    if !first_part_matches
        for i in 1:length(result)
            if result[i] != official_binary[i]
                println("Difference at byte $i: ours=0x$(string(result[i], base=16, pad=2)), official=0x$(string(official_binary[i], base=16, pad=2))")
                break
            end
        end
        return false
    end

    # 6. Look at what comes next in the official binary
    next_offset = length(result) + 1
    next_bytes = official_binary[next_offset:min(next_offset+10, end)]
    println("Next bytes in official: $(bytes2hex(next_bytes))")

    # The payload should be here
    payload = hex_to_bytes(json_data["payload"])
    println("Expected payload: $(bytes2hex(payload))")

    # Look for the payload pattern
    payload_pattern = payload
    for i in 1:(length(official_binary) - length(payload_pattern) + 1)
        if official_binary[i:i+length(payload_pattern)-1] == payload_pattern
            println("Found payload at bytes $i:$(i+length(payload_pattern)-1)")
            if i > 1
                length_byte = official_binary[i-1]
                println("Byte before payload: 0x$(string(length_byte, base=16, pad=2))")
            end
            break
        end
    end

    return true
end

# Run test
if abspath(PROGRAM_FILE) == @__FILE__
    test_simple_encoding()
end