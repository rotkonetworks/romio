# Fixed JAM encoding following the actual binary format
using JSON

const TEST_VECTORS_PATH = joinpath(@__DIR__, "../jamtestvectors")

function hex_to_bytes(hex_str::String)::Vector{UInt8}
    if startswith(hex_str, "0x")
        hex_str = hex_str[3:end]
    end
    return [parse(UInt8, hex_str[i:i+1], base=16) for i in 1:2:length(hex_str)]
end

"""
JAM variable-length encoding for sequence lengths
Based on the actual binary format observed
"""
function encode_length(len::Integer)::Vector{UInt8}
    if len == 0
        return [0x00]
    elseif len < 64
        # For small lengths, use 0x00 followed by the actual length
        return [0x00, UInt8(len)]
    else
        error("Complex length encoding not implemented yet for length $len")
    end
end

"""
Encode work item following the exact binary format
"""
function encode_work_item_fixed(json_data)
    println("🔧 Fixed WorkItem encoding...")

    result = UInt8[]

    # 1. Service ID (4 bytes, little endian)
    service_id = UInt32(json_data["service"])
    append!(result, reinterpret(UInt8, [service_id]))

    # 2. Code hash (32 bytes)
    code_hash = hex_to_bytes(json_data["code_hash"])
    append!(result, code_hash)

    # 3. Refine gas limit (8 bytes, little endian)
    refine_gas = UInt64(json_data["refine_gas_limit"])
    append!(result, reinterpret(UInt8, [refine_gas]))

    # 4. Accumulate gas limit (8 bytes, little endian)
    accumulate_gas = UInt64(json_data["accumulate_gas_limit"])
    append!(result, reinterpret(UInt8, [accumulate_gas]))

    # 5. Export count (1 byte)
    export_count = UInt8(json_data["export_count"])
    push!(result, export_count)

    # 6. Payload with JAM length encoding
    payload = hex_to_bytes(json_data["payload"])
    payload_len = length(payload)
    println("  Payload: $payload_len bytes")

    # Use the observed encoding: 0x00 followed by length for non-zero lengths
    if payload_len == 0
        push!(result, 0x00)
    else
        append!(result, encode_length(payload_len))
        append!(result, payload)
    end

    # 7. Import segments
    import_segments = json_data["import_segments"]
    import_count = length(import_segments)
    println("  Import segments: $import_count")

    # Length encoding for array
    append!(result, encode_length(import_count))

    # Each import segment: tree_root (32 bytes) + index (4 bytes)
    for segment in import_segments
        tree_root = hex_to_bytes(segment["tree_root"])
        index = UInt32(segment["index"])
        append!(result, tree_root)
        append!(result, reinterpret(UInt8, [index]))
    end

    # 8. Extrinsic
    extrinsic = json_data["extrinsic"]
    extrinsic_count = length(extrinsic)
    println("  Extrinsic: $extrinsic_count")

    # Length encoding for array
    append!(result, encode_length(extrinsic_count))

    # Each extrinsic: hash (32 bytes) + len (4 bytes)
    for ext in extrinsic
        hash = hex_to_bytes(ext["hash"])
        len = UInt32(ext["len"])
        append!(result, hash)
        append!(result, reinterpret(UInt8, [len]))
    end

    println("  Total encoded length: $(length(result)) bytes")
    return result
end

"""
Test the fixed encoding
"""
function test_fixed_encoding()
    println("🚀 Testing Fixed JAM Encoding")
    println("=" ^ 50)

    # Load test vector
    json_path = joinpath(TEST_VECTORS_PATH, "codec", "tiny", "work_item.json")
    bin_path = joinpath(TEST_VECTORS_PATH, "codec", "tiny", "work_item.bin")

    json_data = JSON.parsefile(json_path)
    official_binary = read(bin_path)

    println("Official binary: $(length(official_binary)) bytes")

    # Try our fixed encoding
    our_binary = encode_work_item_fixed(json_data)

    println("\nComparison:")
    println("  Official: $(length(official_binary)) bytes")
    println("  Ours:     $(length(our_binary)) bytes")

    if length(our_binary) == length(official_binary)
        println("  ✓ Lengths match!")

        # Compare byte by byte
        for i in 1:length(our_binary)
            if our_binary[i] != official_binary[i]
                println("  ❌ First difference at byte $i:")
                println("    Official: 0x$(string(official_binary[i], base=16, pad=2))")
                println("    Ours:     0x$(string(our_binary[i], base=16, pad=2))")

                # Show context around the difference
                start_idx = max(1, i-5)
                end_idx = min(length(our_binary), i+5)
                println("    Context (bytes $start_idx-$end_idx):")
                println("    Official: $(bytes2hex(official_binary[start_idx:end_idx]))")
                println("    Ours:     $(bytes2hex(our_binary[start_idx:end_idx]))")
                return false
            end
        end

        println("  🎉 Perfect match! Encoding is correct!")
        return true
    else
        println("  ❌ Length mismatch!")
        return false
    end
end

# Run test
if abspath(PROGRAM_FILE) == @__FILE__
    test_fixed_encoding()
end