# Compare our encoding with the official test vectors byte by byte
using JSON

include("../src/types/basic.jl")

const TEST_VECTORS_PATH = joinpath(@__DIR__, "../jamtestvectors")

function hex_to_bytes(hex_str::String)::Vector{UInt8}
    if startswith(hex_str, "0x")
        hex_str = hex_str[3:end]
    end
    return [parse(UInt8, hex_str[i:i+1], base=16) for i in 1:2:length(hex_str)]
end

"""
Manually encode work item step by step to match JAM spec
"""
function encode_work_item_manually(json_data)
    println("🔧 Manual WorkItem encoding step by step...")

    result = UInt8[]

    # 1. Service ID (4 bytes, little endian)
    service_id = UInt32(json_data["service"])
    println("  Service ID: $service_id = 0x$(string(service_id, base=16, pad=8))")
    append!(result, reinterpret(UInt8, [service_id]))

    # 2. Code hash (32 bytes)
    code_hash = hex_to_bytes(json_data["code_hash"])
    println("  Code hash: $(length(code_hash)) bytes")
    append!(result, code_hash)

    # 3. Refine gas limit (8 bytes, little endian)
    refine_gas = UInt64(json_data["refine_gas_limit"])
    println("  Refine gas limit: $refine_gas")
    append!(result, reinterpret(UInt8, [refine_gas]))

    # 4. Accumulate gas limit (8 bytes, little endian)
    accumulate_gas = UInt64(json_data["accumulate_gas_limit"])
    println("  Accumulate gas limit: $accumulate_gas")
    append!(result, reinterpret(UInt8, [accumulate_gas]))

    # 5. Export count (1 byte)
    export_count = UInt8(json_data["export_count"])
    println("  Export count: $export_count")
    push!(result, export_count)

    # 6. Payload (variable length with prefix)
    payload = hex_to_bytes(json_data["payload"])
    payload_len = length(payload)
    println("  Payload length: $payload_len bytes")

    # JAM uses variable-length encoding for length prefix
    # For small lengths (< 64), it's just one byte
    if payload_len < 64
        push!(result, UInt8(payload_len))
    else
        # More complex encoding for longer payloads
        error("Complex length encoding not implemented yet")
    end
    append!(result, payload)

    # 7. Import segments (variable length array)
    import_segments = json_data["import_segments"]
    import_count = length(import_segments)
    println("  Import segments count: $import_count")

    # Length prefix for array
    if import_count < 64
        push!(result, UInt8(import_count))
    else
        error("Complex length encoding not implemented yet")
    end

    # Each import segment: tree_root (32 bytes) + index (4 bytes)
    for (i, segment) in enumerate(import_segments)
        tree_root = hex_to_bytes(segment["tree_root"])
        index = UInt32(segment["index"])
        println("    Segment $i: tree_root $(length(tree_root)) bytes, index $index")
        append!(result, tree_root)
        append!(result, reinterpret(UInt8, [index]))
    end

    # 8. Extrinsic (variable length array)
    extrinsic = json_data["extrinsic"]
    extrinsic_count = length(extrinsic)
    println("  Extrinsic count: $extrinsic_count")

    # Length prefix for array
    if extrinsic_count < 64
        push!(result, UInt8(extrinsic_count))
    else
        error("Complex length encoding not implemented yet")
    end

    # Each extrinsic: hash (32 bytes) + len (4 bytes)
    for (i, ext) in enumerate(extrinsic)
        hash = hex_to_bytes(ext["hash"])
        len = UInt32(ext["len"])
        println("    Extrinsic $i: hash $(length(hash)) bytes, len $len")
        append!(result, hash)
        append!(result, reinterpret(UInt8, [len]))
    end

    println("  Total encoded length: $(length(result)) bytes")
    return result
end

"""
Compare our encoding with the official binary
"""
function compare_encodings()
    println("🚀 Comparing Encodings")
    println("=" ^ 50)

    # Load test vector
    json_path = joinpath(TEST_VECTORS_PATH, "codec", "tiny", "work_item.json")
    bin_path = joinpath(TEST_VECTORS_PATH, "codec", "tiny", "work_item.bin")

    json_data = JSON.parsefile(json_path)
    official_binary = read(bin_path)

    println("Official binary length: $(length(official_binary)) bytes")

    # Try our manual encoding
    our_binary = encode_work_item_manually(json_data)

    println("\nComparison:")
    println("  Official: $(length(official_binary)) bytes")
    println("  Ours:     $(length(our_binary)) bytes")

    if length(our_binary) == length(official_binary)
        println("  ✓ Lengths match!")

        # Compare byte by byte
        matches = 0
        for i in 1:length(our_binary)
            if our_binary[i] == official_binary[i]
                matches += 1
            else
                println("  ❌ Difference at byte $i:")
                println("    Official: 0x$(string(official_binary[i], base=16, pad=2))")
                println("    Ours:     0x$(string(our_binary[i], base=16, pad=2))")
                if matches > 0
                    println("    (First $matches bytes matched)")
                end
                break
            end
        end

        if matches == length(our_binary)
            println("  🎉 Perfect match!")
            return true
        end
    else
        println("  ❌ Length mismatch!")

        # Show first few bytes comparison
        println("\nFirst 32 bytes comparison:")
        println("Official: $(bytes2hex(official_binary[1:min(32, end)]))")
        println("Ours:     $(bytes2hex(our_binary[1:min(32, end)]))")
    end

    return false
end

# Run comparison
if abspath(PROGRAM_FILE) == @__FILE__
    compare_encodings()
end