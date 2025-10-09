# Final correct JAM encoding implementation
using JSON

const TEST_VECTORS_PATH = joinpath(@__DIR__, "../jamtestvectors")

function hex_to_bytes(hex_str::String)::Vector{UInt8}
    if startswith(hex_str, "0x")
        hex_str = hex_str[3:end]
    end
    return [parse(UInt8, hex_str[i:i+1], base=16) for i in 1:2:length(hex_str)]
end

"""
Correct JAM work item encoding
"""
function encode_work_item_correct(json_data)
    println("🔧 Correct JAM WorkItem encoding...")

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

    # 6. Payload with simple length prefix
    payload = hex_to_bytes(json_data["payload"])
    payload_len = UInt8(length(payload))
    push!(result, payload_len)  # Just the length as a single byte
    append!(result, payload)

    # 7. Import segments array
    import_segments = json_data["import_segments"]
    import_count = UInt8(length(import_segments))
    push!(result, import_count)  # Just the count as a single byte

    # Each import segment: tree_root (32 bytes) + index (4 bytes)
    for segment in import_segments
        tree_root = hex_to_bytes(segment["tree_root"])
        index = UInt32(segment["index"])
        append!(result, tree_root)
        append!(result, reinterpret(UInt8, [index]))
    end

    # 8. Extrinsic array
    extrinsic = json_data["extrinsic"]
    extrinsic_count = UInt8(length(extrinsic))
    push!(result, extrinsic_count)  # Just the count as a single byte

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
Test the final correct encoding
"""
function test_correct_encoding()
    println("🚀 Testing Final Correct JAM Encoding")
    println("=" ^ 50)

    # Load test vector
    json_path = joinpath(TEST_VECTORS_PATH, "codec", "tiny", "work_item.json")
    bin_path = joinpath(TEST_VECTORS_PATH, "codec", "tiny", "work_item.bin")

    json_data = JSON.parsefile(json_path)
    official_binary = read(bin_path)

    println("Official binary: $(length(official_binary)) bytes")

    # Try our correct encoding
    our_binary = encode_work_item_correct(json_data)

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

                # Show more context
                start_idx = max(1, i-5)
                end_idx = min(length(our_binary), i+5)
                println("    Context (bytes $start_idx-$end_idx):")
                println("    Official: $(bytes2hex(official_binary[start_idx:end_idx]))")
                println("    Ours:     $(bytes2hex(our_binary[start_idx:end_idx]))")
                return false
            end
        end

        println("  🎉 Perfect match! JAM encoding is now correct!")
        return true
    else
        println("  ❌ Length mismatch!")

        # Show hex comparison for debugging
        min_len = min(length(our_binary), length(official_binary))
        println("\nFirst $min_len bytes comparison:")
        println("Official: $(bytes2hex(official_binary[1:min_len]))")
        println("Ours:     $(bytes2hex(our_binary[1:min_len]))")

        return false
    end
end

"""
Update the basic encoding function in our types
"""
function create_updated_codec()
    println("\n📝 Creating updated codec implementation...")

    codec_content = """
# Updated JAM codec implementation based on test vector validation
using StaticArrays

# Basic JAM encoding function
function jam_encode(data)::Vector{UInt8}
    if isa(data, UInt32)
        return reinterpret(UInt8, [data])
    elseif isa(data, UInt64)
        return reinterpret(UInt8, [data])
    elseif isa(data, UInt8)
        return [data]
    elseif isa(data, Vector{UInt8})
        return data
    elseif isa(data, SVector{N, UInt8}) where N
        return Vector{UInt8}(data)
    else
        error("Unsupported type for JAM encoding: \$(typeof(data))")
    end
end

# Encode array with length prefix
function jam_encode_array(arr::Vector{T}) where T
    result = UInt8[]
    push!(result, UInt8(length(arr)))  # Length prefix
    for item in arr
        append!(result, jam_encode(item))
    end
    return result
end

# Encode variable-length data with length prefix
function jam_encode_blob(data::Vector{UInt8})::Vector{UInt8}
    result = UInt8[]
    push!(result, UInt8(length(data)))  # Length prefix
    append!(result, data)
    return result
end
"""

    write("src/codec_updated.jl", codec_content)
    println("  ✓ Updated codec saved to src/codec_updated.jl")
end

# Run test
if abspath(PROGRAM_FILE) == @__FILE__
    success = test_correct_encoding()
    if success
        create_updated_codec()
    end
end