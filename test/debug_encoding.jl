# Debug the 5-byte difference in our encoding
using JSON

const TEST_VECTORS_PATH = joinpath(@__DIR__, "../jamtestvectors")

function hex_to_bytes(hex_str::String)::Vector{UInt8}
    if startswith(hex_str, "0x")
        hex_str = hex_str[3:end]
    end
    return [parse(UInt8, hex_str[i:i+1], base=16) for i in 1:2:length(hex_str)]
end

"""
Analyze the structure of the official binary step by step
"""
function analyze_official_binary()
    println("🔍 Analyzing Official Binary Structure")
    println("=" ^ 50)

    # Load data
    json_path = joinpath(TEST_VECTORS_PATH, "codec", "tiny", "work_item.json")
    bin_path = joinpath(TEST_VECTORS_PATH, "codec", "tiny", "work_item.bin")

    json_data = JSON.parsefile(json_path)
    binary = read(bin_path)

    println("Total binary length: $(length(binary)) bytes")
    println("JSON data keys: $(keys(json_data))")

    offset = 1

    # 1. Service ID (4 bytes)
    service_bytes = binary[offset:offset+3]
    service_id = reinterpret(UInt32, service_bytes)[1]
    println("\n1. Service ID (bytes $offset-$(offset+3)):")
    println("   Hex: $(bytes2hex(service_bytes))")
    println("   Value: $service_id (expected: $(json_data["service"]))")
    offset += 4

    # 2. Code hash (32 bytes)
    code_hash_bytes = binary[offset:offset+31]
    println("\n2. Code hash (bytes $offset-$(offset+31)):")
    println("   Hex: $(bytes2hex(code_hash_bytes))")
    println("   Expected: $(json_data["code_hash"][3:end])")  # Remove 0x prefix
    offset += 32

    # 3. Refine gas limit (8 bytes)
    refine_gas_bytes = binary[offset:offset+7]
    refine_gas = reinterpret(UInt64, refine_gas_bytes)[1]
    println("\n3. Refine gas limit (bytes $offset-$(offset+7)):")
    println("   Hex: $(bytes2hex(refine_gas_bytes))")
    println("   Value: $refine_gas (expected: $(json_data["refine_gas_limit"]))")
    offset += 8

    # 4. Accumulate gas limit (8 bytes)
    accumulate_gas_bytes = binary[offset:offset+7]
    accumulate_gas = reinterpret(UInt64, accumulate_gas_bytes)[1]
    println("\n4. Accumulate gas limit (bytes $offset-$(offset+7)):")
    println("   Hex: $(bytes2hex(accumulate_gas_bytes))")
    println("   Value: $accumulate_gas (expected: $(json_data["accumulate_gas_limit"]))")
    offset += 8

    # 5. Export count (1 byte)
    export_count = binary[offset]
    println("\n5. Export count (byte $offset):")
    println("   Hex: $(string(export_count, base=16, pad=2))")
    println("   Value: $export_count (expected: $(json_data["export_count"]))")
    offset += 1

    # 6. Payload length and data
    payload_len_byte = binary[offset]
    println("\n6. Payload length (byte $offset):")
    println("   Hex: $(string(payload_len_byte, base=16, pad=2))")
    println("   Value: $payload_len_byte")
    offset += 1

    payload_bytes = binary[offset:offset+payload_len_byte-1]
    println("   Payload data (bytes $offset-$(offset+payload_len_byte-1)):")
    println("   Hex: $(bytes2hex(payload_bytes))")
    println("   Expected: $(json_data["payload"][3:end])")  # Remove 0x prefix
    offset += payload_len_byte

    # 7. Import segments
    import_count_byte = binary[offset]
    println("\n7. Import segments count (byte $offset):")
    println("   Hex: $(string(import_count_byte, base=16, pad=2))")
    println("   Value: $import_count_byte (expected: $(length(json_data["import_segments"])))")
    offset += 1

    for i in 1:import_count_byte
        println("\n   Import segment $i:")

        # Tree root (32 bytes)
        tree_root_bytes = binary[offset:offset+31]
        println("     Tree root (bytes $offset-$(offset+31)):")
        println("     Hex: $(bytes2hex(tree_root_bytes))")
        expected_tree_root = json_data["import_segments"][i]["tree_root"][3:end]  # Remove 0x
        println("     Expected: $expected_tree_root")
        offset += 32

        # Index (4 bytes)
        index_bytes = binary[offset:offset+3]
        index = reinterpret(UInt32, index_bytes)[1]
        println("     Index (bytes $offset-$(offset+3)):")
        println("     Hex: $(bytes2hex(index_bytes))")
        println("     Value: $index (expected: $(json_data["import_segments"][i]["index"]))")
        offset += 4
    end

    # 8. Extrinsic
    extrinsic_count_byte = binary[offset]
    println("\n8. Extrinsic count (byte $offset):")
    println("   Hex: $(string(extrinsic_count_byte, base=16, pad=2))")
    println("   Value: $extrinsic_count_byte (expected: $(length(json_data["extrinsic"])))")
    offset += 1

    for i in 1:extrinsic_count_byte
        println("\n   Extrinsic $i:")

        # Hash (32 bytes)
        hash_bytes = binary[offset:offset+31]
        println("     Hash (bytes $offset-$(offset+31)):")
        println("     Hex: $(bytes2hex(hash_bytes))")
        expected_hash = json_data["extrinsic"][i]["hash"][3:end]  # Remove 0x
        println("     Expected: $expected_hash")
        offset += 32

        # Length (4 bytes)
        len_bytes = binary[offset:offset+3]
        len = reinterpret(UInt32, len_bytes)[1]
        println("     Length (bytes $offset-$(offset+3)):")
        println("     Hex: $(bytes2hex(len_bytes))")
        println("     Value: $len (expected: $(json_data["extrinsic"][i]["len"]))")
        offset += 4
    end

    println("\nTotal bytes analyzed: $(offset-1)")
    println("Remaining bytes: $(length(binary) - (offset-1))")

    if offset-1 < length(binary)
        remaining_bytes = binary[offset:end]
        println("Remaining bytes hex: $(bytes2hex(remaining_bytes))")
    end

    return offset-1
end

# Run analysis
if abspath(PROGRAM_FILE) == @__FILE__
    analyze_official_binary()
end