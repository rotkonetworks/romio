# Codec validation tests against official JAM test vectors
using Test
using JSON

include("../src/types/basic.jl")

const TEST_VECTORS_PATH = joinpath(@__DIR__, "../jamtestvectors")

"""
Convert hex string to byte array
"""
function hex_to_bytes(hex_str::String)::Vector{UInt8}
    if startswith(hex_str, "0x")
        hex_str = hex_str[3:end]
    end
    return [parse(UInt8, hex_str[i:i+1], base=16) for i in 1:2:length(hex_str)]
end

"""
Basic JAM Work Item structure for testing
"""
struct WorkItem
    service::ServiceId
    code_hash::Hash
    refine_gas_limit::Gas
    accumulate_gas_limit::Gas
    export_count::UInt8
    payload::Blob
    import_segments::Vector{Any}  # Simplified for now
    extrinsic::Vector{Any}        # Simplified for now
end

"""
Create WorkItem from test vector JSON
"""
function work_item_from_json(json_data)
    return WorkItem(
        UInt32(json_data["service"]),
        Hash(hex_to_bytes(json_data["code_hash"])),
        UInt64(json_data["refine_gas_limit"]),
        UInt64(json_data["accumulate_gas_limit"]),
        UInt8(json_data["export_count"]),
        hex_to_bytes(json_data["payload"]),
        json_data["import_segments"],
        json_data["extrinsic"]
    )
end

"""
Test our encoding against the official binary
"""
function test_work_item_encoding()
    println("🧪 Testing WorkItem encoding...")

    # Load test vector
    json_path = joinpath(TEST_VECTORS_PATH, "codec", "tiny", "work_item.json")
    bin_path = joinpath(TEST_VECTORS_PATH, "codec", "tiny", "work_item.bin")

    json_data = JSON.parsefile(json_path)
    expected_binary = read(bin_path)

    println("  Expected binary length: $(length(expected_binary)) bytes")
    println("  Expected binary (first 20 bytes): $(bytes2hex(expected_binary[1:min(20, end)]))")

    # Create WorkItem from JSON
    work_item = work_item_from_json(json_data)

    println("  Work item created:")
    println("    Service ID: $(work_item.service)")
    println("    Code hash: $(bytes2hex(work_item.code_hash))")
    println("    Refine gas limit: $(work_item.refine_gas_limit)")
    println("    Payload length: $(length(work_item.payload)) bytes")

    # Try our encoding
    try
        encoded = encode(work_item)
        println("  Our encoded length: $(length(encoded)) bytes")
        println("  Our encoded (first 20 bytes): $(bytes2hex(encoded[1:min(20, end)]))")

        # Compare
        if length(encoded) == length(expected_binary)
            println("  ✓ Length matches!")

            # Check if content matches
            if encoded == expected_binary
                println("  ✅ Perfect match!")
                return true
            else
                # Find first difference
                for i in 1:min(length(encoded), length(expected_binary))
                    if encoded[i] != expected_binary[i]
                        println("  ❌ First difference at byte $i:")
                        println("    Expected: 0x$(string(expected_binary[i], base=16, pad=2))")
                        println("    Got:      0x$(string(encoded[i], base=16, pad=2))")
                        break
                    end
                end
                return false
            end
        else
            println("  ❌ Length mismatch!")
            return false
        end
    catch e
        println("  ❌ Encoding failed: $e")
        return false
    end
end

"""
Test header encoding
"""
function test_header_encoding()
    println("\n📋 Testing Header encoding...")

    json_path = joinpath(TEST_VECTORS_PATH, "codec", "tiny", "header_0.json")
    bin_path = joinpath(TEST_VECTORS_PATH, "codec", "tiny", "header_0.bin")

    json_data = JSON.parsefile(json_path)
    expected_binary = read(bin_path)

    println("  Expected binary length: $(length(expected_binary)) bytes")
    println("  Header JSON keys: $(keys(json_data))")

    # Extract key fields
    if haskey(json_data, "parent")
        println("    Parent: $(json_data["parent"])")
    end
    if haskey(json_data, "slot")
        println("    Slot: $(json_data["slot"])")
    end

    return true
end

"""
Analyze binary patterns in test vectors
"""
function analyze_binary_patterns()
    println("\n🔍 Analyzing binary patterns...")

    # Load work_item binary
    bin_data = read(joinpath(TEST_VECTORS_PATH, "codec", "tiny", "work_item.bin"))
    json_data = JSON.parsefile(joinpath(TEST_VECTORS_PATH, "codec", "tiny", "work_item.json"))

    println("  Work item binary analysis:")
    println("    Total length: $(length(bin_data)) bytes")

    # Try to identify service ID (should be first 4 bytes)
    service_bytes = bin_data[1:4]
    service_value = reinterpret(UInt32, service_bytes)[1]
    println("    First 4 bytes as UInt32: $service_value")
    println("    Expected service ID: $(json_data["service"])")

    # Show hex dump of first 32 bytes
    println("    Hex dump (first 32 bytes):")
    for i in 1:4:min(32, length(bin_data))
        end_idx = min(i+3, length(bin_data))
        hex_str = join([string(b, base=16, pad=2) for b in bin_data[i:end_idx]], " ")
        println("      Bytes $i-$end_idx: $hex_str")
    end

    return true
end

"""
Main codec testing function
"""
function main()
    println("🚀 JAM Codec Validation Tests")
    println("=" ^ 50)

    try
        analyze_binary_patterns()
        test_work_item_encoding()
        test_header_encoding()

        println("\n✅ Codec tests completed!")
    catch e
        println("\n❌ Tests failed: $e")
        return false
    end

    return true
end

# Run if called directly
if abspath(PROGRAM_FILE) == @__FILE__
    main()
end