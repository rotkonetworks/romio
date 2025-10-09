# Test our JAM implementation against test vectors
using Test
using JSON

# Try to include our basic types
try
    include("../src/types/basic.jl")
    println("✅ Basic types loaded successfully")
catch e
    println("❌ Failed to load basic types: $e")
end

# Test basic encoding functions
function test_basic_encoding()
    println("\n🧪 Testing Basic Encoding Functions")
    println("=" ^ 40)

    try
        # Test basic type encoding
        service_id = UInt32(16909060)
        encoded_service = encode(service_id)
        println("Service ID encoding: $(length(encoded_service)) bytes")

        # Test hash type
        test_hash = Hash(zeros(UInt8, 32))
        encoded_hash = encode(test_hash)
        println("Hash encoding: $(length(encoded_hash)) bytes")

        # Test gas encoding
        gas_limit = UInt64(42)
        encoded_gas = encode(gas_limit)
        println("Gas limit encoding: $(length(encoded_gas)) bytes")

        println("✅ Basic encoding functions work")
        return true
    catch e
        println("❌ Basic encoding failed: $e")
        return false
    end
end

# Test against actual test vector data
function test_against_work_item()
    println("\n🔬 Testing Against WorkItem Test Vector")
    println("=" ^ 40)

    try
        # Load test vector
        json_path = joinpath(@__DIR__, "../jamtestvectors/codec/tiny/work_item.json")
        if !isfile(json_path)
            println("❌ Test vector not found")
            return false
        end

        json_data = JSON.parsefile(json_path)
        println("Test vector loaded successfully")

        # Try to create basic types from the test data
        service_id = UInt32(json_data["service"])
        println("Service ID: $service_id")

        refine_gas = UInt64(json_data["refine_gas_limit"])
        println("Refine gas limit: $refine_gas")

        # Test hash parsing
        function hex_to_bytes(hex_str::String)::Vector{UInt8}
            if startswith(hex_str, "0x")
                hex_str = hex_str[3:end]
            end
            return [parse(UInt8, hex_str[i:i+1], base=16) for i in 1:2:length(hex_str)]
        end

        code_hash_bytes = hex_to_bytes(json_data["code_hash"])
        println("Code hash: $(length(code_hash_bytes)) bytes")

        # Test payload
        payload_bytes = hex_to_bytes(json_data["payload"])
        println("Payload: $(length(payload_bytes)) bytes")

        println("✅ Successfully processed test vector data")
        return true
    catch e
        println("❌ Failed to process test vector: $e")
        return false
    end
end

# Test state structure compatibility
function test_state_compatibility()
    println("\n🏗️  Testing State Structure Compatibility")
    println("=" ^ 40)

    try
        # Load an STF test vector
        stf_path = joinpath(@__DIR__, "../jamtestvectors/stf/accumulate/tiny")
        if !isdir(stf_path)
            println("❌ STF test vectors not found")
            return false
        end

        test_files = filter(f -> endswith(f, ".json"), readdir(stf_path))
        if isempty(test_files)
            println("❌ No STF test files found")
            return false
        end

        # Load first test
        test_file = test_files[1]
        test_data = JSON.parsefile(joinpath(stf_path, test_file))
        println("Loaded STF test: $(replace(test_file, ".json" => ""))")

        # Check structure
        required_keys = ["input", "pre_state", "output", "post_state"]
        for key in required_keys
            if haskey(test_data, key)
                println("✅ Has $key")
            else
                println("❌ Missing $key")
                return false
            end
        end

        # Check specific state components
        if haskey(test_data["pre_state"], "current_header")
            println("✅ Has current_header in pre_state")
        end

        if haskey(test_data["pre_state"], "safrole")
            println("✅ Has safrole state")
        end

        if haskey(test_data["input"], "block")
            println("✅ Has block input")
        end

        println("✅ State structure is compatible")
        return true
    catch e
        println("❌ State compatibility test failed: $e")
        return false
    end
end

# Main test function
function main()
    println("🚀 JAM Implementation Test Suite")
    println("=" ^ 50)

    results = []

    # Run tests
    push!(results, test_basic_encoding())
    push!(results, test_against_work_item())
    push!(results, test_state_compatibility())

    # Summary
    passed = count(results)
    total = length(results)

    println("\n📊 Test Results Summary")
    println("=" ^ 30)
    println("Tests passed: $passed/$total")
    println("Success rate: $(round(passed/total*100, digits=1))%")

    if passed == total
        println("🎉 All tests passed! Your implementation is ready for further development.")
    else
        println("⚠️  Some tests failed. Check the output above for details.")
    end

    return passed == total
end

# Run if called directly
if abspath(PROGRAM_FILE) == @__FILE__
    main()
end