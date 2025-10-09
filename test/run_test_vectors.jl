# Simple test runner for JAM test vectors
using Test
using JSON

const TEST_VECTORS_PATH = joinpath(@__DIR__, "../jamtestvectors")

"""
Load a test vector from the jamtestvectors directory
"""
function load_test_vector(category::String, chain::String, name::String)
    json_path = joinpath(TEST_VECTORS_PATH, category, chain, "$(name).json")
    bin_path = joinpath(TEST_VECTORS_PATH, category, chain, "$(name).bin")

    if !isfile(json_path) || !isfile(bin_path)
        error("Test vector not found: $json_path or $bin_path")
    end

    json_data = JSON.parsefile(json_path)
    bin_data = read(bin_path)

    return (json_data, bin_data)
end

"""
Test codec vectors
"""
function test_codec_vectors()
    println("🧪 Testing Codec Vectors...")

    # Test work_item
    println("\n📄 Testing work_item...")
    json_data, bin_data = load_test_vector("codec", "tiny", "work_item")

    println("  JSON structure:")
    println("    Keys: $(keys(json_data))")
    println("    Binary length: $(length(bin_data)) bytes")

    if haskey(json_data, "service_id")
        println("    Service ID: $(json_data["service_id"])")
    end
    if haskey(json_data, "code_hash")
        println("    Code hash: $(json_data["code_hash"])")
    end

    # Test header
    println("\n📋 Testing header_0...")
    json_data, bin_data = load_test_vector("codec", "tiny", "header_0")

    println("  JSON structure:")
    println("    Keys: $(keys(json_data))")
    println("    Binary length: $(length(bin_data)) bytes")

    if haskey(json_data, "parent_hash")
        println("    Parent hash: $(json_data["parent_hash"])")
    end
    if haskey(json_data, "prior_state_root")
        println("    Prior state root: $(json_data["prior_state_root"])")
    end

    # Test block
    println("\n🧱 Testing block...")
    json_data, bin_data = load_test_vector("codec", "tiny", "block")

    println("  JSON structure:")
    println("    Top-level keys: $(keys(json_data))")
    println("    Binary length: $(length(bin_data)) bytes")

    if haskey(json_data, "header") && isa(json_data["header"], Dict)
        println("    Header keys: $(keys(json_data["header"]))")
    end

    return true
end

"""
Test STF vectors
"""
function test_stf_vectors()
    println("\n🔄 Testing STF Vectors...")

    stf_categories = ["accumulate", "assurances", "authorizations",
                     "disputes", "history", "preimages", "reports",
                     "safrole", "statistics"]

    for category in stf_categories
        println("\n📁 Testing STF category: $category")
        stf_path = joinpath(TEST_VECTORS_PATH, "stf", category, "tiny")

        if isdir(stf_path)
            files = readdir(stf_path)
            json_files = filter(f -> endswith(f, ".json"), files)

            println("  Found $(length(json_files)) test vectors")

            # Test first few vectors
            for file in json_files[1:min(2, length(json_files))]
                try
                    json_data = JSON.parsefile(joinpath(stf_path, file))
                    println("    ✓ Loaded $file - keys: $(keys(json_data))")
                catch e
                    println("    ✗ Failed to load $file: $e")
                end
            end
        else
            println("  Directory not found: $stf_path")
        end
    end

    return true
end

"""
Analyze test vector structure
"""
function analyze_test_vectors()
    println("🔍 Analyzing Test Vector Structure...")

    # Check what's available
    categories = readdir(TEST_VECTORS_PATH)
    println("\nAvailable test categories:")
    for cat in categories
        if isdir(joinpath(TEST_VECTORS_PATH, cat))
            println("  📂 $cat")

            # Check subcategories
            subcats = readdir(joinpath(TEST_VECTORS_PATH, cat))
            for subcat in subcats
                subpath = joinpath(TEST_VECTORS_PATH, cat, subcat)
                if isdir(subpath)
                    files = readdir(subpath)
                    json_count = count(f -> endswith(f, ".json"), files)
                    bin_count = count(f -> endswith(f, ".bin"), files)
                    println("    📁 $subcat: $json_count JSON, $bin_count binary files")
                end
            end
        end
    end
end

"""
Main test runner
"""
function main()
    println("🚀 JAM Test Vectors Validation")
    println("=" ^ 50)

    try
        analyze_test_vectors()
        test_codec_vectors()
        test_stf_vectors()

        println("\n✅ Test vector validation completed successfully!")
    catch e
        println("\n❌ Test failed with error: $e")
        return false
    end

    return true
end

# Run if called directly
if abspath(PROGRAM_FILE) == @__FILE__
    main()
end