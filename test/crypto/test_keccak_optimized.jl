# Test optimized Keccak-256 implementation

include("../../src/crypto/keccak256_optimized.jl")

function test_keccak_basic()
    println("Testing optimized Keccak-256...")

    # Test vector 1: empty string
    empty_data = UInt8[]
    expected_empty = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"

    result = keccak_256(empty_data)
    result_hex = bytes2hex(result)

    if result_hex == expected_empty
        println("✅ Empty string test passed")
    else
        println("❌ Empty string test failed")
        println("  Expected: $expected_empty")
        println("  Got: $result_hex")
        return false
    end

    # Test vector 2: "abc"
    abc_data = Vector{UInt8}("abc")
    expected_abc = "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"

    result = keccak_256(abc_data)
    result_hex = bytes2hex(result)

    if result_hex == expected_abc
        println("✅ 'abc' test passed")
    else
        println("❌ 'abc' test failed")
        println("  Expected: $expected_abc")
        println("  Got: $result_hex")
        return false
    end

    # Test vector 3: longer message
    long_data = Vector{UInt8}("The quick brown fox jumps over the lazy dog")
    expected_long = "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15"

    result = keccak_256(long_data)
    result_hex = bytes2hex(result)

    if result_hex == expected_long
        println("✅ Long message test passed")
    else
        println("❌ Long message test failed")
        println("  Expected: $expected_long")
        println("  Got: $result_hex")
        return false
    end

    # Test in-place version
    output_buf = Vector{UInt8}(undef, 32)
    keccak_256!(output_buf, abc_data)
    result_hex = bytes2hex(output_buf)

    if result_hex == expected_abc
        println("✅ In-place version test passed")
    else
        println("❌ In-place version test failed")
        return false
    end

    # Test fast version (thread-local buffer)
    result_hash = keccak_256_fast(abc_data)
    result_hex = bytes2hex(Vector{UInt8}(result_hash))

    if result_hex == expected_abc
        println("✅ Fast version (thread-local) test passed")
    else
        println("❌ Fast version test failed")
        return false
    end

    println("\n✅ All Keccak-256 tests passed!")
    return true
end

# Run test
if abspath(PROGRAM_FILE) == @__FILE__
    success = test_keccak_basic()
    exit(success ? 0 : 1)
end
