# Debug MMR super peak calculation

include("../src/utils/mmr.jl")
include("../src/test_vectors/loader.jl")

# Test data from progress_blocks_history-4
peak0_hex = "a983417440b618f29ed0b7fa65212fce2d363cb2b2c18871a05c4f67217290b0"
peak3_hex = "658b919f734bd39262c10589aa1afc657471d902a6a361c044f78de17d660bc6"
expected_beefy_hex = "ebdb6db060afceaa2a99a499a84476847444ffc3787f6a4786e713f5362dbf4d"

peak0 = parse_hex(peak0_hex)
peak3 = parse_hex(peak3_hex)
expected_beefy = parse_hex(expected_beefy_hex)

# Test with old format (Union{Nothing, Vector{UInt8}})
peaks_old = Union{Nothing, Vector{UInt8}}[peak0, nothing, nothing, peak3]

println("Testing MMR super peak with 2 peaks:")
println("Peak 0: $peak0_hex")
println("Peak 3: $peak3_hex")
println("Expected: $expected_beefy_hex")

result = mmr_super_peak(peaks_old)
result_hex = bytes2hex(result)

println("Got:      $result_hex")

if result == expected_beefy
    println("\n✅ Super peak calculation correct!")
else
    println("\n❌ Super peak calculation wrong!")
    println("\nLet me try computing step by step:")

    # Manual calculation
    prefix = UInt8[0x24, 0x70, 0x65, 0x61, 0x6b]  # "$peak"

    # Should be: keccak256(prefix || peak0 || peak3)
    input = vcat(prefix, peak0, peak3)
    println("Input to keccak (length=$(length(input))):")
    println("  Prefix: $(bytes2hex(prefix))")
    println("  Peak 0: $(bytes2hex(peak0))")
    println("  Peak 3: $(bytes2hex(peak3))")

    manual_result = keccak_256(input)
    manual_hex = bytes2hex(manual_result)
    println("Manual result: $manual_hex")

    if manual_result == expected_beefy
        println("✅ Manual calculation matches expected!")
        println("❌ Bug is in mmr_super_peak implementation")
    else
        println("❌ Manual calculation also doesn't match")
        println("Possible issues:")
        println("  1. Test vector might be wrong")
        println("  2. Different interpretation of spec")
        println("  3. Peak ordering issue")

        # Try reversed order
        input_reversed = vcat(prefix, peak3, peak0)
        reversed_result = keccak_256(input_reversed)
        reversed_hex = bytes2hex(reversed_result)
        println("\nTrying reversed order (peak3 || peak0): $reversed_hex")
        if reversed_result == expected_beefy
            println("✅ Reversed order matches! Order issue found.")
        end
    end
end
