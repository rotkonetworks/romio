# Test vector loader validation

include("../../src/test_vectors/loader.jl")

println("=== Test Vector Loader Validation ===\n")

# Test 1: Parse hex strings
println("Test 1: Hex string parsing")
test_hex = "0x1234567890abcdef"
bytes = parse_hex(test_hex)
println("  Input: $test_hex")
println("  Output: $(length(bytes)) bytes")
println("  First byte: 0x$(string(bytes[1], base=16, pad=2))")
@assert bytes == [0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef]
println("  ✓ Hex parsing correct\n")

# Test 2: Load simple preimage test vector
println("Test 2: Load preimage_needed-1.json")
vector_path = "jam-test-vectors/stf/preimages/tiny/preimage_needed-1.json"
if isfile(vector_path)
    tv = load_test_vector(vector_path)

    println("  Pre-state:")
    println("    Accounts: $(length(tv.pre_state.accounts))")

    if length(tv.pre_state.accounts) > 0
        first_id = first(keys(tv.pre_state.accounts))
        first_acc = tv.pre_state.accounts[first_id]
        println("    First account ID: $first_id")
        println("    Preimages: $(length(first_acc.preimages))")
        println("    Requests: $(length(first_acc.requests))")

        # Check preimage data
        for (hash, blob) in first_acc.preimages
            println("      Preimage hash: 0x$(bytes2hex(hash[1:8]))... ($(length(blob)) bytes)")
        end

        # Check request metadata
        for ((hash, len), req) in first_acc.requests
            println("      Request (len=$len): state=$(req.state)")
        end
    end

    println("  Post-state:")
    println("    Accounts: $(length(tv.post_state.accounts))")

    println("  Output: $(tv.output)")

    println("  ✓ Test vector loaded successfully\n")
else
    println("  ⚠ Test vector file not found: $vector_path\n")
end

# Test 3: Verify account structure
println("Test 3: ServiceAccount structure validation")
if isfile(vector_path)
    tv = load_test_vector(vector_path)
    if length(tv.pre_state.accounts) > 0
        first_id = first(keys(tv.pre_state.accounts))
        acc = tv.pre_state.accounts[first_id]

        println("  ServiceAccount fields:")
        println("    code_hash: $(length(acc.code_hash)) bytes")
        println("    storage: $(length(acc.storage)) items")
        println("    preimages: $(length(acc.preimages)) items")
        println("    requests: $(length(acc.requests)) items")
        println("    balance: $(acc.balance)")
        println("    min_balance: $(acc.min_balance)")
        println("    min_acc_gas: $(acc.min_acc_gas)")
        println("    min_memo_gas: $(acc.min_memo_gas)")
        println("    octets: $(acc.octets)")
        println("    items: $(acc.items)")
        println("    gratis: $(acc.gratis)")
        println("    created: $(acc.created)")
        println("    last_acc: $(acc.last_acc)")
        println("    parent: $(acc.parent)")
        println("  ✓ All 14 ServiceAccount fields present\n")
    end
end

println("=== Test Vector Loader Validation Complete ===")
