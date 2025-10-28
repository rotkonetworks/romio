# State Comparison Framework
# Compares expected and actual states for test vector validation

include("loader.jl")

# Compare two byte arrays
function compare_blobs(expected::Vector{UInt8}, actual::Vector{UInt8}, name::String)::Bool
    if expected != actual
        println("  ❌ $name mismatch:")
        println("     Expected: 0x$(bytes2hex(expected[1:min(16,length(expected))]))...")
        println("     Got:      0x$(bytes2hex(actual[1:min(16,length(actual))]))...")
        return false
    end
    return true
end

# Compare two PreimageRequests
function compare_preimage_requests(expected::PreimageRequest, actual::PreimageRequest, key::Tuple)::Bool
    if expected.state != actual.state
        println("  ❌ PreimageRequest state mismatch for key $(bytes2hex(key[1][1:8]))..., len=$(key[2]):")
        println("     Expected: $(expected.state)")
        println("     Got:      $(actual.state)")
        return false
    end
    return true
end

# Compare two ServiceAccounts
function compare_service_accounts(
    expected::ServiceAccount,
    actual::ServiceAccount,
    service_id::ServiceId
)::Bool
    all_match = true

    # Compare code hash
    if !compare_blobs(expected.code_hash, actual.code_hash, "code_hash for service $service_id")
        all_match = false
    end

    # Compare storage
    if expected.storage != actual.storage
        println("  ❌ Storage mismatch for service $service_id:")
        println("     Expected $(length(expected.storage)) items, got $(length(actual.storage)) items")
        all_match = false
    end

    # Compare preimages
    if expected.preimages != actual.preimages
        println("  ❌ Preimages mismatch for service $service_id:")
        println("     Expected $(length(expected.preimages)) items, got $(length(actual.preimages)) items")
        all_match = false
    end

    # Compare preimage requests
    if Base.length(expected.requests) != Base.length(actual.requests)
        println("  ❌ Preimage requests count mismatch for service $service_id:")
        println("     Expected $(Base.length(expected.requests)) requests, got $(Base.length(actual.requests)) requests")
        all_match = false
    else
        for (key, expected_req) in expected.requests
            if haskey(actual.requests, key)
                if !compare_preimage_requests(expected_req, actual.requests[key], key)
                    all_match = false
                end
            else
                println("  ❌ Missing preimage request for key $(bytes2hex(key[1][1:8]))..., len=$(key[2])")
                all_match = false
            end
        end
    end

    # Compare scalar fields
    fields_to_compare = [
        (:balance, "balance"),
        (:min_balance, "min_balance"),
        (:min_acc_gas, "min_acc_gas"),
        (:min_memo_gas, "min_memo_gas"),
        (:octets, "octets"),
        (:items, "items"),
        (:gratis, "gratis"),
        (:created, "created"),
        (:last_acc, "last_acc"),
        (:parent, "parent")
    ]

    for (field, name) in fields_to_compare
        expected_val = getfield(expected, field)
        actual_val = getfield(actual, field)
        if expected_val != actual_val
            println("  ❌ $name mismatch for service $service_id:")
            println("     Expected: $expected_val")
            println("     Got:      $actual_val")
            all_match = false
        end
    end

    return all_match
end

# Compare two States
function compare_states(expected::State, actual::State)::Bool
    println("\n=== State Comparison ===")
    all_match = true

    # Compare slot
    if expected.slot != actual.slot
        println("  ❌ Slot mismatch:")
        println("     Expected: $(expected.slot)")
        println("     Got:      $(actual.slot)")
        all_match = false
    else
        println("  ✓ Slot matches: $(expected.slot)")
    end

    # Compare entropy
    if !compare_blobs(expected.entropy, actual.entropy, "entropy")
        all_match = false
    else
        println("  ✓ Entropy matches")
    end

    # Compare accounts
    if Base.length(expected.accounts) != Base.length(actual.accounts)
        println("  ❌ Account count mismatch:")
        println("     Expected: $(Base.length(expected.accounts)) accounts")
        println("     Got:      $(Base.length(actual.accounts)) accounts")
        all_match = false
    else
        println("  ✓ Account count matches: $(Base.length(expected.accounts))")

        # Compare each account
        for (service_id, expected_account) in expected.accounts
            if haskey(actual.accounts, service_id)
                if !compare_service_accounts(expected_account, actual.accounts[service_id], service_id)
                    all_match = false
                end
            else
                println("  ❌ Missing account for service $service_id")
                all_match = false
            end
        end
    end

    # TODO: Compare privileges, accumulated, ready_queue, statistics, etc.

    if all_match
        println("\n✅ States match perfectly!")
    else
        println("\n❌ States have differences")
    end

    return all_match
end

# Export functions
export compare_blobs, compare_preimage_requests, compare_service_accounts, compare_states
