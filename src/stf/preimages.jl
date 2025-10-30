# Preimage State Transition Function
# Handles preimage provision according to graypaper

include("../types/basic.jl")
include("../types/accumulate.jl")
include("../test_vectors/loader.jl")
include("../test_vectors/comparison.jl")

# Use our Blake2b implementation
include("../crypto/Blake2b.jl")

# Blake2b-256 hash function
function blake2b_hash(data::Vector{UInt8})::Vector{UInt8}
    output = zeros(UInt8, 32)
    Blake2b!(output, 32, UInt8[], 0, data, length(data))
    return output
end

# Preimage provision input
struct PreimageInput
    service_id::ServiceId
    blob::Blob
end

# Preimage provision result
struct PreimageResult
    ok::Union{Nothing, String}
    error::Union{Nothing, String}
end

# Process preimage provision
function process_preimages(
    state::State,
    slot::TimeSlot,
    preimages::Vector{PreimageInput}
)::Tuple{State, PreimageResult}

    # No preimages to process
    if isempty(preimages)
        return (state, PreimageResult(nothing, nothing))
    end

    # Pre-validate ALL preimages before making any state changes
    # This ensures atomicity - either all succeed or none apply

    # 1. Validate service ordering (ascending service IDs)
    for i in 2:length(preimages)
        if preimages[i].service_id < preimages[i-1].service_id
            return (state, PreimageResult(nothing, "preimages_not_sorted_unique"))
        end
    end

    # 2. Pre-compute all hashes and validate within-service ordering
    preimage_data = []
    last_service_id = ServiceId(0)
    last_hash = nothing

    for preimage in preimages
        hash = blake2b_hash(preimage.blob)
        blob_length = UInt64(length(preimage.blob))

        # Check hash ordering within same service
        if preimage.service_id == last_service_id && last_hash !== nothing
            if hash <= last_hash
                return (state, PreimageResult(nothing, "preimages_not_sorted_unique"))
            end
        end

        last_service_id = preimage.service_id
        last_hash = hash

        push!(preimage_data, (preimage.service_id, hash, blob_length, preimage.blob))
    end

    # 3. Validate no duplicates
    seen = Set{Tuple{ServiceId, Blob}}()
    for (service_id, hash, _, _) in preimage_data
        key = (service_id, hash)
        if key in seen
            return (state, PreimageResult(nothing, "preimages_not_sorted_unique"))
        end
        push!(seen, key)
    end

    # 4. Validate all preimages are solicited and not already provided
    for (service_id, hash, blob_length, _) in preimage_data
        if !haskey(state.accounts, service_id)
            return (state, PreimageResult(nothing, "service_not_found"))
        end

        account = state.accounts[service_id]
        request_key = (hash, blob_length)

        if !haskey(account.requests, request_key)
            return (state, PreimageResult(nothing, "preimage_unneeded"))
        end

        if haskey(account.preimages, hash)
            return (state, PreimageResult(nothing, "preimage_unneeded"))
        end
    end

    # All validations passed - now apply state changes atomically
    provided_count = 0
    provided_size = 0
    new_accounts = copy(state.accounts)

    for (service_id, hash, blob_length, blob) in preimage_data
        account = new_accounts[service_id]

        # Store preimage
        account.preimages[hash] = blob

        # Update statistics
        provided_count += 1
        provided_size += blob_length

        # Update request state: [] -> [slot]
        request_key = (hash, blob_length)
        if haskey(account.requests, request_key)
            req = account.requests[request_key]
            if isempty(req.state)
                account.requests[request_key] = PreimageRequest([UInt64(slot)])
            end
        end
    end

    # Update state
    # Post-state slot is null in test vectors, meaning keep the pre-state slot
    new_state = State(
        state.slot,
        state.entropy,
        new_accounts,
        state.privileges,
        state.accumulated,
        state.ready_queue,
        state.statistics,
        state.validators,
        state.epoch,
        state.validators_next_epoch
    )

    return (new_state, PreimageResult(nothing, nothing))
end

# Run preimage test vector
function run_preimage_test_vector(filepath::String)
    println("\n=== Running Test Vector: $(basename(filepath)) ===")

    # Load test vector
    tv = load_test_vector(filepath)

    # Parse input
    input_slot = UInt32(tv.input[:slot])
    preimages_input = PreimageInput[]

    if haskey(tv.input, :preimages) && !isempty(tv.input[:preimages])
        for item in tv.input[:preimages]
            # Handle different key names: service_id, service, or requester
            service_id_key = if haskey(item, :service_id)
                :service_id
            elseif haskey(item, :service)
                :service
            else
                :requester
            end
            push!(preimages_input, PreimageInput(
                ServiceId(item[service_id_key]),
                parse_hex(item[:blob])
            ))
        end
    end

    println("Input:")
    println("  Slot: $input_slot")
    println("  Preimages: $(length(preimages_input))")

    # Run state transition
    (result_state, result) = process_preimages(tv.pre_state, input_slot, preimages_input)

    # Check result
    expected_ok = haskey(tv.output, :ok) && tv.output[:ok] === nothing
    actual_ok = result.ok === nothing && result.error === nothing

    println("\nResult:")
    if actual_ok
        println("  ✓ Success")
    else
        println("  ❌ Error: $(result.error)")
    end

    # Compare states
    states_match = compare_states(result_state, tv.post_state)

    # Final verdict
    println("\n=== Test Vector Result ===")
    if states_match && (expected_ok == actual_ok)
        println("✅ PASS - Test vector validated successfully!")
        return true
    else
        println("❌ FAIL - Test vector validation failed")
        return false
    end
end

# Export functions
export PreimageInput, PreimageResult, process_preimages, run_preimage_test_vector
