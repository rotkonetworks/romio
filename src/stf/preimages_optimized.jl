# Optimized Preimage State Transition Function
# L1 cache-optimized version with minimal allocations

include("../types/basic.jl")
include("../types/accumulate.jl")
include("../test_vectors/loader.jl")
include("../test_vectors/comparison.jl")
include("../crypto/Blake2b.jl")

# Error codes (UInt8 enum - no string allocation)
const ERR_OK = 0x00
const ERR_NOT_SORTED = 0x01
const ERR_DUPLICATE = 0x02
const ERR_SERVICE_NOT_FOUND = 0x03
const ERR_UNNEEDED = 0x04

# Error code to message mapping (only for display)
const ERROR_MESSAGES = Dict(
    ERR_OK => nothing,
    ERR_NOT_SORTED => "preimages_not_sorted_unique",
    ERR_DUPLICATE => "preimages_not_sorted_unique",
    ERR_SERVICE_NOT_FOUND => "service_not_found",
    ERR_UNNEEDED => "preimage_unneeded"
)

# Preimage provision input
struct PreimageInput
    service_id::ServiceId
    blob::Blob
end

# Preimage provision result (optimized)
struct PreimageResult
    ok::Union{Nothing, String}
    error::Union{Nothing, String}
end

# Blake2b-256 hash function (reuse from original)
function blake2b_hash(data::Vector{UInt8})::Vector{UInt8}
    output = zeros(UInt8, 32)
    Blake2b!(output, 32, UInt8[], 0, data, length(data))
    return output
end

# Fast hash comparison (lexicographic byte-by-byte)
@inline function hash_less_than(a::Vector{UInt8}, b::Vector{UInt8})::Bool
    # Lexicographic comparison: compare bytes left-to-right
    # Unroll loop for L1 cache optimization
    @inbounds for i in 1:32
        if a[i] != b[i]
            return a[i] < b[i]
        end
    end
    return false  # Equal
end

@inline function hash_equal(a::Vector{UInt8}, b::Vector{UInt8})::Bool
    # Compare all 32 bytes
    # Use SIMD-friendly comparison (Julia compiler will optimize)
    @inbounds for i in 1:32
        if a[i] != b[i]
            return false
        end
    end
    return true
end

# Optimized preimage processing
function process_preimages_optimized(
    state::State,
    slot::TimeSlot,
    preimages::Vector{PreimageInput}
)::Tuple{State, UInt8}

    n = length(preimages)
    if n == 0
        return (state, ERR_OK)
    end

    # Pre-allocate hash array (avoid reallocation)
    hashes = Vector{Vector{UInt8}}(undef, n)
    sizehint!(hashes, n)

    # Single pass: validate ordering + compute hashes
    last_service_id = ServiceId(0)
    last_hash = nothing

    @inbounds for i in 1:n
        service_id = preimages[i].service_id

        # Validate service ordering (ascending)
        if service_id < last_service_id
            return (state, ERR_NOT_SORTED)
        end

        # Compute hash once
        hash = blake2b_hash(preimages[i].blob)
        hashes[i] = hash

        # Validate hash ordering within same service
        # Duplicates will be adjacent in sorted order
        if service_id == last_service_id && last_hash !== nothing
            # Check if hash <= last_hash (duplicate or wrong order)
            if hash_equal(last_hash, hash) || hash_less_than(hash, last_hash)
                return (state, ERR_DUPLICATE)
            end
            last_hash = hash
        else
            # New service - reset hash tracking
            last_service_id = service_id
            last_hash = hash
        end
    end

    # Batch validation: check all accounts exist
    # Groups memory accesses for better cache locality
    @inbounds for i in 1:n
        if !haskey(state.accounts, preimages[i].service_id)
            return (state, ERR_SERVICE_NOT_FOUND)
        end
    end

    # Validate solicitation (batch by service for cache locality)
    @inbounds for i in 1:n
        service_id = preimages[i].service_id
        account = state.accounts[service_id]
        hash = hashes[i]
        blob_length = UInt64(length(preimages[i].blob))

        request_key = (hash, blob_length)

        # Check if solicited
        if !haskey(account.requests, request_key)
            return (state, ERR_UNNEEDED)
        end

        # Check if already provided
        if haskey(account.preimages, hash)
            return (state, ERR_UNNEEDED)
        end
    end

    # All validations passed - apply state changes
    # Use copy-on-write: only copy modified accounts
    new_accounts = state.accounts  # Shallow reference first
    modified_services = Set{ServiceId}()
    accounts_copied = false

    @inbounds for i in 1:n
        service_id = preimages[i].service_id

        # Copy accounts Dict only once
        if !accounts_copied
            new_accounts = copy(state.accounts)
            accounts_copied = true
        end

        # Copy specific account only if not already copied
        if !(service_id in modified_services)
            # Deep copy this specific account
            old_account = state.accounts[service_id]
            new_accounts[service_id] = ServiceAccount(
                copy(old_account.code_hash),
                old_account.balance,
                old_account.min_acc_gas,
                old_account.min_memo_gas,
                gratis = old_account.gratis,
                created = old_account.created,
                parent = old_account.parent
            )
            # Copy mutable fields
            new_account = new_accounts[service_id]
            new_account.storage = copy(old_account.storage)
            new_account.preimages = copy(old_account.preimages)
            new_account.requests = copy(old_account.requests)
            new_account.octets = old_account.octets
            new_account.items = old_account.items
            new_account.min_balance = old_account.min_balance
            new_account.last_acc = old_account.last_acc

            push!(modified_services, service_id)
        end

        # Apply changes to copied account
        account = new_accounts[service_id]
        hash = hashes[i]
        blob = preimages[i].blob
        blob_length = UInt64(length(blob))

        # Store preimage
        account.preimages[hash] = blob

        # Update request state: [] -> [slot]
        request_key = (hash, blob_length)
        req = account.requests[request_key]
        if isempty(req.state)
            account.requests[request_key] = PreimageRequest([UInt64(slot)])
        end
    end

    # Construct new state (keep slot from pre-state as per test vectors)
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

    return (new_state, ERR_OK)
end

# Wrapper for compatibility with original interface
function process_preimages(
    state::State,
    slot::TimeSlot,
    preimages::Vector{PreimageInput}
)::Tuple{State, PreimageResult}

    (new_state, error_code) = process_preimages_optimized(state, slot, preimages)

    if error_code == ERR_OK
        return (new_state, PreimageResult(nothing, nothing))
    else
        return (state, PreimageResult(nothing, ERROR_MESSAGES[error_code]))
    end
end

# Run preimage test vector (same as original)
function run_preimage_test_vector(filepath::String)
    println("\n=== Running Test Vector: $(basename(filepath)) ===")

    # Load test vector
    tv = load_test_vector(filepath)

    # Parse input
    input_slot = UInt32(tv.input[:slot])
    preimages_input = PreimageInput[]

    if haskey(tv.input, :preimages) && !isempty(tv.input[:preimages])
        for item in tv.input[:preimages]
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
export process_preimages_optimized, hash_less_than, hash_equal
