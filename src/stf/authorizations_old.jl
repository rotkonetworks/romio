# Authorizations State Transition Function
# Per graypaper section on authorization (authorization.tex)

include("../types/basic.jl")
using JSON3

# Process authorizations STF
# Per graypaper equation on line 26-28 of authorization.tex
function process_authorizations(
    auth_pools::Vector{Vector{String}},
    auth_queues::Vector{Vector{String}},
    slot::TimeSlot,
    guarantees
)
    # Per graypaper: pool'[core] = overleftarrow{F(core) ++ queue'[slot]}^{pool_size}
    # where F(core) removes authorizer used in guarantee for this core

    new_pools = Vector{Vector{String}}()
    C_AUTH_POOL_SIZE = 8

    for core_idx in 1:length(auth_pools)
        pool = copy(auth_pools[core_idx])
        queue = auth_queues[core_idx]

        # F(core): Remove authorizer used in guarantee for this core
        # Per graypaper eq 27: pool \ {(g_workreport)_authorizer} if exists g where g_core = core
        for g in guarantees
            if g[:core] == core_idx - 1  # Test vectors use 0-indexed cores
                auth_hash = String(g[:auth_hash])
                # Remove the used authorizer from pool
                pool = filter(a -> a != auth_hash, pool)
                break  # Only one guarantee per core per block
            end
        end

        # Get authorizer from queue at cyclic index based on slot
        queue_idx = (slot % length(queue)) + 1  # Julia 1-indexed
        new_auth = queue[queue_idx]

        # Append new authorizer
        pool_with_new = vcat(pool, [new_auth])

        # overleftarrow: keep last C_AUTH_POOL_SIZE elements
        if length(pool_with_new) > C_AUTH_POOL_SIZE
            new_pool = pool_with_new[end-C_AUTH_POOL_SIZE+1:end]
        else
            new_pool = pool_with_new
        end

        push!(new_pools, new_pool)
    end

    return new_pools
end

# Run authorizations test vector
function run_authorizations_test_vector(filepath::String)
    println("\n=== Running Authorizations Test Vector: $(basename(filepath)) ===")

    # Load test vector
    json_str = read(filepath, String)
    tv = JSON3.read(json_str)

    # Parse pre-state
    pre_pools = [collect(pool) for pool in tv[:pre_state][:auth_pools]]
    pre_queues = [collect(queue) for queue in tv[:pre_state][:auth_queues]]

    # Parse input
    input_slot = UInt32(tv[:input][:slot])
    guarantees = tv[:input][:auths]  # Authorization extrinsic (empty in basic tests)

    println("Input:")
    println("  Slot: $input_slot")
    println("  Guarantees: $(length(guarantees))")
    println("  Pools: $(length(pre_pools))")
    println("  Queues: $(length(pre_queues))")

    # Run state transition
    result_pools = process_authorizations(pre_pools, pre_queues, input_slot, guarantees)

    # Parse expected post-state
    post_pools = [collect(pool) for pool in tv[:post_state][:auth_pools]]

    # Compare
    println("\n=== State Comparison ===")
    all_match = true

    for core_idx in 1:length(post_pools)
        expected = post_pools[core_idx]
        actual = result_pools[core_idx]

        if expected != actual
            println("❌ Core $core_idx pool mismatch:")
            println("  Expected: $(expected[1:min(2, length(expected))])...")
            println("  Got: $(actual[1:min(2, length(actual))])...")
            all_match = false
        end
    end

    if all_match
        println("✅ All auth pools match!")
    end

    # Final verdict
    println("\n=== Test Vector Result ===")
    if all_match
        println("✅ PASS")
        return true
    else
        println("❌ FAIL")
        return false
    end
end

export process_authorizations, run_authorizations_test_vector
