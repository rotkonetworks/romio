# Authorizations State Transition Function - Optimized
# Per graypaper section on authorization (authorization.tex)

include("../types/basic.jl")
using JSON3

# Process authorizations STF (optimized version)
# Per graypaper equation on line 26-28 of authorization.tex
function process_authorizations(
    auth_pools::Vector{Vector{Hash}},
    auth_queues::Vector{Vector{Hash}},
    slot::TimeSlot,
    guarantees
)::Vector{Vector{Hash}}
    # Per graypaper: pool'[core] = overleftarrow{F(core) ++ queue'[slot]}^{pool_size}
    # where F(core) removes authorizer used in guarantee for this core

    C_AUTH_POOL_SIZE = 8
    num_cores = length(auth_pools)

    # Pre-allocate result vector (avoid dynamic growth)
    new_pools = Vector{Vector{Hash}}(undef, num_cores)

    # Process each core independently (parallelizable)
    @inbounds for core_idx in 1:num_cores
        # Get pool and queue for this core
        pool = auth_pools[core_idx]
        queue = auth_queues[core_idx]

        # F(core): Remove authorizer used in guarantee for this core
        # Per graypaper eq 27: pool \ {(g_workreport)_authorizer} if exists g where g_core = core
        removed_hash = H0  # Sentinel value for "no removal"

        for g in guarantees
            if g[:core] == core_idx - 1  # Test vectors use 0-indexed cores
                removed_hash = parse_hash(g[:auth_hash])
                break  # Only one guarantee per core per block
            end
        end

        # Build new pool efficiently
        # Pre-allocate with max possible size
        temp_pool = Vector{Hash}(undef, length(pool) + 1)
        write_idx = 1

        # Copy pool, filtering out removed hash if present
        if removed_hash != H0
            for i in 1:length(pool)
                if pool[i] != removed_hash
                    temp_pool[write_idx] = pool[i]
                    write_idx += 1
                end
            end
        else
            # No removal, just copy
            copyto!(temp_pool, 1, pool, 1, length(pool))
            write_idx = length(pool) + 1
        end

        # Get authorizer from queue at cyclic index based on slot
        queue_idx = (slot % length(queue)) + 1  # Julia 1-indexed
        new_auth = queue[queue_idx]

        # Append new authorizer
        temp_pool[write_idx] = new_auth
        write_idx += 1

        # overleftarrow: keep last C_AUTH_POOL_SIZE elements
        final_size = min(write_idx - 1, C_AUTH_POOL_SIZE)
        start_idx = max(1, write_idx - C_AUTH_POOL_SIZE)

        # Allocate exact size for final pool
        new_pool = Vector{Hash}(undef, final_size)
        copyto!(new_pool, 1, temp_pool, start_idx, final_size)

        new_pools[core_idx] = new_pool
    end

    return new_pools
end

# Parallel version for many cores
function process_authorizations_parallel(
    auth_pools::Vector{Vector{Hash}},
    auth_queues::Vector{Vector{Hash}},
    slot::TimeSlot,
    guarantees
)::Vector{Vector{Hash}}
    C_AUTH_POOL_SIZE = 8
    num_cores = length(auth_pools)
    new_pools = Vector{Vector{Hash}}(undef, num_cores)

    # Use threading for large core counts
    Threads.@threads for core_idx in 1:num_cores
        pool = auth_pools[core_idx]
        queue = auth_queues[core_idx]

        removed_hash = H0

        @inbounds for g in guarantees
            if g[:core] == core_idx - 1
                removed_hash = parse_hash(g[:auth_hash])
                break
            end
        end

        temp_pool = Vector{Hash}(undef, length(pool) + 1)
        write_idx = 1

        @inbounds if removed_hash != H0
            for i in 1:length(pool)
                if pool[i] != removed_hash
                    temp_pool[write_idx] = pool[i]
                    write_idx += 1
                end
            end
        else
            copyto!(temp_pool, 1, pool, 1, length(pool))
            write_idx = length(pool) + 1
        end

        queue_idx = (slot % length(queue)) + 1
        temp_pool[write_idx] = queue[queue_idx]
        write_idx += 1

        final_size = min(write_idx - 1, C_AUTH_POOL_SIZE)
        start_idx = max(1, write_idx - C_AUTH_POOL_SIZE)

        new_pool = Vector{Hash}(undef, final_size)
        @inbounds copyto!(new_pool, 1, temp_pool, start_idx, final_size)

        new_pools[core_idx] = new_pool
    end

    return new_pools
end

# Run authorizations test vector
function run_authorizations_test_vector(filepath::String)
    println("\n=== Running Authorizations Test Vector: $(basename(filepath)) ===")

    # Load test vector
    json_str = read(filepath, String)
    tv = JSON3.read(json_str)

    # Parse pre-state with Hash type
    pre_pools = [Hash[parse_hash(h) for h in pool] for pool in tv[:pre_state][:auth_pools]]
    pre_queues = [Hash[parse_hash(h) for h in queue] for queue in tv[:pre_state][:auth_queues]]

    # Parse input
    input_slot = UInt32(tv[:input][:slot])
    guarantees = tv[:input][:auths]

    println("Input:")
    println("  Slot: $input_slot")
    println("  Guarantees: $(length(guarantees))")
    println("  Pools: $(length(pre_pools))")
    println("  Queues: $(length(pre_queues))")

    # Run state transition (use parallel for many cores)
    result_pools = if length(pre_pools) > 16
        process_authorizations_parallel(pre_pools, pre_queues, input_slot, guarantees)
    else
        process_authorizations(pre_pools, pre_queues, input_slot, guarantees)
    end

    # Parse expected post-state
    post_pools = [Hash[parse_hash(h) for h in pool] for pool in tv[:post_state][:auth_pools]]

    # Compare
    println("\n=== State Comparison ===")
    all_match = true

    @inbounds for core_idx in 1:length(post_pools)
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

export process_authorizations, process_authorizations_parallel, run_authorizations_test_vector
