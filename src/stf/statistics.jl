# Statistics State Transition Function
# Updates validator statistics based on extrinsic contents

include("../types/basic.jl")
using JSON3

# Validator statistics structure
mutable struct ValidatorStats
    blocks::Int64
    tickets::Int64
    pre_images::Int64
    pre_images_size::Int64
    guarantees::Int64
    assurances::Int64
end

# State structure for statistics
struct StatisticsState
    curr_validators::Vector{Any}
    slot::TimeSlot
    vals_curr_stats::Vector{ValidatorStats}
    vals_last_stats::Union{Nothing, Vector{ValidatorStats}}
end

# Process statistics STF
# Per graypaper statistics.tex equations 39-68
function process_statistics(
    state::StatisticsState,
    slot::TimeSlot,
    author_index::Int,
    extrinsic::Dict{Symbol, Any};
    epoch_length::Int = 12  # Tiny test config uses 12, full uses 600
)::StatisticsState

    # Check for epoch change
    pre_epoch = div(state.slot, epoch_length)
    new_epoch = div(slot, epoch_length)

    # Handle epoch transition
    new_curr_stats, new_last_stats = if new_epoch == pre_epoch
        # Same epoch: keep accumulator and previous
        ([ValidatorStats(s.blocks, s.tickets, s.pre_images, s.pre_images_size, s.guarantees, s.assurances)
          for s in state.vals_curr_stats], state.vals_last_stats)
    else
        # New epoch: reset accumulator, move old to previous
        zero_stats = [ValidatorStats(0, 0, 0, 0, 0, 0) for _ in state.vals_curr_stats]
        (zero_stats, state.vals_curr_stats)
    end

    # Update the author's block count
    if author_index >= 0 && author_index < length(new_curr_stats)
        new_curr_stats[author_index + 1].blocks += 1

        # Count tickets (author only)
        if haskey(extrinsic, :tickets)
            new_curr_stats[author_index + 1].tickets += length(extrinsic[:tickets])
        end

        # Count preimages (author only)
        if haskey(extrinsic, :preimages)
            preimages = extrinsic[:preimages]
            new_curr_stats[author_index + 1].pre_images += length(preimages)
            # Sum preimage sizes
            for preimage in preimages
                if haskey(preimage, :blob)
                    blob = preimage[:blob]
                    if startswith(blob, "0x")
                        new_curr_stats[author_index + 1].pre_images_size += div(length(blob) - 2, 2)
                    else
                        new_curr_stats[author_index + 1].pre_images_size += length(blob)
                    end
                end
            end
        end
    end

    # Count guarantees per validator who signed
    # Per graypaper eq 62-63: increment for each validator in reporters set
    if haskey(extrinsic, :guarantees)
        for guarantee in extrinsic[:guarantees]
            if haskey(guarantee, :signatures)
                for sig in guarantee[:signatures]
                    validator_idx = sig[:validator_index] + 1  # Julia 1-indexed
                    if validator_idx >= 1 && validator_idx <= length(new_curr_stats)
                        new_curr_stats[validator_idx].guarantees += 1
                    end
                end
            end
        end
    end

    # Count assurances per validator who made them
    # Per graypaper eq 64-66: increment if assurer = validator
    if haskey(extrinsic, :assurances)
        for assurance in extrinsic[:assurances]
            if haskey(assurance, :validator_index)
                validator_idx = assurance[:validator_index] + 1  # Julia 1-indexed
                if validator_idx >= 1 && validator_idx <= length(new_curr_stats)
                    new_curr_stats[validator_idx].assurances += 1
                end
            end
        end
    end

    return StatisticsState(
        state.curr_validators,
        slot,
        new_curr_stats,
        new_last_stats
    )
end

# Run statistics test vector
function run_statistics_test_vector(filepath::String)
    println("\n=== Running Statistics Test Vector: $(basename(filepath)) ===")

    # Load test vector JSON directly
    json_str = read(filepath, String)
    tv = JSON3.read(json_str)

    # Parse pre-state
    pre = tv[:pre_state]
    pre_stats = [ValidatorStats(
        s[:blocks], s[:tickets], s[:pre_images],
        s[:pre_images_size], s[:guarantees], s[:assurances]
    ) for s in pre[:vals_curr_stats]]

    pre_last_stats = if haskey(pre, :vals_last_stats) && pre[:vals_last_stats] !== nothing
        [ValidatorStats(
            s[:blocks], s[:tickets], s[:pre_images],
            s[:pre_images_size], s[:guarantees], s[:assurances]
        ) for s in pre[:vals_last_stats]]
    else
        nothing
    end

    pre_state = StatisticsState(
        pre[:curr_validators],
        UInt32(pre[:slot]),
        pre_stats,
        pre_last_stats
    )

    # Parse input
    input = tv[:input]
    input_slot = UInt32(input[:slot])
    author_index = input[:author_index]
    extrinsic = Dict{Symbol, Any}(pairs(input[:extrinsic]))

    println("Input:")
    println("  Slot: $input_slot")
    println("  Author: $author_index")

    # Run state transition
    result_state = process_statistics(pre_state, input_slot, author_index, extrinsic)

    # Parse expected post-state
    post = tv[:post_state]
    post_stats = [ValidatorStats(
        s[:blocks], s[:tickets], s[:pre_images],
        s[:pre_images_size], s[:guarantees], s[:assurances]
    ) for s in post[:vals_curr_stats]]

    # Compare stats
    println("\n=== State Comparison ===")
    all_match = true

    for i in 1:length(post_stats)
        expected = post_stats[i]
        actual = result_state.vals_curr_stats[i]

        if expected.blocks != actual.blocks ||
           expected.tickets != actual.tickets ||
           expected.pre_images != actual.pre_images ||
           expected.pre_images_size != actual.pre_images_size ||
           expected.guarantees != actual.guarantees ||
           expected.assurances != actual.assurances

            println("❌ Validator $i stats mismatch:")
            println("  blocks: expected=$(expected.blocks), got=$(actual.blocks)")
            println("  tickets: expected=$(expected.tickets), got=$(actual.tickets)")
            println("  pre_images: expected=$(expected.pre_images), got=$(actual.pre_images)")
            println("  pre_images_size: expected=$(expected.pre_images_size), got=$(actual.pre_images_size)")
            println("  guarantees: expected=$(expected.guarantees), got=$(actual.guarantees)")
            println("  assurances: expected=$(expected.assurances), got=$(actual.assurances)")
            all_match = false
        end
    end

    if all_match
        println("✅ All validator stats match!")
    end

    # Final verdict
    println("\n=== Test Vector Result ===")
    if all_match
        println("✅ PASS - Test vector validated successfully!")
        return true
    else
        println("❌ FAIL - Test vector validation failed")
        return false
    end
end

# Export functions
export process_statistics, run_statistics_test_vector
