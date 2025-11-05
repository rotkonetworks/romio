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
function process_statistics(
    state::StatisticsState,
    slot::TimeSlot,
    author_index::Int,
    extrinsic::Dict{Symbol, Any}
)::StatisticsState

    # Copy current stats (deep copy to avoid mutation)
    new_curr_stats = [ValidatorStats(s.blocks, s.tickets, s.pre_images, s.pre_images_size, s.guarantees, s.assurances)
                      for s in state.vals_curr_stats]

    # Update the author's statistics
    if author_index >= 0 && author_index < length(new_curr_stats)
        author_stats = new_curr_stats[author_index + 1]  # Julia 1-indexed

        # Increment blocks
        author_stats.blocks += 1

        # Count tickets
        if haskey(extrinsic, :tickets)
            author_stats.tickets += length(extrinsic[:tickets])
        end

        # Count preimages
        if haskey(extrinsic, :preimages)
            preimages = extrinsic[:preimages]
            author_stats.pre_images += length(preimages)
            # Sum preimage sizes
            for preimage in preimages
                if haskey(preimage, :blob)
                    blob = preimage[:blob]
                    if startswith(blob, "0x")
                        author_stats.pre_images_size += div(length(blob) - 2, 2)
                    else
                        author_stats.pre_images_size += length(blob)
                    end
                end
            end
        end

        # Count guarantees
        if haskey(extrinsic, :guarantees)
            author_stats.guarantees += length(extrinsic[:guarantees])
        end

        # Count assurances
        if haskey(extrinsic, :assurances)
            author_stats.assurances += length(extrinsic[:assurances])
        end
    end

    return StatisticsState(
        state.curr_validators,
        slot,
        new_curr_stats,
        state.vals_last_stats
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
