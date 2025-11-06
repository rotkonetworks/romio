# Statistics State Transition Function - Optimized
# Per graypaper section on statistics (statistics.tex)

include("../types/basic.jl")
using JSON3
using StructArrays

# Validator statistics structure - immutable and cache-aligned
# Padded to 64 bytes for perfect cache line alignment
struct ValidatorStats
    blocks::Int64
    tickets::Int64
    pre_images::Int64
    pre_images_size::Int64
    guarantees::Int64
    assurances::Int64
    _pad1::Int64  # Padding to 64 bytes (8 fields × 8 bytes)
    _pad2::Int64
end

# Constructor without padding arguments
ValidatorStats(blocks, tickets, pre_images, pre_images_size, guarantees, assurances) =
    ValidatorStats(blocks, tickets, pre_images, pre_images_size, guarantees, assurances, 0, 0)

# State structure for statistics - now uses StructArray
struct StatisticsState
    curr_validators::Vector{Any}
    slot::TimeSlot
    vals_curr_stats::StructArray{ValidatorStats}  # Struct-of-arrays layout
    vals_last_stats::Union{Nothing, StructArray{ValidatorStats}}
end

# Constructor from regular arrays
function StatisticsState(validators, slot, curr_stats::Vector{ValidatorStats}, last_stats)
    curr_sa = StructArray(curr_stats)
    last_sa = last_stats === nothing ? nothing : StructArray(last_stats)
    return StatisticsState(validators, slot, curr_sa, last_sa)
end

# Process statistics STF - optimized with StructArrays
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

    # Handle epoch transition with StructArrays
    new_curr_stats, new_last_stats = if new_epoch == pre_epoch
        # Same epoch: copy current stats (StructArray copy is efficient)
        (StructArray(state.vals_curr_stats), state.vals_last_stats)
    else
        # New epoch: reset accumulator, move old to previous
        num_validators = length(state.vals_curr_stats)
        zero_stats = StructArray{ValidatorStats}((
            blocks = zeros(Int64, num_validators),
            tickets = zeros(Int64, num_validators),
            pre_images = zeros(Int64, num_validators),
            pre_images_size = zeros(Int64, num_validators),
            guarantees = zeros(Int64, num_validators),
            assurances = zeros(Int64, num_validators),
            _pad1 = zeros(Int64, num_validators),
            _pad2 = zeros(Int64, num_validators)
        ))
        (zero_stats, state.vals_curr_stats)
    end

    # Update the author's block count (direct array access - cache friendly!)
    if author_index >= 0 && author_index < length(new_curr_stats)
        idx = author_index + 1
        new_curr_stats.blocks[idx] += 1

        # Count tickets (author only)
        if haskey(extrinsic, :tickets)
            new_curr_stats.tickets[idx] += length(extrinsic[:tickets])
        end

        # Count preimages (author only)
        if haskey(extrinsic, :preimages)
            preimages = extrinsic[:preimages]
            new_curr_stats.pre_images[idx] += length(preimages)

            # Sum preimage sizes
            total_size = 0
            @inbounds for preimage in preimages
                if haskey(preimage, :blob)
                    blob = preimage[:blob]
                    if startswith(blob, "0x")
                        total_size += div(length(blob) - 2, 2)
                    else
                        total_size += length(blob)
                    end
                end
            end
            new_curr_stats.pre_images_size[idx] += total_size
        end
    end

    # Count guarantees per validator who signed
    # Per graypaper eq 62-63: increment for each validator in reporters set
    # Direct array access with StructArrays enables SIMD optimization
    if haskey(extrinsic, :guarantees)
        @inbounds for guarantee in extrinsic[:guarantees]
            if haskey(guarantee, :signatures)
                for sig in guarantee[:signatures]
                    validator_idx = sig[:validator_index] + 1
                    if 1 <= validator_idx <= length(new_curr_stats)
                        new_curr_stats.guarantees[validator_idx] += 1
                    end
                end
            end
        end
    end

    # Count assurances per validator who made them
    # Per graypaper eq 64-66: increment if assurer = validator
    if haskey(extrinsic, :assurances)
        @inbounds for assurance in extrinsic[:assurances]
            if haskey(assurance, :validator_index)
                validator_idx = assurance[:validator_index] + 1
                if 1 <= validator_idx <= length(new_curr_stats)
                    new_curr_stats.assurances[validator_idx] += 1
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

    # Parse pre-state - convert to StructArray immediately
    pre = tv[:pre_state]
    pre_stats_vec = [ValidatorStats(
        s[:blocks], s[:tickets], s[:pre_images],
        s[:pre_images_size], s[:guarantees], s[:assurances]
    ) for s in pre[:vals_curr_stats]]
    pre_stats = StructArray(pre_stats_vec)

    pre_last_stats = if haskey(pre, :vals_last_stats) && pre[:vals_last_stats] !== nothing
        last_vec = [ValidatorStats(
            s[:blocks], s[:tickets], s[:pre_images],
            s[:pre_images_size], s[:guarantees], s[:assurances]
        ) for s in pre[:vals_last_stats]]
        StructArray(last_vec)
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
    post_stats_vec = [ValidatorStats(
        s[:blocks], s[:tickets], s[:pre_images],
        s[:pre_images_size], s[:guarantees], s[:assurances]
    ) for s in post[:vals_curr_stats]]

    # Compare stats (StructArray allows efficient field-by-field comparison)
    println("\n=== State Comparison ===")
    all_match = true

    @inbounds for i in 1:length(post_stats_vec)
        expected = post_stats_vec[i]
        # Access fields directly from StructArray
        actual_blocks = result_state.vals_curr_stats.blocks[i]
        actual_tickets = result_state.vals_curr_stats.tickets[i]
        actual_pre_images = result_state.vals_curr_stats.pre_images[i]
        actual_pre_images_size = result_state.vals_curr_stats.pre_images_size[i]
        actual_guarantees = result_state.vals_curr_stats.guarantees[i]
        actual_assurances = result_state.vals_curr_stats.assurances[i]

        if expected.blocks != actual_blocks ||
           expected.tickets != actual_tickets ||
           expected.pre_images != actual_pre_images ||
           expected.pre_images_size != actual_pre_images_size ||
           expected.guarantees != actual_guarantees ||
           expected.assurances != actual_assurances

            println("❌ Validator $i stats mismatch:")
            println("  blocks: expected=$(expected.blocks), got=$actual_blocks")
            println("  tickets: expected=$(expected.tickets), got=$actual_tickets")
            println("  pre_images: expected=$(expected.pre_images), got=$actual_pre_images")
            println("  pre_images_size: expected=$(expected.pre_images_size), got=$actual_pre_images_size")
            println("  guarantees: expected=$(expected.guarantees), got=$actual_guarantees")
            println("  assurances: expected=$(expected.assurances), got=$actual_assurances")
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
export process_statistics, run_statistics_test_vector, ValidatorStats, StatisticsState
