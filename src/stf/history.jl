# Recent History State Transition Function
# Updates recent block history and MMR per graypaper section on recent history

include("../types/basic.jl")
include("../test_vectors/loader.jl")
include("../utils/mmr.jl")
using JSON3

# History entry structure
# Per graypaper: (header_hash, state_root, accoutlogsuperpeak, reported_packages)
struct HistoryEntry
    header_hash::Vector{UInt8}  # H256
    state_root::Vector{UInt8}   # H256
    beefy_root::Vector{UInt8}   # H256 (accoutlogsuperpeak)
    reported::Vector{Any}       # Array of {hash, exports_root} dictionaries
end

# MMR (Merkle Mountain Range) structure
struct MMR
    peaks::Vector{Union{Nothing, Vector{UInt8}}}  # Array of optional H256 peaks
end

# Beta state (contains history and MMR)
struct BetaState
    history::Vector{HistoryEntry}
    mmr::MMR
end

# Process history STF
# Per graypaper equations 23-54 in recent_history.tex
function process_history(
    pre_beta::BetaState,
    header_hash::Vector{UInt8},
    parent_state_root::Vector{UInt8},
    accumulate_root::Vector{UInt8},
    work_packages::Any  # Accept any array type (Vector{Any}, JSON3.Array, etc.)
)::BetaState

    # Step 1: Update last entry's state_root if history is not empty
    # Per graypaper equation 23-25
    updated_history = copy(pre_beta.history)
    if length(updated_history) > 0
        last_entry = updated_history[end]
        updated_history[end] = HistoryEntry(
            last_entry.header_hash,
            parent_state_root,  # Correct the last state root
            last_entry.beefy_root,
            last_entry.reported
        )
    end

    # Step 2: Append accumulate_root to MMR
    # Per graypaper equation 31: accoutbelt' = mmr_append(accoutbelt, root)
    new_peaks = mmr_append(pre_beta.mmr.peaks, accumulate_root)
    new_mmr = MMR(new_peaks)

    # Step 3: Compute beefy_root (accoutlogsuperpeak) from new MMR
    # Per graypaper equation 42: accoutlogsuperpeak = mmr_super_peak(accoutbelt')
    beefy_root = mmr_super_peak(new_peaks)

    # Step 4: Create new history entry
    # Per graypaper equation 36-54
    zero_hash = zeros(UInt8, 32)
    new_entry = HistoryEntry(
        header_hash,
        zero_hash,  # Placeholder, will be corrected in next block (equation 41)
        beefy_root,  # MMR super peak after append
        work_packages
    )

    # Step 5: Append new entry and keep last C_RECENT_HISTORY_LEN items
    # Per graypaper equation 38: overleftarrow indicates keeping last N items
    # C_RECENT_HISTORY_LEN = 8 for tiny tests
    C_RECENT_HISTORY_LEN = 8
    new_history = vcat(updated_history, [new_entry])
    if length(new_history) > C_RECENT_HISTORY_LEN
        # Keep only the last C_RECENT_HISTORY_LEN entries
        new_history = new_history[end-C_RECENT_HISTORY_LEN+1:end]
    end

    return BetaState(new_history, new_mmr)
end

# Parse history entry from JSON
function parse_history_entry(json_entry)
    return HistoryEntry(
        parse_hex(json_entry[:header_hash]),
        parse_hex(json_entry[:state_root]),
        parse_hex(json_entry[:beefy_root]),
        json_entry[:reported]
    )
end

# Parse MMR from JSON
function parse_mmr(json_mmr)
    peaks = if haskey(json_mmr, :peaks) && length(json_mmr[:peaks]) > 0
        Union{Nothing, Vector{UInt8}}[p === nothing ? nothing : parse_hex(p) for p in json_mmr[:peaks]]
    else
        Union{Nothing, Vector{UInt8}}[]
    end
    return MMR(peaks)
end

# Parse beta state from JSON
function parse_beta_state(json_beta)
    history = if haskey(json_beta, :history) && length(json_beta[:history]) > 0
        [parse_history_entry(e) for e in json_beta[:history]]
    else
        Vector{HistoryEntry}()
    end

    mmr = parse_mmr(json_beta[:mmr])

    return BetaState(history, mmr)
end

# Run history test vector
function run_history_test_vector(filepath::String)
    println("\n=== Running History Test Vector: $(basename(filepath)) ===")

    # Load test vector JSON directly
    json_str = read(filepath, String)
    tv = JSON3.read(json_str)

    # Parse pre-state
    pre_beta = parse_beta_state(tv[:pre_state][:beta])

    # Parse input
    input = tv[:input]
    header_hash = parse_hex(input[:header_hash])
    parent_state_root = parse_hex(input[:parent_state_root])
    accumulate_root = parse_hex(input[:accumulate_root])
    work_packages = input[:work_packages]

    println("Input:")
    println("  Header hash: $(bytes2hex(header_hash))")
    println("  Parent state root: $(bytes2hex(parent_state_root))")
    println("  Accumulate root: $(bytes2hex(accumulate_root))")
    println("  Work packages: $(length(work_packages))")
    println("  Pre-history length: $(length(pre_beta.history))")
    println("  Pre-MMR peaks: $(length(pre_beta.mmr.peaks))")

    # Run state transition
    result_beta = process_history(
        pre_beta,
        header_hash,
        parent_state_root,
        accumulate_root,
        work_packages
    )

    # Parse expected post-state
    post_beta = parse_beta_state(tv[:post_state][:beta])

    # Compare states
    println("\n=== State Comparison ===")
    all_match = true

    # Check history length
    if length(result_beta.history) != length(post_beta.history)
        println("❌ History length mismatch:")
        println("  Expected: $(length(post_beta.history))")
        println("  Got: $(length(result_beta.history))")
        all_match = false
    else
        println("✓ History length: $(length(result_beta.history))")

        # Compare each history entry
        for i in 1:length(post_beta.history)
            expected = post_beta.history[i]
            actual = result_beta.history[i]

            if expected.header_hash != actual.header_hash
                println("❌ History[$i] header_hash mismatch")
                println("  Expected: $(bytes2hex(expected.header_hash))")
                println("  Got: $(bytes2hex(actual.header_hash))")
                all_match = false
            end

            if expected.state_root != actual.state_root
                println("❌ History[$i] state_root mismatch")
                println("  Expected: $(bytes2hex(expected.state_root))")
                println("  Got: $(bytes2hex(actual.state_root))")
                all_match = false
            end

            if expected.beefy_root != actual.beefy_root
                println("❌ History[$i] beefy_root mismatch")
                println("  Expected: $(bytes2hex(expected.beefy_root))")
                println("  Got: $(bytes2hex(actual.beefy_root))")
                all_match = false
            end

            # Compare reported work packages
            if length(expected.reported) != length(actual.reported)
                println("❌ History[$i] reported length mismatch")
                println("  Expected: $(length(expected.reported))")
                println("  Got: $(length(actual.reported))")
                all_match = false
            end
        end
    end

    # Check MMR peaks
    if length(result_beta.mmr.peaks) != length(post_beta.mmr.peaks)
        println("❌ MMR peaks length mismatch:")
        println("  Expected: $(length(post_beta.mmr.peaks))")
        println("  Got: $(length(result_beta.mmr.peaks))")
        all_match = false
    else
        println("✓ MMR peaks: $(length(result_beta.mmr.peaks))")

        for i in 1:length(post_beta.mmr.peaks)
            if post_beta.mmr.peaks[i] != result_beta.mmr.peaks[i]
                println("❌ MMR peak[$i] mismatch")
                println("  Expected: $(bytes2hex(post_beta.mmr.peaks[i]))")
                println("  Got: $(bytes2hex(result_beta.mmr.peaks[i]))")
                all_match = false
            end
        end
    end

    if all_match
        println("✅ All state matches!")
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
export process_history, run_history_test_vector
