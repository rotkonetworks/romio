# Test state comparison framework

include("../../src/test_vectors/comparison.jl")

println("=== State Comparison Framework Test ===\n")

# Load a test vector
vector_path = "jam-test-vectors/stf/preimages/tiny/preimage_needed-1.json"
if !isfile(vector_path)
    println("⚠ Test vector file not found: $vector_path")
    exit(1)
end

tv = load_test_vector(vector_path)

# Test 1: Compare state to itself (should match perfectly)
println("Test 1: Compare pre_state to itself")
result = compare_states(tv.pre_state, tv.pre_state)
@assert result == true
println("")

# Test 2: Compare pre_state to post_state (may differ)
println("Test 2: Compare pre_state to post_state")
result = compare_states(tv.pre_state, tv.post_state)
println("\nResult: $(result ? "States match" : "States differ")")
println("")

# Test 3: Create modified state and detect difference
println("Test 3: Detect modified slot")
modified_state = State(
    tv.pre_state.slot + 1,  # Changed slot
    tv.pre_state.entropy,
    tv.pre_state.accounts,
    tv.pre_state.privileges,
    tv.pre_state.accumulated,
    tv.pre_state.ready_queue,
    tv.pre_state.statistics,
    tv.pre_state.validators,
    tv.pre_state.epoch,
    tv.pre_state.validators_next_epoch
)
result = compare_states(tv.pre_state, modified_state)
@assert result == false
println("")

println("=== State Comparison Tests Complete ===")
