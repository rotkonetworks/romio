# test_accumulate_host_calls_rigorous.jl
# Rigorous test suite for accumulate host calls
# Tests edge cases, boundary conditions, overflows, and state consistency

include("../../src/pvm/pvm.jl")
using .PVM
using .PVM.HostCalls

# Test utilities
function setup_test_state()
    """Create a minimal PVM state for testing host calls"""
    mem = PVM.Memory()

    # Mark some pages as readable/writable for testing
    # Pages 32-35 (0x20000-0x23FFF)
    for i in 33:36
        mem.access[i] = :write
    end

    state = PVM.PVMState(
        UInt32(0),  # pc
        Int64(100000),  # gas
        zeros(UInt64, 13),  # registers
        mem,
        :running,
        UInt32(0),  # host_call_id
        UInt8[],  # instructions
        BitVector(),  # opcode_mask
        UInt32[],  # jump_table
        Vector{Vector{UInt8}}(),  # exports
        Dict{UInt32, PVM.GuestPVM}()  # machines
    )

    return state
end

function setup_test_implications()
    """Create implications context for accumulate testing"""
    priv_state = HostCalls.create_privileged_state()
    priv_state.manager = UInt32(1)
    priv_state.delegator = UInt32(2)
    priv_state.registrar = UInt32(3)

    service_account = HostCalls.create_service_account(
        zeros(UInt8, 32),  # code_hash
        UInt64(1000000),  # balance
        UInt64(1000)  # min_balance
    )

    accounts = Dict{UInt32, HostCalls.ServiceAccount}()
    accounts[UInt32(100)] = service_account

    im = HostCalls.create_implications_context(
        UInt32(100),
        service_account,
        accounts,
        priv_state,
        UInt32(12345)  # current_time
    )

    return im
end

println("=== Rigorous Accumulate Host Call Tests ===\n")

# ========================================
# Test 1: BLESS - Boundary Conditions
# ========================================
println("Test 1: BLESS with boundary service IDs")

begin
    state = setup_test_state()
    im = setup_test_implications()
    context = HostCalls.HostCallContext(im, nothing, nothing, nothing, nothing)

    # Write test data to memory
    # Authorizers array at 0x20000 (2 cores * 4 bytes)
    offset = UInt32(0x20000)
    for i in 1:HostCalls.Ccorecount
        # Write service ID = i
        for j in 0:3
            state.memory.data[offset + (i-1)*4 + j + 1] = UInt8((i >> (8*j)) & 0xFF)
        end
    end

    # Always-access array at 0x20100 (0 entries for this test)
    access_offset = UInt32(0x20100)

    # Set registers
    state.registers[8] = UInt64(1)  # manager_id
    state.registers[9] = UInt64(offset)  # auth_offset
    state.registers[10] = UInt64(2)  # validator_id
    state.registers[11] = UInt64(3)  # registrar_id
    state.registers[12] = UInt64(access_offset)  # access_offset
    state.registers[13] = UInt64(0)  # access_count

    # Call bless
    state = HostCalls.host_call_bless(state, context)

    if state.registers[8] == HostCalls.OK
        println("  ✓ BLESS succeeded with valid service IDs")
    else
        println("  ✗ BLESS failed: r7 = $(state.registers[8])")
    end
end

# ========================================
# Test 2: BLESS - Invalid Service ID (Overflow)
# ========================================
println("\nTest 2: BLESS with service ID >= 2^32")

begin
    state = setup_test_state()
    im = setup_test_implications()
    context = HostCalls.HostCallContext(im, nothing, nothing, nothing, nothing)

    # Setup memory
    offset = UInt32(0x20000)
    state.memory.data[offset+1:offset+8] .= 0x00

    # Set registers with manager_id >= 2^32
    state.registers[8] = UInt64(2^32)  # INVALID: manager_id >= 2^32
    state.registers[9] = UInt64(offset)
    state.registers[10] = UInt64(2)
    state.registers[11] = UInt64(3)
    state.registers[12] = UInt64(offset + 0x100)
    state.registers[13] = UInt64(0)

    state = HostCalls.host_call_bless(state, context)

    if state.registers[8] == HostCalls.WHO
        println("  ✓ BLESS correctly rejected service ID >= 2^32")
    else
        println("  ✗ BLESS should have returned WHO, got $(state.registers[8])")
    end
end

# ========================================
# Test 3: BLESS - Memory Out of Bounds
# ========================================
println("\nTest 3: BLESS with memory out of bounds")

begin
    state = setup_test_state()
    im = setup_test_implications()
    context = HostCalls.HostCallContext(im, nothing, nothing, nothing, nothing)

    # Set registers with auth_offset pointing to unreadable memory
    state.registers[8] = UInt64(1)
    state.registers[9] = UInt64(0x100000)  # Way out of bounds
    state.registers[10] = UInt64(2)
    state.registers[11] = UInt64(3)
    state.registers[12] = UInt64(0x20000)
    state.registers[13] = UInt64(0)

    state = HostCalls.host_call_bless(state, context)

    if state.status == :panic
        println("  ✓ BLESS correctly panicked on OOB memory")
    else
        println("  ✗ BLESS should have panicked, status = $(state.status)")
    end
end

# ========================================
# Test 4: ASSIGN - Core Ownership Validation
# ========================================
println("\nTest 4: ASSIGN with incorrect core ownership")

begin
    state = setup_test_state()
    im = setup_test_implications()

    # Set up assigners - core 0 owned by service 999, not 100
    im.privileged_state.assigners = [UInt32(999), UInt32(0)]

    context = HostCalls.HostCallContext(im, nothing, nothing, nothing, nothing)

    # Write auth queue to memory
    offset = UInt32(0x20000)
    for i in 1:HostCalls.Cauthqueuesize
        for j in 0:31
            state.memory.data[offset + (i-1)*32 + j + 1] = UInt8(i & 0xFF)
        end
    end

    # Try to assign core 0 (owned by 999, not 100)
    state.registers[8] = UInt64(0)  # core_index
    state.registers[9] = UInt64(offset)  # queue_offset
    state.registers[10] = UInt64(42)  # new assigner_id

    state = HostCalls.host_call_assign(state, context)

    if state.registers[8] == HostCalls.HUH
        println("  ✓ ASSIGN correctly rejected unauthorized core assignment")
    else
        println("  ✗ ASSIGN should have returned HUH, got $(state.registers[8])")
    end
end

# ========================================
# Test 5: ASSIGN - Core Index Out of Range
# ========================================
println("\nTest 5: ASSIGN with core index >= Ccorecount")

begin
    state = setup_test_state()
    im = setup_test_implications()
    context = HostCalls.HostCallContext(im, nothing, nothing, nothing, nothing)

    offset = UInt32(0x20000)
    state.memory.data[offset+1:offset+100] .= 0x00

    # Try to assign core that doesn't exist
    state.registers[8] = UInt64(HostCalls.Ccorecount)  # INVALID: >= Ccorecount
    state.registers[9] = UInt64(offset)
    state.registers[10] = UInt64(42)

    state = HostCalls.host_call_assign(state, context)

    if state.registers[8] == HostCalls.CORE
        println("  ✓ ASSIGN correctly rejected invalid core index")
    else
        println("  ✗ ASSIGN should have returned CORE, got $(state.registers[8])")
    end
end

# ========================================
# Test 6: QUERY - Preimage Request States
# ========================================
println("\nTest 6: QUERY with all preimage request states")

begin
    state = setup_test_state()
    im = setup_test_implications()

    # Test hash
    test_hash = zeros(UInt8, 32)
    test_hash[1] = 0x42

    # Test all states
    test_cases = [
        (Vector{UInt64}(), "empty []", 0, 0),
        ([UInt64(100)], "partial [x]", 1 + (100 << 32), 0),
        ([UInt64(100), UInt64(200)], "pending [x,y]", 2 + (100 << 32), 200),
        ([UInt64(100), UInt64(200), UInt64(300)], "available [x,y,z]", 3 + (100 << 32), 200 + (300 << 32))
    ]

    all_passed = true
    for (state_vec, desc, expected_r7, expected_r8) in test_cases
        # Create fresh state and context
        test_state = setup_test_state()
        test_im = setup_test_implications()

        # Add request with specific state
        key = (test_hash, UInt64(32))
        test_im.self.requests[key] = HostCalls.PreimageRequest(copy(state_vec))

        test_context = HostCalls.HostCallContext(test_im, nothing, nothing, nothing, nothing)

        # Write hash to memory
        offset = UInt32(0x20000)
        test_state.memory.data[offset+1:offset+32] = test_hash

        # Set registers
        test_state.registers[8] = UInt64(offset)  # hash_offset
        test_state.registers[9] = UInt64(32)  # length

        # Call query
        test_state = HostCalls.host_call_query(test_state, test_context)

        if test_state.registers[8] == expected_r7 && test_state.registers[9] == expected_r8
            println("  ✓ QUERY correctly encoded $desc")
        else
            println("  ✗ QUERY $desc: expected ($(expected_r7), $(expected_r8)), got ($(test_state.registers[8]), $(test_state.registers[9]))")
            all_passed = false
        end
    end

    if all_passed
        println("  ✓ All QUERY state encodings passed")
    end
end

# ========================================
# Test 7: SOLICIT - Invalid State Transitions
# ========================================
println("\nTest 7: SOLICIT with invalid state transitions")

begin
    state = setup_test_state()
    im = setup_test_implications()

    test_hash = zeros(UInt8, 32)
    test_hash[1] = 0x99

    # Try to transition from [x] state (invalid - should be [] or [x,y])
    key = (test_hash, UInt64(64))
    im.self.requests[key] = HostCalls.PreimageRequest([UInt64(500)])

    context = HostCalls.HostCallContext(im, nothing, nothing, nothing, nothing)

    # Write hash to memory
    offset = UInt32(0x20000)
    state.memory.data[offset+1:offset+32] = test_hash

    state.registers[8] = UInt64(offset)
    state.registers[9] = UInt64(64)

    state = HostCalls.host_call_solicit(state, context)

    if state.registers[8] == HostCalls.HUH
        println("  ✓ SOLICIT correctly rejected invalid state transition from [x]")
    else
        println("  ✗ SOLICIT should have returned HUH, got $(state.registers[8])")
    end
end

# ========================================
# Test 8: SOLICIT - Balance Check
# ========================================
println("\nTest 8: SOLICIT with insufficient balance")

begin
    state = setup_test_state()
    im = setup_test_implications()

    # Set balance < min_balance
    im.self.balance = 500
    im.self.min_balance = 1000

    test_hash = zeros(UInt8, 32)
    test_hash[1] = 0xAA

    context = HostCalls.HostCallContext(im, nothing, nothing, nothing, nothing)

    offset = UInt32(0x20000)
    state.memory.data[offset+1:offset+32] = test_hash

    state.registers[8] = UInt64(offset)
    state.registers[9] = UInt64(128)

    state = HostCalls.host_call_solicit(state, context)

    if state.registers[8] == HostCalls.FULL
        println("  ✓ SOLICIT correctly detected insufficient balance")
    else
        println("  ✗ SOLICIT should have returned FULL, got $(state.registers[8])")
    end
end

# ========================================
# Test 9: YIELD - Hash Storage
# ========================================
println("\nTest 9: YIELD correctly stores hash")

begin
    state = setup_test_state()
    im = setup_test_implications()

    test_hash = UInt8[i for i in 1:32]

    context = HostCalls.HostCallContext(im, nothing, nothing, nothing, nothing)

    offset = UInt32(0x20000)
    state.memory.data[offset+1:offset+32] = test_hash

    state.registers[8] = UInt64(offset)

    state = HostCalls.host_call_yield(state, context)

    if state.registers[8] == HostCalls.OK && !isnothing(im.yield_hash) && im.yield_hash == test_hash
        println("  ✓ YIELD correctly stored hash")
    else
        println("  ✗ YIELD failed to store hash correctly")
    end
end

# ========================================
# Test 10: PROVIDE - Duplicate Provision Check
# ========================================
println("\nTest 10: PROVIDE with duplicate provision")

begin
    state = setup_test_state()
    im = setup_test_implications()

    test_data = UInt8[i for i in 1:100]
    test_hash = zeros(UInt8, 32)
    test_hash[1] = 0xBB

    # Add request in [] state
    key = (test_hash, UInt64(100))
    im.self.requests[key] = HostCalls.PreimageRequest(Vector{UInt64}())

    # Add provision to set (simulating previous provide)
    push!(im.provisions, (UInt32(100), test_data))

    context = HostCalls.HostCallContext(im, nothing, nothing, nothing, nothing)

    # Write data to memory
    offset = UInt32(0x20000)
    state.memory.data[offset+1:offset+100] = test_data

    state.registers[8] = typemax(UInt64)  # self
    state.registers[9] = UInt64(offset)
    state.registers[10] = UInt64(100)

    state = HostCalls.host_call_provide(state, context)

    if state.registers[8] == HostCalls.HUH
        println("  ✓ PROVIDE correctly rejected duplicate provision")
    else
        println("  ✗ PROVIDE should have returned HUH, got $(state.registers[8])")
    end
end

# ========================================
# Test 11: CHECKPOINT - Exceptional State Creation
# ========================================
println("\nTest 11: CHECKPOINT creates exceptional state")

begin
    state = setup_test_state()
    im = setup_test_implications()

    # Add some state before checkpoint
    im.yield_hash = zeros(UInt8, 32)
    push!(im.transfers, HostCalls.DeferredTransfer(
        UInt32(1), UInt32(2), UInt64(1000), zeros(UInt8, 128), UInt64(5000)
    ))

    context = HostCalls.HostCallContext(im, nothing, nothing, nothing, nothing)

    state = HostCalls.host_call_checkpoint(state, context)

    if state.registers[8] == UInt64(state.gas) && !isnothing(im.exceptional_state)
        println("  ✓ CHECKPOINT created exceptional state and returned gas")
    else
        println("  ✗ CHECKPOINT failed to create exceptional state")
    end
end

# ========================================
# Test 12: Gas Exhaustion
# ========================================
println("\nTest 12: Gas exhaustion handling")

begin
    state = setup_test_state()
    state.gas = 5  # Not enough for any host call (need 10)

    im = setup_test_implications()
    context = HostCalls.HostCallContext(im, nothing, nothing, nothing, nothing)

    state = HostCalls.host_call_bless(state, context)

    if state.status == :oog
        println("  ✓ Correctly detected out-of-gas")
    else
        println("  ✗ Should have detected out-of-gas, status = $(state.status)")
    end
end

println("\n=== Rigorous Test Suite Complete ===")
println("\nAll tests exercise:")
println("  ✓ Boundary conditions (max/min values)")
println("  ✓ Memory safety (out of bounds detection)")
println("  ✓ Integer overflow checks (service ID >= 2^32)")
println("  ✓ State consistency (request transitions)")
println("  ✓ Authorization (core ownership)")
println("  ✓ Resource limits (gas, balance)")
println("  ✓ Duplicate detection (provisions)")
println("  ✓ Error paths (panic, OOG, invalid params)")
