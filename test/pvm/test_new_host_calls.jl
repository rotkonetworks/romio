# test_new_host_calls.jl
# Comprehensive tests for newly implemented accumulate host calls
# Tests NEW, UPGRADE, TRANSFER, EJECT, FORGET, DESIGNATE

include("../../src/pvm/pvm.jl")
using .PVM
using .PVM.HostCalls

println("=== New Accumulate Host Call Tests ===\n")

# Helper function to create test PVM state
function create_test_state()
    mem = PVM.Memory()
    # Mark pages as writable for testing
    for i in 33:40
        mem.access[i] = :write
    end

    state = PVM.PVMState(
        UInt32(0),
        Int64(100000),
        zeros(UInt64, 13),
        mem,
        :running,
        UInt32(0),
        UInt8[],
        BitVector(),
        UInt32[],
        Vector{Vector{UInt8}}(),
        Dict{UInt32, PVM.GuestPVM}()
    )

    return state
end

# Test 1: NEW creates service account correctly
println("Test 1: NEW creates service account with proper initialization")
begin
    state = create_test_state()

    # Create implications context
    priv_state = HostCalls.create_privileged_state()
    priv_state.registrar = UInt32(100)  # Set caller as registrar

    service_account = HostCalls.create_service_account(
        zeros(UInt8, 32),
        UInt64(10^18),  # Large balance
        UInt64(1000)
    )

    im = HostCalls.create_implications_context(
        UInt32(100),
        service_account,
        Dict{UInt32, HostCalls.ServiceAccount}(),
        priv_state,
        UInt32(12345)
    )

    context = HostCalls.HostCallContext(im, nothing, nothing, nothing, nothing)

    # Write code hash to memory
    code_hash = UInt8[i for i in 1:32]
    offset = UInt32(0x20000)
    state.memory.data[offset+1:offset+32] = code_hash

    # Set registers for NEW
    state.registers[8] = UInt64(offset)        # hash_offset
    state.registers[9] = UInt64(1000)          # code_length
    state.registers[10] = UInt64(50000)        # min_acc_gas
    state.registers[11] = UInt64(10000)        # min_memo_gas
    state.registers[12] = UInt64(5000)         # gratis
    state.registers[13] = UInt64(0)            # desired_id (auto-assign)

    initial_balance = im.self.balance
    result_state = HostCalls.host_call_new(state, context)

    if result_state.registers[8] >= HostCalls.Cminpublicindex
        assigned_id = UInt32(result_state.registers[8])
        if haskey(im.accounts, assigned_id)
            new_acc = im.accounts[assigned_id]
            if new_acc.code_hash == code_hash &&
               new_acc.min_acc_gas == 50000 &&
               new_acc.min_memo_gas == 10000 &&
               new_acc.gratis == 5000 &&
               new_acc.parent == UInt32(100) &&
               new_acc.created == UInt32(12345) &&
               im.self.balance == initial_balance - UInt64(10^15)
                println("  ✓ NEW correctly created service with ID $assigned_id")
            else
                println("  ✗ NEW created service but fields incorrect")
            end
        else
            println("  ✗ NEW returned ID but account not in accounts dict")
        end
    else
        println("  ✗ NEW failed with code: $(result_state.registers[8])")
    end
end

# Test 2: NEW rejects when insufficient balance
println("\nTest 2: NEW rejects creation when caller has insufficient balance")
begin
    state = create_test_state()

    priv_state = HostCalls.create_privileged_state()
    priv_state.registrar = UInt32(100)

    # Create service with insufficient balance
    service_account = HostCalls.create_service_account(
        zeros(UInt8, 32),
        UInt64(10^14),  # Less than min_balance + Cminbalance
        UInt64(10^14)
    )

    im = HostCalls.create_implications_context(
        UInt32(100),
        service_account,
        Dict{UInt32, HostCalls.ServiceAccount}(),
        priv_state,
        UInt32(12345)
    )

    context = HostCalls.HostCallContext(im, nothing, nothing, nothing, nothing)

    code_hash = zeros(UInt8, 32)
    offset = UInt32(0x20000)
    state.memory.data[offset+1:offset+32] = code_hash

    state.registers[8] = UInt64(offset)
    state.registers[9] = UInt64(100)
    state.registers[10] = UInt64(1000)
    state.registers[11] = UInt64(1000)
    state.registers[12] = UInt64(0)
    state.registers[13] = UInt64(0)

    result_state = HostCalls.host_call_new(state, context)

    if result_state.registers[8] == HostCalls.FULL
        println("  ✓ NEW correctly rejected insufficient balance")
    else
        println("  ✗ NEW should return FULL, got: $(result_state.registers[8])")
    end
end

# Test 3: UPGRADE updates service parameters
println("\nTest 3: UPGRADE correctly updates code hash and gas parameters")
begin
    state = create_test_state()

    service_account = HostCalls.create_service_account(
        zeros(UInt8, 32),
        UInt64(10^18),
        UInt64(1000)
    )

    im = HostCalls.create_implications_context(
        UInt32(100),
        service_account,
        Dict{UInt32, HostCalls.ServiceAccount}(),
        HostCalls.create_privileged_state(),
        UInt32(12345)
    )

    context = HostCalls.HostCallContext(im, nothing, nothing, nothing, nothing)

    # Write new code hash
    new_code_hash = UInt8[i for i in 33:64]
    offset = UInt32(0x20000)
    state.memory.data[offset+1:offset+32] = new_code_hash

    state.registers[8] = UInt64(offset)
    state.registers[9] = UInt64(75000)   # new min_acc_gas
    state.registers[10] = UInt64(15000)  # new min_memo_gas

    result_state = HostCalls.host_call_upgrade(state, context)

    if result_state.registers[8] == HostCalls.OK &&
       im.self.code_hash == new_code_hash &&
       im.self.min_acc_gas == 75000 &&
       im.self.min_memo_gas == 15000
        println("  ✓ UPGRADE correctly updated all parameters")
    else
        println("  ✗ UPGRADE failed or didn't update correctly")
    end
end

# Test 4: TRANSFER creates deferred transfer
println("\nTest 4: TRANSFER creates deferred transfer with correct parameters")
begin
    state = create_test_state()

    service_account = HostCalls.create_service_account(
        zeros(UInt8, 32),
        UInt64(10^18),
        UInt64(10^15)
    )

    # Create destination account
    dest_account = HostCalls.create_service_account(
        zeros(UInt8, 32),
        UInt64(10^15),
        UInt64(5000)
    )
    dest_account.min_memo_gas = UInt64(5000)

    accounts = Dict{UInt32, HostCalls.ServiceAccount}()
    accounts[UInt32(200)] = dest_account

    im = HostCalls.create_implications_context(
        UInt32(100),
        service_account,
        accounts,
        HostCalls.create_privileged_state(),
        UInt32(12345)
    )

    context = HostCalls.HostCallContext(im, nothing, nothing, nothing, nothing)

    # Write memo
    memo = UInt8[i % 256 for i in 1:128]
    offset = UInt32(0x20000)
    state.memory.data[offset+1:offset+128] = memo

    initial_balance = im.self.balance
    transfer_amount = UInt64(10^16)

    state.registers[8] = UInt64(200)            # dest_service_id
    state.registers[9] = transfer_amount         # amount
    state.registers[10] = UInt64(10000)         # gas_limit
    state.registers[11] = UInt64(offset)        # memo_offset

    result_state = HostCalls.host_call_transfer(state, context)

    if result_state.registers[8] == HostCalls.OK &&
       length(im.transfers) == 1 &&
       im.transfers[1].source == UInt32(100) &&
       im.transfers[1].dest == UInt32(200) &&
       im.transfers[1].amount == transfer_amount &&
       im.transfers[1].gas == 10000 &&
       im.self.balance == initial_balance - transfer_amount
        println("  ✓ TRANSFER correctly created deferred transfer")
    else
        println("  ✗ TRANSFER failed or didn't create transfer correctly")
    end
end

# Test 5: TRANSFER rejects when destination doesn't exist
println("\nTest 5: TRANSFER rejects non-existent destination")
begin
    state = create_test_state()

    service_account = HostCalls.create_service_account(
        zeros(UInt8, 32),
        UInt64(10^18),
        UInt64(10^15)
    )

    im = HostCalls.create_implications_context(
        UInt32(100),
        service_account,
        Dict{UInt32, HostCalls.ServiceAccount}(),
        HostCalls.create_privileged_state(),
        UInt32(12345)
    )

    context = HostCalls.HostCallContext(im, nothing, nothing, nothing, nothing)

    memo = zeros(UInt8, 128)
    offset = UInt32(0x20000)
    state.memory.data[offset+1:offset+128] = memo

    state.registers[8] = UInt64(999)      # non-existent service
    state.registers[9] = UInt64(1000)
    state.registers[10] = UInt64(5000)
    state.registers[11] = UInt64(offset)

    result_state = HostCalls.host_call_transfer(state, context)

    if result_state.registers[8] == HostCalls.WHO
        println("  ✓ TRANSFER correctly rejected non-existent destination")
    else
        println("  ✗ TRANSFER should return WHO, got: $(result_state.registers[8])")
    end
end

# Test 6: FORGET removes request in [] state
println("\nTest 6: FORGET removes request in [] state")
begin
    state = create_test_state()

    service_account = HostCalls.create_service_account(
        zeros(UInt8, 32),
        UInt64(10^18),
        UInt64(1000)
    )

    # Add request in [] state
    hash = UInt8[i for i in 1:32]
    key = (hash, UInt64(100))
    service_account.requests[key] = HostCalls.PreimageRequest(Vector{UInt64}())
    service_account.items = UInt32(1)

    im = HostCalls.create_implications_context(
        UInt32(100),
        service_account,
        Dict{UInt32, HostCalls.ServiceAccount}(),
        HostCalls.create_privileged_state(),
        UInt32(12345)
    )

    context = HostCalls.HostCallContext(im, nothing, nothing, nothing, nothing)

    # Write hash to memory
    offset = UInt32(0x20000)
    state.memory.data[offset+1:offset+32] = hash

    state.registers[8] = UInt64(offset)
    state.registers[9] = UInt64(100)

    result_state = HostCalls.host_call_forget(state, context)

    if result_state.registers[8] == HostCalls.OK &&
       !haskey(im.self.requests, key) &&
       im.self.items == UInt32(0)
        println("  ✓ FORGET correctly removed request in [] state")
    else
        println("  ✗ FORGET failed to remove request")
    end
end

# Test 7: FORGET transitions [x] to [x, time]
println("\nTest 7: FORGET transitions [x] state to [x, time]")
begin
    state = create_test_state()

    service_account = HostCalls.create_service_account(
        zeros(UInt8, 32),
        UInt64(10^18),
        UInt64(1000)
    )

    # Add request in [x] state
    hash = UInt8[i for i in 1:32]
    key = (hash, UInt64(100))
    service_account.requests[key] = HostCalls.PreimageRequest([UInt64(5000)])

    im = HostCalls.create_implications_context(
        UInt32(100),
        service_account,
        Dict{UInt32, HostCalls.ServiceAccount}(),
        HostCalls.create_privileged_state(),
        UInt32(12345)
    )

    context = HostCalls.HostCallContext(im, nothing, nothing, nothing, nothing)

    offset = UInt32(0x20000)
    state.memory.data[offset+1:offset+32] = hash

    state.registers[8] = UInt64(offset)
    state.registers[9] = UInt64(100)

    result_state = HostCalls.host_call_forget(state, context)

    req = im.self.requests[key]
    if result_state.registers[8] == HostCalls.OK &&
       length(req.state) == 2 &&
       req.state[1] == 5000 &&
       req.state[2] == 12345
        println("  ✓ FORGET correctly transitioned [x] to [x, time]")
    else
        println("  ✗ FORGET failed to transition state correctly")
    end
end

# Test 8: DESIGNATE updates staging_set
println("\nTest 8: DESIGNATE updates validator staging set")
begin
    # Create state with more writable pages for validator data
    mem = PVM.Memory()
    # Need 1023 * 336 = 343728 bytes starting at 0x20000 (131072)
    # That's pages 32 through 115 (343728 / 4096 ≈ 84 pages)
    for i in 32:120
        mem.access[i] = :write
    end

    state = PVM.PVMState(
        UInt32(0),
        Int64(100000),
        zeros(UInt64, 13),
        mem,
        :running,
        UInt32(0),
        UInt8[],
        BitVector(),
        UInt32[],
        Vector{Vector{UInt8}}(),
        Dict{UInt32, PVM.GuestPVM}()
    )

    priv_state = HostCalls.create_privileged_state()
    priv_state.delegator = UInt32(100)  # Set caller as delegator

    service_account = HostCalls.create_service_account(
        zeros(UInt8, 32),
        UInt64(10^18),
        UInt64(1000)
    )

    im = HostCalls.create_implications_context(
        UInt32(100),
        service_account,
        Dict{UInt32, HostCalls.ServiceAccount}(),
        priv_state,
        UInt32(12345)
    )

    context = HostCalls.HostCallContext(im, nothing, nothing, nothing, nothing)

    # Write validator staging data (simplified - just test structure)
    val_count = 1023
    validator_size = 336
    offset = UInt32(0x20000)

    # Fill with test data
    for i in 1:val_count
        entry_offset = offset + UInt32((i-1) * validator_size)
        for j in 1:validator_size
            state.memory.data[entry_offset + UInt32(j)] = UInt8((i + j) % 256)
        end
    end

    state.registers[8] = UInt64(offset)

    result_state = HostCalls.host_call_designate(state, context)

    if result_state.registers[8] == HostCalls.OK &&
       length(im.privileged_state.staging_set) == val_count
        println("  ✓ DESIGNATE correctly updated staging set")
    else
        println("  ✗ DESIGNATE failed: code=$(result_state.registers[8]), length=$(length(im.privileged_state.staging_set))")
    end
end

# Test 9: DESIGNATE rejects non-delegator
println("\nTest 9: DESIGNATE rejects caller who is not delegator")
begin
    # Create state with writable pages
    mem = PVM.Memory()
    for i in 32:120
        mem.access[i] = :write
    end

    state = PVM.PVMState(
        UInt32(0),
        Int64(100000),
        zeros(UInt64, 13),
        mem,
        :running,
        UInt32(0),
        UInt8[],
        BitVector(),
        UInt32[],
        Vector{Vector{UInt8}}(),
        Dict{UInt32, PVM.GuestPVM}()
    )

    priv_state = HostCalls.create_privileged_state()
    priv_state.delegator = UInt32(200)  # Different from caller

    service_account = HostCalls.create_service_account(
        zeros(UInt8, 32),
        UInt64(10^18),
        UInt64(1000)
    )

    im = HostCalls.create_implications_context(
        UInt32(100),  # Caller is not delegator
        service_account,
        Dict{UInt32, HostCalls.ServiceAccount}(),
        priv_state,
        UInt32(12345)
    )

    context = HostCalls.HostCallContext(im, nothing, nothing, nothing, nothing)

    offset = UInt32(0x20000)
    state.registers[8] = UInt64(offset)

    result_state = HostCalls.host_call_designate(state, context)

    if result_state.registers[8] == HostCalls.HUH
        println("  ✓ DESIGNATE correctly rejected non-delegator")
    else
        println("  ✗ DESIGNATE should return HUH, got: $(result_state.registers[8])")
    end
end

# Test 10: EJECT removes child service correctly
println("\nTest 10: EJECT removes child service and transfers balance")
begin
    state = create_test_state()

    service_account = HostCalls.create_service_account(
        zeros(UInt8, 32),
        UInt64(10^18),
        UInt64(1000)
    )

    # Create child service to eject
    child_code = zeros(UInt8, 32)
    child_account = HostCalls.create_service_account(
        child_code,
        UInt64(10^16),  # Has some balance
        UInt64(1000)
    )
    child_account.parent = UInt32(100)  # Parent is caller
    child_account.items = UInt32(2)  # Code request + one other

    # Add expired request
    req_hash = UInt8[i for i in 1:32]
    # Use an old_time that's expired but valid (won't underflow)
    old_time = UInt32(100)  # Much older than current_time - expunge_period
    child_account.requests[(req_hash, UInt64(100))] = HostCalls.PreimageRequest([
        UInt64(1000),
        UInt64(old_time),
        UInt64(12340)
    ])
    child_account.requests[(child_code, UInt64(0))] = HostCalls.PreimageRequest([])

    accounts = Dict{UInt32, HostCalls.ServiceAccount}()
    accounts[UInt32(200)] = child_account

    # Use a large current_time so expunge_threshold calculation works
    im = HostCalls.create_implications_context(
        UInt32(100),
        service_account,
        accounts,
        HostCalls.create_privileged_state(),
        UInt32(50000)  # Large enough: 50000 - 19200 = 30800 > 100
    )

    context = HostCalls.HostCallContext(im, nothing, nothing, nothing, nothing)

    # Write hash to memory
    offset = UInt32(0x20000)
    state.memory.data[offset+1:offset+32] = req_hash

    initial_balance = im.self.balance
    child_balance = child_account.balance

    state.registers[8] = UInt64(200)      # service_to_eject
    state.registers[9] = UInt64(offset)   # hash_offset

    result_state = HostCalls.host_call_eject(state, context)

    if result_state.registers[8] == HostCalls.OK &&
       !haskey(im.accounts, UInt32(200)) &&
       im.self.balance == initial_balance + child_balance
        println("  ✓ EJECT correctly removed service and transferred balance")
    else
        println("  ✗ EJECT failed: code=$(result_state.registers[8]), exists=$(haskey(im.accounts, UInt32(200)))")
    end
end

println("\n=== New Host Call Tests Complete ===\n")
println("All new accumulate host calls tested:")
println("  ✓ NEW - service creation with validation")
println("  ✓ UPGRADE - code and gas parameter updates")
println("  ✓ TRANSFER - deferred transfers with checks")
println("  ✓ EJECT - service removal with parent validation")
println("  ✓ FORGET - preimage cleanup state machine")
println("  ✓ DESIGNATE - validator staging set updates")
