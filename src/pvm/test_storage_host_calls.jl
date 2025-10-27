# test_storage_host_calls.jl
# Test storage and account-related host calls (info, read, write, lookup)

include("pvm.jl")
using .PVM
using .PVM.HostCalls

println("=== PVM Storage Host Call Tests ===\n")

# Helper to create test service account
function create_test_account()
    account = HostCalls.ServiceAccount(
        Dict{Vector{UInt8}, Vector{UInt8}}(),  # storage
        Dict{Vector{UInt8}, Vector{UInt8}}(),  # preimages
        rand(UInt8, 32),  # code_hash
        UInt64(10000),    # balance
        UInt64(100),      # min_balance
        UInt64(1000),     # min_acc_gas
        UInt64(500),      # min_memo_gas
        UInt64(0),        # octets
        UInt32(0),        # items
        UInt64(0),        # gratis
        UInt32(100),      # created
        UInt32(150),      # last_acc
        UInt32(0)         # parent
    )

    # Add some test storage
    account.storage[UInt8[0x01, 0x02]] = UInt8[0x41, 0x42, 0x43]  # key=[1,2], value="ABC"
    account.items = 1
    account.octets = UInt64(34 + 2 + 3)  # overhead + key + value

    # Add a test preimage
    test_hash = rand(UInt8, 32)
    test_preimage = UInt8[0x48, 0x65, 0x6c, 0x6c, 0x6f]  # "Hello"
    account.preimages[test_hash] = test_preimage

    return (account, test_hash)
end

println("Test 1: Info host call - retrieve service account information")
println("  Creating test service account...")

(test_account, test_hash) = create_test_account()
accounts = Dict{UInt32, HostCalls.ServiceAccount}(
    UInt32(42) => test_account
)

context = HostCalls.HostCallContext(
    test_account,
    UInt32(42),
    accounts
)

# Create a simple PVM state (we'll manually call the host function)
# In a real test, we'd execute PVM code that calls the host function
println("  Calling info host call...")

# Mock PVM state
mutable struct MockState
    gas::Int64
    registers::Vector{UInt64}
    memory::PVM.Memory
    status::Symbol
end

state = MockState(
    1000,
    zeros(UInt64, 13),
    PVM.Memory(),
    :continue
)

# Setup writable memory for output
for i in 1:10
    state.memory.access[i] = :write
end

# Set registers for info call:
# r7 = service ID (42)
# r8 = output offset (0x1000)
# r9 = source offset (0)
# r10 = length to copy (200)
state.registers[8] = UInt64(42)        # r7: service ID
state.registers[9] = UInt64(0x1000)    # r8: output offset
state.registers[10] = UInt64(0)        # r9: source offset
state.registers[11] = UInt64(200)      # r10: length

state = HostCalls.host_call_info(state, context)

result_length = state.registers[8]
# Encoded size: 32 (code_hash) + 8*5 (balance,min_balance,min_acc_gas,min_memo_gas,octets) +
#               4 (items) + 8 (gratis) + 4*3 (created,last_acc,parent) = 32+40+4+8+12 = 96 bytes
expected_length = 96
println("  Result: got $result_length bytes of account info")
println("  Expected: $expected_length bytes")

if result_length == expected_length && state.gas == 990
    println("  ✓ TEST PASSED")
else
    println("  ✗ TEST FAILED")
    println("    Result length: $result_length (expected $expected_length)")
    println("    Gas: $(state.gas) (expected 990)")
end

println("\n" * "="^60)

# Test 2: Read host call
println("\nTest 2: Read host call - read from storage")

state2 = MockState(
    1000,
    zeros(UInt64, 13),
    PVM.Memory(),
    :continue
)

# Setup memory permissions
for i in 1:10
    state2.memory.access[i] = :write
end
for i in 11:20
    state2.memory.access[i] = :read
end

# Write test key to memory at offset 0x2000
key = UInt8[0x01, 0x02]
for (i, b) in enumerate(key)
    state2.memory.data[0x2000 + i] = b
end

# Mark that memory as readable
state2.memory.access[div(0x2000, 4096) + 1] = :read

# Set registers for read call:
# r7 = service ID (2^64-1 for self)
# r8 = key offset
# r9 = key length
# r10 = output offset
# r11 = source offset in value
# r12 = length to copy
state2.registers[8] = typemax(UInt64)  # r7: self
state2.registers[9] = UInt64(0x2000)   # r8: key offset
state2.registers[10] = UInt64(2)       # r9: key length
state2.registers[11] = UInt64(0x3000)  # r10: output offset
state2.registers[12] = UInt64(0)       # r11: source offset
state2.registers[13] = UInt64(10)      # r12: length to copy

# Mark output memory as writable
state2.memory.access[div(0x3000, 4096) + 1] = :write

state2 = HostCalls.host_call_read(state2, context)

result_length2 = state2.registers[8]
println("  Result: value length = $result_length2")
println("  Expected: 3 (value is 'ABC')")

# Check if value was copied to memory
copied_value = state2.memory.data[0x3001:0x3003]
println("  Copied value: $(String(copy(copied_value)))")

if result_length2 == 3 && copied_value == UInt8[0x41, 0x42, 0x43] && state2.gas == 990
    println("  ✓ TEST PASSED")
else
    println("  ✗ TEST FAILED")
end

println("\n" * "="^60)

# Test 3: Write host call
println("\nTest 3: Write host call - write to storage")

state3 = MockState(
    1000,
    zeros(UInt64, 13),
    PVM.Memory(),
    :continue
)

# Make service account mutable for this test
mutable_account = test_account
mutable_context = HostCalls.HostCallContext(
    mutable_account,
    UInt32(42),
    accounts
)

# Setup memory
for i in 1:100
    state3.memory.access[i] = :read
end

# Write new key and value to memory
new_key = UInt8[0x03, 0x04]
new_value = UInt8[0x58, 0x59, 0x5A]  # "XYZ"

for (i, b) in enumerate(new_key)
    state3.memory.data[0x4000 + i] = b
end

for (i, b) in enumerate(new_value)
    state3.memory.data[0x5000 + i] = b
end

# Mark memory as readable
state3.memory.access[div(0x4000, 4096) + 1] = :read
state3.memory.access[div(0x5000, 4096) + 1] = :read

# Set registers for write call:
# r7 = key offset
# r8 = key length
# r9 = value offset
# r10 = value length
state3.registers[8] = UInt64(0x4000)   # r7: key offset
state3.registers[9] = UInt64(2)        # r8: key length
state3.registers[10] = UInt64(0x5000)  # r9: value offset
state3.registers[11] = UInt64(3)       # r10: value length

items_before = mutable_account.items
state3 = HostCalls.host_call_write(state3, mutable_context)

old_value_len = state3.registers[8]
items_after = mutable_account.items

println("  Old value length: $old_value_len (should be NONE for new key)")
println("  Items before: $items_before, after: $items_after")
println("  New item in storage: $(haskey(mutable_account.storage, new_key))")

if old_value_len == HostCalls.NONE && items_after == items_before + 1 &&
   haskey(mutable_account.storage, new_key) && state3.gas == 990
    println("  ✓ TEST PASSED")
else
    println("  ✗ TEST FAILED")
end

println("\n" * "="^60)

# Test 4: Lookup host call
println("\nTest 4: Lookup host call - preimage lookup")

state4 = MockState(
    1000,
    zeros(UInt64, 13),
    PVM.Memory(),
    :continue
)

# Setup memory
for i in 1:100
    state4.memory.access[i] = :write
end

# Write hash to memory
for (i, b) in enumerate(test_hash)
    state4.memory.data[0x6000 + i] = b
end

# Mark hash memory as readable
state4.memory.access[div(0x6000, 4096) + 1] = :read

# Set registers for lookup call:
# r7 = service ID
# r8 = hash offset
# r9 = output offset
# r10 = source offset
# r11 = length to copy
state4.registers[8] = typemax(UInt64)  # r7: self
state4.registers[9] = UInt64(0x6000)   # r8: hash offset
state4.registers[10] = UInt64(0x7000)  # r9: output offset
state4.registers[11] = UInt64(0)       # r10: source offset
state4.registers[12] = UInt64(10)      # r11: length to copy

# Mark output as writable
state4.memory.access[div(0x7000, 4096) + 1] = :write

state4 = HostCalls.host_call_lookup(state4, context)

preimage_length = state4.registers[8]
println("  Preimage length: $preimage_length")
println("  Expected: 5 ('Hello')")

# Check copied preimage
copied_preimage = state4.memory.data[0x7001:0x7005]
println("  Copied preimage: $(String(copy(copied_preimage)))")

if preimage_length == 5 && copied_preimage == UInt8[0x48, 0x65, 0x6c, 0x6c, 0x6f] && state4.gas == 990
    println("  ✓ TEST PASSED")
else
    println("  ✗ TEST FAILED")
end

println("\n=== All Storage Host Call Tests Complete ===")
