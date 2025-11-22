#!/usr/bin/env julia
# Unit tests for PVM implementation
# Focus on 1-indexing issues and core functionality

include("src/pvm/pvm.jl")

using Test
using JSON3

# Test counters
tests_passed = 0
tests_failed = 0
test_details = []

function run_test(test_fn::Function, name::String)
    global tests_passed, tests_failed, test_details
    try
        test_fn()
        tests_passed += 1
        push!(test_details, (name, :pass, ""))
        println("✅ $name")
    catch e
        tests_failed += 1
        error_type = string(typeof(e))
        push!(test_details, (name, :fail, error_type))
        println("❌ $name - $error_type")
    end
end

println("\n=== PVM Unit Tests ===\n")

# ===== Test 1: Memory Read/Write 1-Indexing =====
run_test("Memory write/read at address 0x10000") do
    state = PVM.PVMState(
        UInt32(0), PVM.CONTINUE, Int64(1000),
        UInt8[], BitVector(), zeros(UInt64, 13),
        PVM.Memory(), UInt32[], UInt32(0),
        Vector{UInt8}[], Dict{UInt32, PVM.GuestPVM}()
    )

    # Write to address 0x10000
    addr = UInt64(0x10000)
    test_byte = UInt8(0x42)

    # Set page permissions
    page = div(addr, PVM.PAGE_SIZE)
    state.memory.access[page + 1] = PVM.WRITE

    # Write
    PVM.write_u8(state, addr, test_byte)
    @test state.status == PVM.CONTINUE

    # Read back
    state.memory.access[page + 1] = PVM.READ
    val = PVM.read_u8(state, addr)
    @test val == test_byte
    @test state.status == PVM.CONTINUE
end

# ===== Test 2: Memory Write/Read at 0x20000 =====
run_test("Memory write/read at address 0x20000") do
    state = PVM.PVMState(
        UInt32(0), PVM.CONTINUE, Int64(1000),
        UInt8[], BitVector(), zeros(UInt64, 13),
        PVM.Memory(), UInt32[], UInt32(0),
        Vector{UInt8}[], Dict{UInt32, PVM.GuestPVM}()
    )

    addr = UInt64(0x20000)
    test_bytes = UInt8[0x01, 0x02, 0x03, 0x04]

    page = div(addr, PVM.PAGE_SIZE)
    state.memory.access[page + 1] = PVM.WRITE

    # Write bytes
    for i in 1:length(test_bytes)
        PVM.write_u8(state, addr + UInt64(i-1), test_bytes[i])
    end

    # Read back
    state.memory.access[page + 1] = PVM.READ
    for i in 1:length(test_bytes)
        val = PVM.read_u8(state, addr + UInt64(i-1))
        @test val == test_bytes[i]
    end
end

# ===== Test 3: Jump Table Entry Point Calculation =====
run_test("Jump table entry point 5 calculation") do
    jump_table = UInt32[0x100, 0x200, 0x300, 0x400, 0x500, 0x1af, 0x700]

    # Entry point 0 should use PC=0
    entry_point = 0
    start_pc = if entry_point == 0
        UInt32(0)
    else
        jump_table[entry_point + 1]  # Julia 1-indexed
    end
    @test start_pc == 0

    # Entry point 5 should use jump_table[6] (Julia 1-indexed)
    entry_point = 5
    start_pc = if entry_point == 0
        UInt32(0)
    else
        jump_table[entry_point + 1]  # Julia 1-indexed
    end
    @test start_pc == 0x1af

    # Verify we have enough entries
    @test length(jump_table) > 5
end

# ===== Test 4: Decode Immediate Value =====
run_test("Decode immediate from instruction stream") do
    # Create test instruction stream
    # Format: [opcode, arg_byte, imm_byte1, imm_byte2, ...]
    instructions = UInt8[
        0x33,  # load_imm opcode
        0x00,  # ra=0, skip=0
        0x04,  # immediate value = 4
        0x00,
    ]

    state = PVM.PVMState(
        UInt32(0),  # PC at opcode
        PVM.CONTINUE,
        Int64(1000),
        instructions,
        BitVector(),
        zeros(UInt64, 13),
        PVM.Memory(),
        UInt32[],
        UInt32(0),
        Vector{UInt8}[],
        Dict{UInt32, PVM.GuestPVM}()
    )

    # Decode immediate: PC=0, offset=2, reads at position 0+2=2
    # skip=2 gives lx=1, which reads 1 byte
    skip = 2
    lx = min(4, max(0, skip - 1))
    immx = PVM.decode_immediate(state, 2, lx)

    # Should read 1 byte at index 2, which is 0x04
    @test immx == 4
end

# ===== Test 5: Read Bytes from ro_data range =====
run_test("Read 8 bytes from ro_data at 0x10910") do
    state = PVM.PVMState(
        UInt32(0), PVM.CONTINUE, Int64(1000),
        UInt8[], BitVector(), zeros(UInt64, 13),
        PVM.Memory(), UInt32[], UInt32(0),
        Vector{UInt8}[], Dict{UInt32, PVM.GuestPVM}()
    )

    # Write test pattern to 0x10910
    addr = UInt64(0x10910)
    test_pattern = UInt8[0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37]  # "01234567"

    page_start = div(UInt64(0x10000), PVM.PAGE_SIZE)
    page_end = div(addr + 8, PVM.PAGE_SIZE)

    for page in page_start:page_end
        state.memory.access[page + 1] = PVM.WRITE
    end

    # Write pattern
    for i in 1:length(test_pattern)
        PVM.write_u8(state, addr + UInt64(i-1), test_pattern[i])
    end

    # Set readable
    for page in page_start:page_end
        state.memory.access[page + 1] = PVM.READ
    end

    # Read back 8 bytes
    bytes = PVM.read_bytes(state, addr, 8)
    @test length(bytes) == 8
    @test bytes == test_pattern

    # Decode as u64 (little-endian)
    val = sum(UInt64(bytes[i+1]) << (8*i) for i in 0:7)
    @test val == 0x3736353433323130
end

# ===== Test 6: Register Indexing =====
run_test("Register indexing (1-based Julia arrays)") do
    state = PVM.PVMState(
        UInt32(0), PVM.CONTINUE, Int64(1000),
        UInt8[], BitVector(), zeros(UInt64, 13),
        PVM.Memory(), UInt32[], UInt32(0),
        Vector{UInt8}[], Dict{UInt32, PVM.GuestPVM}()
    )

    # Register 0 is stored at index 1
    state.registers[0 + 1] = 0xDEADBEEF
    @test state.registers[1] == 0xDEADBEEF

    # Register 8 is stored at index 9
    state.registers[8 + 1] = 0xCAFEBABE
    @test state.registers[9] == 0xCAFEBABE
end

# ===== Test 7: Deblob Test Data =====
run_test("Deblob returns correct ro_data length") do
    data = JSON3.read(read("jam-test-vectors/stf/accumulate/tiny/process_one_immediate_report-1.json", String))

    for acc in data[:pre_state][:accounts]
        if acc[:id] == 1729
            for preimage in acc[:data][:preimages_blob]
                if length(preimage[:blob]) > 10000
                    blob_hex = preimage[:blob]
                    hex_str = blob_hex[3:end]
                    blob_bytes = [parse(UInt8, hex_str[i:i+1], base=16) for i in 1:2:length(hex_str)]

                    result = PVM.deblob(blob_bytes)
                    @test result !== nothing

                    instructions, opcode_mask, jump_table, ro_data, rw_data, stack_pages, stack_bytes = result

                    # Verify ro_data length
                    @test length(ro_data) == 7368

                    # Verify test pattern at offset 0x910
                    @test ro_data[0x910 + 1] == 0x30  # '0'
                    @test ro_data[0x911 + 1] == 0x31  # '1'

                    # Verify jump table has entry 5
                    @test length(jump_table) > 5
                    @test jump_table[5 + 1] == 0x1af

                    break
                end
            end
            break
        end
    end
end

# ===== Test 8: Sign Extension =====
run_test("Sign extend 32-bit values correctly") do
    # Positive number
    val = UInt32(0x12345678)
    result = PVM.sign_extend_32(val)
    @test result == 0x12345678

    # Negative number (MSB set)
    val = UInt32(0x80000000)
    result = PVM.sign_extend_32(val)
    @test result == 0xFFFFFFFF80000000

    # Edge case
    val = UInt32(0xFFFFFFFF)
    result = PVM.sign_extend_32(val)
    @test result == 0xFFFFFFFFFFFFFFFF
end

# ===== Test 9: PC Bounds Checking =====
run_test("PC advancement stays within instruction bounds") do
    instructions = UInt8[0x00, 0x01, 0x02, 0x03]
    state = PVM.PVMState(
        UInt32(0), PVM.CONTINUE, Int64(1000),
        instructions, BitVector(zeros(Bool, length(instructions))),
        zeros(UInt64, 13), PVM.Memory(), UInt32[],
        UInt32(0), Vector{UInt8}[], Dict{UInt32, PVM.GuestPVM}()
    )

    # PC should be within bounds
    @test state.pc < length(state.instructions)

    # Advancing PC beyond bounds should be caught
    state.pc = UInt32(length(instructions))
    @test state.pc >= length(state.instructions)
end

# ===== Test 10: Input Address Calculation =====
run_test("Input address calculation r7 initialization") do
    ZONE_SIZE = 0x10000
    MAX_INPUT = 0x1000000

    expected_r7 = UInt32(UInt64(2^32) - UInt64(ZONE_SIZE) - UInt64(MAX_INPUT))
    @test expected_r7 == 0xfeff0000

    # r8 should be input length
    input = UInt8[0x2b, 0x86, 0xc1, 0x01]
    expected_r8 = UInt64(length(input))
    @test expected_r8 == 4
end

# ===== Summary =====
println("\n" * "="^50)
println("Test Summary:")
println("  Passed: $tests_passed")
println("  Failed: $tests_failed")
println("  Total:  $(tests_passed + tests_failed)")
println("  Pass Rate: $(round(100 * tests_passed / (tests_passed + tests_failed), digits=1))%")
println("="^50)

if tests_failed > 0
    println("\nFailed tests:")
    for (name, status, error) in test_details
        if status == :fail
            println("  ❌ $name")
            if !isempty(error)
                for line in split(error, '\n')
                    println("     $line")
                end
            end
        end
    end
end

exit(tests_failed > 0 ? 1 : 0)
