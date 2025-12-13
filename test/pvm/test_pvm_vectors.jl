# PVM Instruction Test Runner
# Tests PVM implementation against official graypaper test vectors

using JSON3

# Include PVM module
include("../../src/pvm/pvm.jl")
using .PVM

# Read graypaper-style varint from data starting at offset (1-indexed)
# Returns (value, next_offset)
function read_graypaper_varint(data::Vector{UInt8}, offset::Int)
    if offset > length(data)
        return (0, offset)
    end

    first_byte = data[offset]

    # Case 1: x = 0
    if first_byte == 0
        return (0, offset + 1)
    end

    # Case 2: x < 128 (l=0, direct encoding)
    if first_byte < 128
        return (Int(first_byte), offset + 1)
    end

    # Determine l from first byte
    l = if first_byte < 192
        1
    elseif first_byte < 224
        2
    elseif first_byte < 240
        3
    elseif first_byte < 248
        4
    elseif first_byte < 252
        5
    elseif first_byte < 254
        6
    elseif first_byte < 255
        7
    else  # first_byte == 255
        8
    end

    if offset + l > length(data)
        return (0, offset)
    end

    # Extract header value
    header_offset = UInt64(256 - (1 << (8 - l)))
    header_val = UInt64(first_byte) - header_offset

    # Read next l bytes as little-endian
    remainder = UInt64(0)
    for i in 0:l-1
        remainder |= UInt64(data[offset + 1 + i]) << (8 * i)
    end

    # Reconstruct: header_val * 2^(8l) + remainder
    result = (header_val << (8 * l)) + remainder

    return (Int(result), offset + 1 + l)
end

# Parse the inner code blob format from test vectors
# Format: encode(len(j)) ++ encode[1](z) ++ encode(len(c)) ++ encode[z](j) ++ code ++ mask
function parse_inner_code(program::Vector{UInt8})
    if isempty(program)
        return nothing
    end

    offset = 1

    # Read varint for jump table length
    jump_table_len, offset = read_graypaper_varint(program, offset)

    # Read 1 byte for mask padding (z)
    if offset > length(program)
        return nothing
    end
    mask_padding = Int(program[offset])
    offset += 1

    # Read varint for code length
    if offset > length(program)
        return nothing
    end
    code_len, offset = read_graypaper_varint(program, offset)

    # Read jump table entries (z bytes each, where z is the mask_padding value)
    entry_size = mask_padding  # z determines the size of each jump table entry
    if entry_size == 0
        entry_size = 4  # Default to 4 bytes if z is 0
    end
    jump_table = UInt32[]
    for _ in 1:jump_table_len
        if offset + entry_size - 1 > length(program)
            return nothing
        end
        entry = UInt64(0)
        for i in 0:entry_size-1
            entry |= UInt64(program[offset + i]) << (8 * i)
        end
        push!(jump_table, UInt32(entry))
        offset += entry_size
    end

    # Read code bytes
    if offset + code_len - 1 > length(program)
        return nothing
    end
    instructions = program[offset:offset+code_len-1]
    offset += code_len

    # Read mask bytes
    # Mask covers code_len bits, one bit per code byte
    mask_byte_count = div(code_len + 7, 8)
    available_bytes = min(mask_byte_count, length(program) - offset + 1)
    if available_bytes <= 0
        # No mask bytes available - use zeros (no opcodes marked)
        mask_bytes = fill(UInt8(0x00), mask_byte_count)
    elseif available_bytes < mask_byte_count
        # Read what's available and pad with zeros
        mask_bytes = zeros(UInt8, mask_byte_count)
        mask_bytes[1:available_bytes] = program[offset:offset+available_bytes-1]
    else
        mask_bytes = program[offset:offset+mask_byte_count-1]
    end

    # Build opcode mask - bits are packed LSB first in each byte
    # Note: mask_padding (z) is only used for jump table entry size, NOT for mask bit offset
    opcode_mask = BitVector(undef, code_len)
    for i in 0:code_len-1
        byte_idx = div(i, 8) + 1
        bit_idx = i % 8
        if byte_idx <= length(mask_bytes)
            opcode_mask[i+1] = (mask_bytes[byte_idx] & (1 << bit_idx)) != 0
        else
            opcode_mask[i+1] = false
        end
    end

    return (instructions, opcode_mask, jump_table)
end

# Create PVM state from test vector
function create_test_state(
    program::Vector{UInt8},
    initial_regs::Vector{UInt64},
    initial_pc::UInt32,
    initial_gas::Int64,
    page_map::Vector{Dict{String,Any}},
    initial_memory::Vector{Dict{String,Any}}
)
    # Parse inner code
    result = parse_inner_code(program)
    if result === nothing
        return nothing
    end

    instructions, opcode_mask, jump_table = result

    # Create memory
    memory = PVM.Memory()

    # Set up page access permissions
    for page_entry in page_map
        addr = UInt32(page_entry["address"])
        len = UInt32(page_entry["length"])
        is_writable = page_entry["is-writable"]

        # Mark pages as accessible
        start_page = div(addr, PVM.PAGE_SIZE)
        end_page = div(addr + len - 1, PVM.PAGE_SIZE)

        for page in start_page:end_page
            page_idx = page + 1
            memory.access[page_idx] = is_writable ? PVM.WRITE : PVM.READ
        end
    end

    # Initialize memory with values
    for mem_entry in initial_memory
        addr = UInt32(mem_entry["address"])
        contents = UInt8.(collect(mem_entry["contents"]))
        for (i, byte) in enumerate(contents)
            memory.data[addr + i] = byte
        end
    end

    # Create state
    state = PVM.PVMState(
        initial_pc,           # pc
        PVM.CONTINUE,         # status
        initial_gas,          # gas
        instructions,         # instructions
        opcode_mask,          # opcode_mask
        copy(initial_regs),   # registers (copy to avoid mutation)
        memory,               # memory
        jump_table,           # jump_table
        UInt32(0),            # host_call_id
        Vector{Vector{UInt8}}(), # exports
        Dict{UInt32, PVM.GuestPVM}()  # machines
    )

    return state
end

# Parse array of integers from JSON string directly to avoid Float64 precision loss
function parse_uint64_array(json_str::String, field_name::String)
    # Find the field and extract the array
    pattern = Regex("\"$(field_name)\"\\s*:\\s*\\[(\\s*-?\\d+(?:\\s*,\\s*-?\\d+)*\\s*)\\]")
    m = match(pattern, json_str)
    if m === nothing
        return UInt64[]
    end

    nums_str = m.captures[1]
    result = UInt64[]
    for num_match in eachmatch(r"-?\d+", nums_str)
        val = parse(BigInt, num_match.match)
        if val < 0
            # Two's complement for negative values
            val = BigInt(2)^64 + val
        end
        push!(result, UInt64(val % (BigInt(2)^64)))
    end
    return result
end

# Safely convert to UInt64 handling large values
function safe_uint64(val)
    if val isa Float64
        # Handle large values parsed as floats
        # Use BigInt intermediate to avoid precision loss
        bigval = round(BigInt, val)
        # Clamp to UInt64 range
        if bigval < 0
            return UInt64(0)
        elseif bigval > typemax(UInt64)
            # Wrap around for overflow
            return UInt64(bigval % (BigInt(2)^64))
        end
        return UInt64(bigval)
    elseif val isa Integer
        if val < 0
            # Handle negative values as two's complement
            return reinterpret(UInt64, Int64(val))
        end
        return UInt64(val)
    end
    return UInt64(val)
end

# Run test and compare results
function run_test(filepath::String; verbose::Bool=false)
    # Load test vector
    json_str = read(filepath, String)
    tv = JSON3.read(json_str)

    test_name = String(tv["name"])

    if verbose
        println("  Running: $test_name")
    end

    # Extract test data - use direct parsing for register arrays to avoid Float64 precision loss
    program = UInt8.(collect(tv["program"]))
    initial_regs = parse_uint64_array(json_str, "initial-regs")
    initial_pc = UInt32(tv["initial-pc"])
    initial_gas = Int64(tv["initial-gas"])
    page_map = [Dict{String,Any}(string(k) => v for (k,v) in pm) for pm in tv["initial-page-map"]]
    initial_memory = [Dict{String,Any}(string(k) => v for (k,v) in mm) for mm in tv["initial-memory"]]

    expected_status = String(tv["expected-status"])
    expected_regs = parse_uint64_array(json_str, "expected-regs")
    expected_pc = UInt32(tv["expected-pc"])
    expected_gas = Int64(tv["expected-gas"])
    expected_memory = [Dict{String,Any}(string(k) => v for (k,v) in mm) for mm in tv["expected-memory"]]

    # Create state
    state = create_test_state(program, initial_regs, initial_pc, initial_gas, page_map, initial_memory)
    if state === nothing
        return (false, test_name, "Failed to parse program")
    end

    # Run until completion
    max_steps = 100000
    steps = 0
    while state.status == PVM.CONTINUE && steps < max_steps
        PVM.step!(state)
        steps += 1
    end

    # Check status
    actual_status = if state.status == PVM.HALT
        "halt"
    elseif state.status == PVM.PANIC
        "panic"
    elseif state.status == PVM.FAULT
        "page-fault"
    elseif state.status == PVM.OOG
        "panic"  # OOG maps to panic in test vectors
    else
        "unknown"
    end

    # Collect errors
    errors = String[]

    if actual_status != expected_status
        push!(errors, "Status: expected $expected_status, got $actual_status")
    end

    if state.pc != expected_pc
        push!(errors, "PC: expected 0x$(string(expected_pc, base=16)), got 0x$(string(state.pc, base=16))")
    end

    if state.gas != expected_gas
        push!(errors, "Gas: expected $expected_gas, got $(state.gas)")
    end

    # Check registers
    for i in 1:13
        if state.registers[i] != expected_regs[i]
            push!(errors, "r$(i-1): expected 0x$(string(expected_regs[i], base=16)), got 0x$(string(state.registers[i], base=16))")
        end
    end

    # Check memory
    for mem_entry in expected_memory
        addr = UInt32(mem_entry["address"])
        expected_contents = UInt8.(collect(mem_entry["contents"]))
        for (i, expected_byte) in enumerate(expected_contents)
            actual_byte = state.memory.data[addr + i]
            if actual_byte != expected_byte
                push!(errors, "Memory[0x$(string(addr+i-1, base=16))]: expected 0x$(string(expected_byte, base=16, pad=2)), got 0x$(string(actual_byte, base=16, pad=2))")
            end
        end
    end

    if isempty(errors)
        return (true, test_name, "")
    else
        return (false, test_name, join(errors, "; "))
    end
end

# Main test runner
function run_all_tests(vectors_dir::String; verbose::Bool=false, name_filter::Union{String,Nothing}=nothing)
    all_vectors = sort(Base.filter(f -> endswith(f, ".json"), readdir(vectors_dir)))

    if name_filter !== nothing
        all_vectors = Base.filter(f -> occursin(name_filter, f), all_vectors)
    end

    println("Found $(length(all_vectors)) test vectors")
    println()

    passed = 0
    failed = 0
    failed_tests = String[]

    for test_file in all_vectors
        filepath = joinpath(vectors_dir, test_file)

        try
            success, name, error_msg = run_test(filepath; verbose=verbose)
            if success
                passed += 1
                if verbose
                    println("    ✓ PASS")
                end
            else
                failed += 1
                push!(failed_tests, "$name: $error_msg")
                if verbose
                    println("    ✗ FAIL: $error_msg")
                end
            end
        catch e
            failed += 1
            push!(failed_tests, "$test_file: Exception - $e")
            if verbose
                println("    ✗ EXCEPTION: $e")
            end
        end
    end

    # Summary
    println("\n" * "="^60)
    println("=== PVM Test Summary ===")
    println("Passed: $passed")
    println("Failed: $failed")
    println("Total:  $(passed + failed)")
    println("Pass rate: $(round(100 * passed / (passed + failed), digits=1))%")

    if length(failed_tests) > 0 && length(failed_tests) <= 20
        println("\nFailed tests:")
        for t in failed_tests
            println("  - $t")
        end
    elseif length(failed_tests) > 20
        println("\nFirst 20 failed tests:")
        for t in failed_tests[1:20]
            println("  - $t")
        end
        println("  ... and $(length(failed_tests) - 20) more")
    end

    return (passed, failed)
end

# Run tests
if abspath(PROGRAM_FILE) == @__FILE__
    vectors_dir = joinpath(@__DIR__, "../../pvm-test-vectors/pvm/programs")
    run_all_tests(vectors_dir; verbose=true)
end
