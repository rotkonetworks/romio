# Trace service 1729 execution from entry to step 48 (LOG call)
# Goal: identify what check fails causing error path

push!(LOAD_PATH, joinpath(@__DIR__, "src"))

include("src/stf/accumulate.jl")
include("src/pvm/pvm.jl")
using .PVM

# Load a failing test with service 1729
test_path = "jam-test-vectors/stf/accumulate/full/process_one_immediate_report-1.json"
tv = load_test_vector(test_path)

# Get service 1729
service_id = ServiceId(1729)
account = tv.pre_state.accounts[service_id]

println("=== Service 1729 Early Execution Trace ===")
println("Code hash: $(bytes2hex(account.code_hash))")
println("Code size: $(length(account.preimages[account.code_hash])) bytes")

# Get the work result for service 1729
reports_input = get(tv.input, :reports, [])
report = parse_work_report(reports_input[1])
work_result = report.results[1]  # Should be service 1729

println("\nWork result:")
println("  service_id: $(work_result.service_id)")
println("  accumulate_gas: $(work_result.accumulate_gas)")
println("  result length: $(length(work_result.result.ok)) bytes")

# Build the input buffer (same as execute_accumulate)
input_timeslot = UInt32(tv.input[:slot])
input_service_id = UInt32(work_result.service_id)
input_count = UInt32(1)

input = UInt8[]
append!(input, reinterpret(UInt8, [input_timeslot]))
append!(input, reinterpret(UInt8, [input_service_id]))
append!(input, reinterpret(UInt8, [input_count]))

println("\nInput buffer ($(length(input)) bytes):")
println("  timeslot: $input_timeslot")
println("  service_id: $input_service_id")
println("  count: $input_count")
println("  hex: $(bytes2hex(input))")

# Build operandtuple
operandtuple_encoded = UInt8[]
append!(operandtuple_encoded, report.package_hash)
append!(operandtuple_encoded, report.seg_root)
append!(operandtuple_encoded, report.authorizer_hash)
append!(operandtuple_encoded, work_result.payload_hash)
append!(operandtuple_encoded, reinterpret(UInt8, [UInt64(work_result.accumulate_gas)]))
auth_trace = UInt8[]
append!(operandtuple_encoded, encode_jam_blob(auth_trace))
append!(operandtuple_encoded, encode_jam_blob(work_result.result.ok))

println("\nOperandtuple ($(length(operandtuple_encoded)) bytes)")

# Create context
implications = ImplicationsContext(
    work_result.service_id,
    account,
    tv.pre_state.accounts,
    tv.pre_state.privileges,
    input_timeslot
)

work_package = Dict{Symbol, Any}(
    :results => [operandtuple_encoded]
)
context = HostCallContext(implications, tv.pre_state.entropy, nothing, work_package, nothing)

# Get service code
service_code = account.preimages[work_result.code_hash]

# Now manually trace execution
println("\n=== Execution Trace (first 60 steps) ===")

# Initialize PVM state manually to trace
ZONE_SIZE = UInt32(65536)
PAGE_SIZE = UInt32(4096)
MAX_INPUT = UInt32(16777216)

# Parse program blob
parsed = PVM.parse_program_blob(service_code)
if parsed === nothing
    error("Failed to parse program blob")
end

code, ro_data, rw_data, jump_table, stack_pages = parsed

println("\nProgram info:")
println("  Code: $(length(code)) bytes")
println("  RO data: $(length(ro_data)) bytes")
println("  RW data: $(length(rw_data)) bytes")
println("  Jump table: $(length(jump_table)) entries")
println("  Stack pages: $stack_pages")

# Initialize registers
registers = zeros(UInt64, 13)
registers[1] = UInt64(0xFFFF0000)  # r0 = return address
registers[2] = UInt64(2^32 - 2*ZONE_SIZE - MAX_INPUT)  # r1/SP
registers[8] = UInt64(2^32 - ZONE_SIZE - MAX_INPUT)  # r7 (input address)
registers[9] = UInt64(length(input))  # r8 = input length

println("\nInitial registers:")
for i in 0:12
    if registers[i+1] != 0
        println("  r$i = 0x$(string(registers[i+1], base=16))")
    end
end

# Initialize memory
memory = zeros(UInt8, 2^32)

# Load code at 0x10000
code_start = UInt32(ZONE_SIZE)
for i in 1:length(code)
    memory[code_start + i] = code[i]
end

# Load ro_data after code
ro_data_start = code_start + UInt32(length(code))
for i in 1:length(ro_data)
    memory[ro_data_start + i] = ro_data[i]
end

# Load rw_data at 0x20000
rw_data_start = UInt32(2 * ZONE_SIZE)
for i in 1:length(rw_data)
    memory[rw_data_start + i] = rw_data[i]
end

# Load input at argument pointer
arg_ptr = UInt32(2^32 - ZONE_SIZE - MAX_INPUT)
for i in 1:length(input)
    memory[arg_ptr + i] = input[i]
end

# Get entry point (5 for accumulate)
entry_point = 5
if entry_point >= length(jump_table)
    error("Entry point $entry_point out of range")
end
pc = jump_table[entry_point + 1]

println("\nEntry point: $entry_point -> PC = 0x$(string(pc, base=16))")

# Trace execution
step = 0
max_steps = 60

while step < max_steps
    step += 1

    # Decode instruction at PC
    if pc >= length(code)
        println("Step $step: PC out of bounds (0x$(string(pc, base=16)))")
        break
    end

    opcode = code[pc + 1]

    # Get instruction info
    instr_name, instr_len = PVM.get_instruction_info(opcode, code, pc)

    # Print state
    print("Step $step: PC=0x$(string(pc, base=16, pad=4)) ")
    print("op=0x$(string(opcode, base=16, pad=2)) ")
    print("[$instr_name] ")

    # Print relevant registers
    r7 = registers[8]
    r8 = registers[9]
    r10 = registers[11]

    # Show key registers for this instruction
    if instr_name in ["load_imm", "add_imm", "store_u32", "load_u32", "branch_eq_imm", "branch_ne_imm"]
        # These often use specific registers
        print("r7=0x$(string(r7, base=16)) r8=0x$(string(r8, base=16)) r10=0x$(string(r10, base=16))")
    end

    println()

    # Check for ECALLI (host call)
    if opcode == 0x4e
        # Get host call ID from next byte
        if pc + 1 < length(code)
            host_id = code[pc + 2]
            println("  -> HOST CALL: id=$host_id")

            if host_id == 20  # LOG
                # r7 = target (where to write result)
                # r8 = source ptr
                # r9 = length
                r7_val = registers[8]
                r8_val = registers[9]
                r9_val = registers[10]
                println("  -> LOG: target=0x$(string(r7_val, base=16)) src=0x$(string(r8_val, base=16)) len=$r9_val")
            end
        end
    end

    # Single step execution
    old_pc = pc
    status = PVM.single_step!(registers, memory, code, jump_table, pc)

    if status == :halt
        println("  -> HALT with r0 = 0x$(string(registers[1], base=16))")
        break
    elseif status == :panic
        println("  -> PANIC")
        break
    elseif status == :host_call
        # Handle host call
        host_id = code[pc + 2]
        println("  -> Executing host call $host_id...")

        # We need to actually execute the host call through context
        # For now, just note it
        if host_id == 20  # LOG
            println("  -> LOG call detected")
        end

        # Skip past ecalli
        pc += 2
    elseif status isa UInt32
        pc = status
    else
        # Normal instruction, PC advanced
        pc = old_pc + instr_len
    end
end

println("\n=== Final Register State ===")
for i in 0:12
    println("  r$i = 0x$(string(registers[i+1], base=16))")
end
