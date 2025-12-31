# Benchmark: Native BF vs BLC-based BF interpreter
#
# Compares execution time and gas usage for:
# - 0xBF prefix: Native C brainfuck interpreter
# - 0xB0 prefix: John Tromp's BLC-encoded BF interpreter

const SRC_DIR = joinpath(dirname(@__DIR__), "src")

include(joinpath(SRC_DIR, "pvm", "pvm.jl"))
include(joinpath(SRC_DIR, "pvm", "polkavm_blob.jl"))

using .PVM
using .PolkaVMBlob

# Simple BF program: output "Hi" (no loops, minimal)
# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ (72x +) = 'H'
# .
# +++++++++++++++++++++++++++ (29x +) to get to 'i' (101 = 72+29)
# actually simpler: just set cell to 'H' and 'i' directly
const BF_HI = collect(UInt8, "+++++++++[>++++++++<-]>." *  # 72 = 8*9 = 'H'
                              "+++++++++++++++++++++++++++++.") # +29 = 'i'

# Even simpler: just output 'A' (65)
# ++++++++[>++++++++<-]>+.  = 64 + 1 = 65 = 'A'
const BF_A = collect(UInt8, "++++++++[>++++++++<-]>+.")

function load_blc_vm()
    blc_path = "/home/alice/rotko/blc-service/services/output/blc-vm.corevm"
    blc_data = read(blc_path)

    pvm_magic = findfirst(b"PVM\0", blc_data)
    pvm_blob = blc_data[pvm_magic[1]:end]
    parsed = PolkaVMBlob.parse_polkavm_blob(pvm_blob)

    return parsed
end

function setup_pvm(parsed)
    VM_MAX_PAGE_SIZE = UInt32(0x10000)
    align_64k(x) = (x + VM_MAX_PAGE_SIZE - 1) & ~(VM_MAX_PAGE_SIZE - 1)
    ro_data_address_space = align_64k(parsed.ro_data_size)
    RO_BASE = UInt32(0x10000)
    RW_BASE = UInt32(RO_BASE + ro_data_address_space + VM_MAX_PAGE_SIZE)
    STACK_HIGH = UInt32(0xFFFF0000 - VM_MAX_PAGE_SIZE)
    STACK_LOW = UInt32(STACK_HIGH - parsed.stack_size)
    HEAP_BASE = UInt32(RW_BASE + parsed.rw_data_size)

    rw_data_full = zeros(UInt8, max(1, parsed.rw_data_size))
    if length(parsed.rw_data) > 0
        copyto!(rw_data_full, 1, parsed.rw_data, 1, min(length(parsed.rw_data), parsed.rw_data_size))
    end

    memory = PVM.Memory()
    PVM.init_memory_regions!(memory,
        RO_BASE, UInt32(length(parsed.ro_data)), parsed.ro_data,
        RW_BASE, UInt32(length(rw_data_full)), rw_data_full,
        STACK_LOW, STACK_HIGH,
        HEAP_BASE, STACK_LOW)

    opcode_mask = PolkaVMBlob.get_opcode_mask(parsed)
    skip_distances = PVM.precompute_skip_distances(opcode_mask)

    # Find jb_refine
    entry_pc = 0
    for exp in parsed.exports
        if exp.name == "jb_refine"
            entry_pc = exp.pc
            break
        end
    end

    regs = zeros(UInt64, 13)
    regs[1] = UInt64(0xFFFF0000)
    regs[2] = UInt64(STACK_HIGH)

    initial_gas = Int64(100_000_000)
    state = PVM.PVMState(
        UInt32(entry_pc), PVM.CONTINUE, initial_gas,
        parsed.code, opcode_mask, skip_distances, regs, memory, parsed.jump_table,
        UInt32(0), Vector{Vector{UInt8}}(), Dict{UInt32, PVM.GuestPVM}()
    )

    return state, HEAP_BASE
end

function run_bf_test(parsed, mode::Symbol)
    # Hardcode the BF program to avoid closure issues
    bf_program = collect(UInt8, "++++++++[>++++++++<-]>+.")
    println("  run_bf_test: bf_program length=$(length(bf_program))")
    state, heap_base = setup_pvm(parsed)

    # Prepare payload based on mode
    if mode == :native
        # 0xBF prefix for native
        payload = UInt8[0xBF]
        append!(payload, bf_program)
    elseif mode == :blc
        # 0xB0 prefix for BLC-based
        payload = UInt8[0xB0]
        append!(payload, bf_program)
    else
        error("Unknown mode: $mode")
    end

    println("  Created payload: $(length(payload)) bytes, first 8: $(payload[1:min(8, length(payload))])")

    # Write payload to heap
    for (i, b) in enumerate(payload)
        PVM.sparse_write!(state.memory.sparse, heap_base + UInt32(i-1), b)
    end

    start_gas = state.gas
    max_steps = 10_000_000
    steps = 0
    output_data = UInt8[]

    while steps < max_steps && state.status == PVM.CONTINUE && state.gas > 0
        PVM.step!(state)
        steps += 1

        if state.status == PVM.HALT
            break
        elseif state.status == PVM.HOST
            call_id = Int(state.host_call_id)

            if call_id == 1  # host_fetch - return payload
                # blc-vm.c fetch() uses: a0=buf, a1=0, a2=len, a3=discriminator(13)
                ptr = UInt32(state.registers[8])      # a0 = buffer address
                offset = Int(state.registers[9])      # a1 = offset (always 0)
                max_len = Int(state.registers[10])    # a2 = buffer length
                discriminator = Int(state.registers[11])  # a3 = discriminator

                # Debug: show all register values and payload
                println("  host_fetch: a0=$(state.registers[8]) a1=$(state.registers[9]) a2=$(state.registers[10]) a3=$(state.registers[11])")
                println("  host_fetch: payload length=$(length(payload)), max_len=$(max_len)")

                # Write payload to ptr - max_len should be 256 from the C code
                write_len = min(length(payload), max_len)
                for i in 1:write_len
                    PVM.sparse_write!(state.memory.sparse, ptr + UInt32(i-1), payload[i])
                end
                state.registers[8] = UInt64(write_len)
                println("  host_fetch: wrote $(write_len) bytes to 0x$(string(ptr, base=16)), payload=$(payload[1:min(8, length(payload))])")

                skip = PVM.skip_distance(state.opcode_mask, Int(state.pc) + 1)
                state.pc = state.pc + 1 + skip
                state.status = PVM.CONTINUE

            elseif call_id == 7  # host_export - capture output
                ptr = UInt32(state.registers[8])
                len = Int(state.registers[9])

                println("  host_export: ptr=0x$(string(ptr, base=16)), len=$len")
                for i in 1:len
                    b = PVM.sparse_read(state.memory.sparse, ptr + UInt32(i-1))
                    push!(output_data, b)
                end
                println("  host_export: captured bytes: $output_data")

                skip = PVM.skip_distance(state.opcode_mask, Int(state.pc) + 1)
                state.pc = state.pc + 1 + skip
                state.status = PVM.CONTINUE
            else
                # Other host calls - just skip
                skip = PVM.skip_distance(state.opcode_mask, Int(state.pc) + 1)
                state.pc = state.pc + 1 + skip
                state.status = PVM.CONTINUE
            end
        elseif state.status == PVM.PANIC || state.status == PVM.OOG
            break
        end
    end

    gas_used = start_gas - state.gas

    return (
        steps = steps,
        gas_used = gas_used,
        status = state.status,
        output = output_data
    )
end

function main()
    println("Loading blc-vm...")
    parsed = load_blc_vm()
    println("  Code size: $(length(parsed.code)) bytes")

    println("\n=== Benchmark: Native BF (0xBF) vs BLC-based BF (0xB0) ===\n")

    # Test program: output 'A'
    bf_program = copy(BF_A)  # Make a copy to avoid any const issues
    println("BF program: $(String(bf_program))")
    println("Expected output: 'A' (0x41)\n")

    println("Running native BF (0xBF prefix)...")
    result_native = run_bf_test(parsed, :native)
    println("  Steps: $(result_native.steps)")
    println("  Gas used: $(result_native.gas_used)")
    println("  Status: $(result_native.status)")
    println("  Output: $(result_native.output) = '$(String(copy(result_native.output)))'")

    println("\nRunning BLC-based BF (0xB0 prefix)...")
    result_blc = run_bf_test(parsed, :blc)
    println("  Steps: $(result_blc.steps)")
    println("  Gas used: $(result_blc.gas_used)")
    println("  Status: $(result_blc.status)")
    println("  Output: $(result_blc.output)")

    if result_native.steps > 0 && result_blc.steps > 0
        println("\n=== Comparison ===")
        println("Steps ratio: $(result_blc.steps / result_native.steps)x slower")
        println("Gas ratio: $(result_blc.gas_used / result_native.gas_used)x more gas")
    end
end

main()
