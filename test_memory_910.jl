#!/usr/bin/env julia
# Verify what's actually in memory at 0x10910

using JSON3
include("src/pvm/pvm.jl")

data = JSON3.read(read("jam-test-vectors/stf/accumulate/tiny/process_one_immediate_report-1.json", String))

for acc in data[:pre_state][:accounts]
    if acc[:id] == 1729
        for preimage in acc[:data][:preimages_blob]
            if length(preimage[:blob]) > 10000
                blob_hex = preimage[:blob]
                hex_str = blob_hex[3:end]
                blob_bytes = [parse(UInt8, hex_str[i:i+1], base=16) for i in 1:2:length(hex_str)]

                result = PVM.deblob(blob_bytes)
                if result !== nothing
                    instructions, opcode_mask, jump_table, ro_data, rw_data, stack_pages, stack_bytes = result

                    println("=== RO_DATA CONTENT CHECK ===\n")

                    # Check what's in ro_data array at offset 0x910
                    println("ro_data length: $(length(ro_data))")
                    println("ro_data[0x910+1:0x910+8] (Julia 1-indexed):")
                    bytes = ro_data[0x910+1:0x910+8]
                    for (i, b) in enumerate(bytes)
                        println("  ro_data[0x$(string(0x910 + i, base=16))] = 0x$(string(b, base=16, pad=2)) ('$(Char(b))')")
                    end

                    # Now create a PVM state and setup memory
                    start_pc = 0x1af  # entry point 5
                    input = UInt8[0x2b, 0x86, 0xc1, 0x01]  # encode(43, 1729, 1)
                    gas = 100000

                    # Initialize PVM state
                    registers = zeros(UInt64, 13)
                    registers[1] = UInt64(2^32 - 2^16)
                    registers[2] = UInt64(2^32 - 2*PVM.ZONE_SIZE - PVM.MAX_INPUT)
                    registers[8] = UInt64(2^32 - PVM.ZONE_SIZE - PVM.MAX_INPUT)
                    registers[9] = UInt64(length(input))

                    state = PVM.PVMState(
                        start_pc,
                        PVM.CONTINUE,
                        gas,
                        instructions,
                        opcode_mask,
                        registers,
                        PVM.Memory(),
                        jump_table,
                        UInt32(0),
                        [],
                        Dict{UInt32, PVM.GuestPVM}()
                    )

                    # Setup memory
                    PVM.setup_memory!(state, input, ro_data, rw_data, stack_pages, stack_bytes)

                    # Now read what's actually at memory address 0x10910
                    println("\n=== MEMORY AT ADDRESS 0x10910 ===\n")
                    for i in 0:7
                        addr = UInt64(0x10910 + i)
                        # Read using memory indexing
                        byte_from_mem = state.memory.data[addr + 1]  # Julia 1-indexed
                        println("  memory[0x$(string(addr, base=16))] = 0x$(string(byte_from_mem, base=16, pad=2)) ('$(Char(byte_from_mem))')")
                    end

                    # Compare
                    println("\n=== COMPARISON ===")
                    println("Expected at 0x10910: '01234567'")
                    println("Actual   at 0x10910: $(String([Char(state.memory.data[0x10910 + i + 1]) for i in 0:7]))")
                end
                break
            end
        end
        break
    end
end
