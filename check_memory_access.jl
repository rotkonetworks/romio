#!/usr/bin/env julia
# Check if address 0xfefdff20 is accessible

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

                    # Setup minimal state
                    start_pc = 0x1af
                    input = UInt8[0x2b, 0x86, 0xc1, 0x01]
                    gas = 100000

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

                    PVM.setup_memory!(state, input, ro_data, rw_data, stack_pages, stack_bytes)

                    println("=== MEMORY LAYOUT CHECK ===\n")
                    println("Initial registers:")
                    println("  r0  = 0x$(string(registers[1], base=16, pad=8)) = $(registers[1])")
                    println("  r1/SP = 0x$(string(registers[2], base=16, pad=8)) = $(registers[2])")
                    println("  r7  = 0x$(string(registers[8], base=16, pad=8)) = $(registers[8])")
                    println()

                    # Check address 0xfefdff20
                    test_addr = UInt64(0xfefdff20)
                    println("Testing address: 0x$(string(test_addr, base=16))")
                    println("  Page: 0x$(string(div(UInt32(test_addr % 2^32), PVM.PAGE_SIZE), base=16))")

                    # Check accessibility
                    println("\nAttempting to read 8 bytes from 0x$(string(test_addr, base=16))...")
                    bytes = PVM.read_bytes(state, test_addr, 8)
                    println("  Read $(length(bytes)) bytes")
                    if length(bytes) == 8
                        val = reinterpret(UInt64, bytes)[1]
                        println("  Value: 0x$(string(val, base=16, pad=16))")
                    else
                        println("  READ FAILED!")
                        println("  State status: $(state.status)")
                    end

                    # Check memory access map
                    println("\n=== MEMORY ACCESS MAP ===")
                    page_start = div(UInt32(0xfefdf000 % 2^32), PVM.PAGE_SIZE)
                    page_end = div(UInt32(0xfefe0000 % 2^32), PVM.PAGE_SIZE)
                    for page in page_start:page_end
                        page_idx = page + 1
                        if page_idx <= length(state.memory.access)
                            access = state.memory.access[page_idx]
                            addr_start = page * PVM.PAGE_SIZE
                            addr_end = (page + 1) * PVM.PAGE_SIZE - 1
                            access_str = access == PVM.READ ? "R--" : (access == PVM.WRITE ? "RW-" : "---")
                            println("  Page 0x$(string(page, base=16, pad=4)): [0x$(string(addr_start, base=16, pad=8))-0x$(string(addr_end, base=16, pad=8))] $access_str")
                        end
                    end
                end
                break
            end
        end
        break
    end
end
