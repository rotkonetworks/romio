#!/usr/bin/env julia
include("src/pvm/pvm.jl")
using JSON3

data = JSON3.read(read("jam-test-vectors/stf/accumulate/tiny/enqueue_and_unlock_chain-3.json", String))

for acc in data[:pre_state][:accounts]
    if acc[:id] == 1729
        for preimage in acc[:data][:preimages_blob]
            if length(preimage[:blob]) > 10000
                blob_hex = preimage[:blob]
                hex_str = blob_hex[3:end]
                blob = [parse(UInt8, hex_str[i:i+1], base=16) for i in 1:2:length(hex_str)]

                result = PVM.deblob(blob)
                if result !== nothing
                    instructions, opcode_mask, jump_table, ro_data, rw_data, stack_pages, stack_bytes = result

                    println("ro_data length: $(length(ro_data))")
                    println("ro_data range: 0x10000 to 0x$(string(0x10000 + length(ro_data) - 1, base=16))")
                    println()

                    # Create and run PVM
                    state = PVM.PVMState(
                        UInt32(0),
                        PVM.CONTINUE,
                        Int64(10000000),
                        instructions,
                        opcode_mask,
                        zeros(UInt64, 13),
                        PVM.Memory(),
                        jump_table,
                        UInt32(0),
                        Vector{UInt8}[],
                        Dict{UInt32, PVM.GuestPVM}()
                    )

                    # Use proper setup_memory that takes input
                    input = UInt8[0x2e, 0x86, 0xc1, 0x01]  # encode(46, 1729, 1)
                    PVM.setup_memory!(state, input, ro_data, rw_data, stack_pages, stack_bytes)

                    # Set entry point
                    state.pc = jump_table[6]

                    println("Starting execution from PC=0x$(string(state.pc, base=16))")
                    println()

                    # Run to step 969 and beyond
                    for step in 1:1000
                        if state.status != PVM.CONTINUE
                            break
                        end

                        pc = state.pc
                        opcode = instructions[pc + 1]

                        # Trace steps 960-990
                        if step >= 960 && step <= 990
                            println("Step $step: PC=0x$(string(pc, base=16)) op=$opcode")
                            println("  Registers: r1=0x$(string(state.registers[2], base=16)) r8=0x$(string(state.registers[9], base=16)) r12=0x$(string(state.registers[13], base=16))")
                        end

                        PVM.step!(state)

                        if state.status != PVM.CONTINUE && step >= 960
                            println("\nExecution ended: status=$(state.status) at step $step")
                            println("Final PC=0x$(string(state.pc, base=16))")
                            println("Final r8=0x$(string(state.registers[9], base=16))")

                            # Check if fault address is valid
                            fault_addr = state.registers[9]
                            page = div(fault_addr, 4096)
                            println("\nFault address 0x$(string(fault_addr, base=16)): page=$page")
                            if page < length(state.memory.access)
                                println("  Page access: $(state.memory.access[page + 1])")
                            else
                                println("  Page out of range!")
                            end
                            break
                        end
                    end
                end
                break
            end
        end
        break
    end
end
