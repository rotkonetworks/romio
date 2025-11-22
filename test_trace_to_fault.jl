#!/usr/bin/env julia
# Trace execution up to fault

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

                    start_pc = 0x1af  # entry point 5
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

                    println("=== TRACING FROM STEP 970 TO FAULT ===\n")

                    step = 0
                    while state.status == PVM.CONTINUE && state.gas > 0 && step < 1000
                        step += 1

                        pc = state.pc
                        opcode = state.instructions[pc + 1]
                        skip = PVM.skip_distance(state.opcode_mask, pc + 1)

                        if step >= 970
                            # Show register state at critical steps
                            println("Step $step: PC=0x$(string(pc, base=16, pad=4)) opcode=0x$(string(opcode, base=16, pad=2)) skip=$skip")

                            if step >= 975
                                println("  r6=0x$(string(state.registers[7], base=16, pad=16))")
                                println("  r8=0x$(string(state.registers[9], base=16, pad=16))")
                                println("  r10=0x$(string(state.registers[11], base=16, pad=16))")
                                println("  r11=0x$(string(state.registers[12], base=16, pad=16))")
                            end
                        end

                        PVM.execute_instruction!(state, opcode, skip)

                        # Advance PC if not branching
                        if state.status == PVM.CONTINUE && !PVM.is_branch_instruction(opcode)
                            state.pc = pc + 1 + skip
                        end
                    end

                    println("\n=== EXECUTION STOPPED ===")
                    println("Final step: $step")
                    println("Status: $(state.status)")
                    println("Gas: $(state.gas)")
                    println("PC: 0x$(string(state.pc, base=16))")
                end
                break
            end
        end
        break
    end
end
