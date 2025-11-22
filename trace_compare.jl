#!/usr/bin/env julia
include("src/pvm/pvm.jl")
using JSON3

function run_test_trace(filename, max_steps=1000)
    data = JSON3.read(read("jam-test-vectors/stf/accumulate/tiny/$filename", String))

    # Find service 1729
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

                        # Create state
                        state = PVM.PVMState()
                        state.instructions = instructions
                        state.opcode_mask = opcode_mask
                        state.jump_table = jump_table
                        state.gas = 1000000000

                        # Setup memory
                        PVM.setup_memory!(state.memory, ro_data, rw_data, stack_pages, stack_bytes, UInt8[])

                        # Set initial PC from entry point 5
                        state.pc = jump_table[6]  # 1-indexed, so index 6 is entry 5

                        # Run with trace
                        trace = []
                        for step in 1:max_steps
                            if state.status != PVM.CONTINUE
                                break
                            end

                            pc = state.pc
                            opcode = instructions[pc + 1]

                            # Record key state every 200 steps and near fault area
                            if step % 200 == 0 || step >= 950
                                push!(trace, (step, pc, opcode, copy(state.registers)))
                            end

                            PVM.execute_instruction!(state)
                        end

                        return (state.status, trace)
                    end
                end
            end
        end
    end
    return (:no_blob, [])
end

# Run passing test
println("=== enqueue_and_unlock_chain-1 (PASS) ===")
status1, trace1 = run_test_trace("enqueue_and_unlock_chain-1.json", 1500)
println("Final status: $status1")
println("Trace points:")
for (step, pc, opcode, regs) in trace1[max(1,end-10):end]
    println("  step=$step pc=0x$(string(pc, base=16, pad=4)) op=$opcode r8=$(regs[9])")
end

println("\n=== enqueue_and_unlock_chain-3 (FAIL) ===")
status2, trace2 = run_test_trace("enqueue_and_unlock_chain-3.json", 1500)
println("Final status: $status2")
println("Trace points:")
for (step, pc, opcode, regs) in trace2[max(1,end-10):end]
    println("  step=$step pc=0x$(string(pc, base=16, pad=4)) op=$opcode r8=$(regs[9])")
end
