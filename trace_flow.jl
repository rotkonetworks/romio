#!/usr/bin/env julia

# Patch PVM to trace execution flow
include("src/pvm/pvm.jl")

# Monkey-patch the step function to trace
original_step = PVM.step!

# Add tracing to dispatch_host_call
function trace_execution()
    # Run the test with tracing
    include("src/stf/accumulate.jl")
    
    test_file = "jam-test-vectors/stf/accumulate/tiny/process_one_immediate_report-1.json"
    tv = load_test_vector(test_file)
    
    input_slot = UInt32(tv.input[:slot])
    reports_input = get(tv.input, :reports, [])
    
    # Get service 1729's code
    for acc in tv.pre_state.accounts
        if acc[1] == 1729
            account = acc[2]
            for work_result in parse_work_report(reports_input[1]).results
                if work_result.service_id == 1729
                    service_code = account.preimages[work_result.code_hash]
                    
                    # Create context (simplified)
                    result = PVM.deblob(service_code)
                    if result !== nothing
                        instructions, opcode_mask, jump_table, ro_data, rw_data, stack_pages, stack_bytes = result
                        
                        println("Tracing execution from entry point 0x$(string(jump_table[11], base=16)):")
                        println("First FETCH is at PC=0x0991")
                        println()
                        
                        # Trace key PCs
                        key_pcs = [0x035b, 0x0991, 0x32a0, 0x47d1]
                        
                        println("Key locations:")
                        for pc in key_pcs
                            opcode = instructions[pc + 1]
                            skip = PVM.skip_distance(opcode_mask, pc + 1)
                            println("  PC=0x$(string(pc, base=16)): opcode=$opcode, skip=$skip")
                        end
                    end
                    break
                end
            end
            break
        end
    end
end

trace_execution()
