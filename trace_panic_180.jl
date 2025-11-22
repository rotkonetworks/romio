#!/usr/bin/env julia
include("src/pvm/pvm.jl")
using JSON3

data = JSON3.read(read("jam-test-vectors/stf/accumulate/tiny/process_one_immediate_report-1.json", String))

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

                    # Check instruction at 0x32a0 (panic location)
                    pc = 0x32a0
                    opcode = instructions[pc + 1]
                    skip = PVM.skip_distance(opcode_mask, pc + 1)
                    reg_byte = instructions[pc + 2]
                    ra = reg_byte & 0x0F
                    rb = reg_byte >> 4

                    println("PC=0x$(string(pc, base=16)): load_imm_jump_ind ra=$ra rb=$rb skip=$skip")
                    println("jump_table has $(length(jump_table)) entries")

                    # This instruction has complex immediate decoding
                    # lx = min(4, instructions[pc + 3] % 8)
                    # immx from bytes 3 to 3+lx
                    # immy from bytes 3+lx onwards
                    lx = Int(min(4, instructions[pc + 3] % 8))
                    println("lx = $lx")

                    # If rb=0 (r0) and r0 was loaded from uninitialized memory (0)
                    # addr = 0 + immy, which panics if immy = 0
                    println()
                    println("If r$rb = 0, addr = 0 + immy → PANIC (addr == 0)")
                end
                break
            end
        end
        break
    end
end
