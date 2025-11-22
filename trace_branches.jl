#!/usr/bin/env julia
# Trace branches and register values from step 48 (after TEST) to step 237 (error loaded)

include("src/pvm/pvm.jl")
include("src/stf/accumulate.jl")
using JSON3

data = JSON3.read(read("jam-test-vectors/stf/accumulate/tiny/enqueue_and_unlock_chain-3.json", String))

# Get service account and code
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

                    # Branch opcodes
                    branch_ops = Dict(
                        8 => "branch_eq", 24 => "branch_ne",
                        60 => "branch_lt_u", 44 => "branch_lt_s",
                        45 => "branch_le_u", 61 => "branch_le_s",
                        28 => "branch_ge_u", 12 => "branch_ge_s",
                        13 => "branch_gt_u", 29 => "branch_gt_s",
                        17 => "branch_eq_imm", 23 => "branch_ne_imm",
                        47 => "branch_lt_u_imm", 59 => "branch_lt_s_imm",
                        63 => "branch_le_u_imm", 43 => "branch_le_s_imm",
                        58 => "branch_ge_u_imm", 46 => "branch_ge_s_imm",
                        42 => "branch_gt_u_imm", 62 => "branch_gt_s_imm"
                    )

                    # Decode instruction at a PC
                    function decode_at(pc)
                        opcode = instructions[pc + 1]
                        skip = PVM.skip_distance(opcode_mask, pc + 1)
                        reg_byte = skip >= 2 ? instructions[pc + 2] : 0
                        ra = reg_byte & 0x0F
                        rb = reg_byte >> 4

                        lx = min(4, max(0, skip - 1))
                        immx = UInt64(0)
                        for i in 0:lx-1
                            if pc + 2 + i < length(instructions)
                                byte = instructions[pc + 2 + i + 1]
                                immx |= UInt64(byte) << (8*i)
                            end
                        end
                        if lx > 0 && (immx >> (8*lx - 1)) & 1 == 1
                            immx |= ~((UInt64(1) << (8*lx)) - 1)
                        end
                        immx_signed = reinterpret(Int64, immx)

                        return (opcode, ra, rb, immx_signed, skip)
                    end

                    # Trace what happens at each branch near PC=0x4caf
                    # First, let's decode instructions around that error handling code
                    println("Decoding around error handler at PC=0x4caf:")
                    for offset in -20:10
                        pc = 0x4caf + offset
                        if pc >= 0 && pc < length(instructions)
                            opcode, ra, rb, imm, skip = decode_at(pc)
                            if haskey(branch_ops, opcode)
                                println("  PC=0x$(string(pc, base=16)): $(branch_ops[opcode]) r$ra, r$rb, $imm")
                            elseif opcode == 51  # add_imm
                                println("  PC=0x$(string(pc, base=16)): add_imm r$ra = r$rb + $imm")
                            end
                        end
                    end

                    println()
                    println("Now let's find what branches TO 0x4caf:")
                    # Search for branch instructions targeting 0x4caf
                    pc = 0
                    while pc < length(instructions)
                        opcode = instructions[pc + 1]
                        skip = PVM.skip_distance(opcode_mask, pc + 1)

                        if haskey(branch_ops, opcode)
                            opcode, ra, rb, imm, skip = decode_at(pc)
                            # Target = PC + skip + imm (for relative branches)
                            target = pc + skip + imm
                            if target == 0x4caf || (target >= 0x4ca0 && target <= 0x4cb5)
                                println("PC=0x$(string(pc, base=16)): $(branch_ops[opcode]) -> 0x$(string(target, base=16))")
                            end
                        end

                        pc += max(1, skip)
                    end
                end
                break
            end
        end
        break
    end
end
