#!/usr/bin/env julia
# Trace all memory store operations to find when 70850 (error pointer) is written

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

                    # Find all store instructions and their addresses
                    # Store opcodes: store_imm_u8 (62), store_imm_u16 (79), store_imm_u32 (38), store_imm_u64 (39)
                    # store_ind_u8 (22), store_ind_u16 (91), store_ind_u32 (52), store_ind_u64 (53)

                    store_opcodes = Dict(
                        62 => "store_imm_u8",
                        79 => "store_imm_u16",
                        38 => "store_imm_u32",
                        39 => "store_imm_u64",
                        22 => "store_ind_u8",
                        91 => "store_ind_u16",
                        52 => "store_ind_u32",
                        53 => "store_ind_u64"
                    )

                    # The error pointer is 70850 = 0x114c2
                    # It's stored at stack address 0xFEFDFE38
                    # Let's find what instruction would write to that location

                    println("Looking for stores of value 70850 (0x114c2) or to address near 0xFEFDFE38")
                    println()

                    # The value 70850 is likely computed as 0x10000 (ro_data base) + 0x14c2 (offset)
                    # Let's see if there's an ADD instruction that computes this

                    # Actually, let me look for instructions that reference 0x14c2 or compute 0x114c2
                    # The offset 0x14c2 = 5314 decimal

                    # Let me find instructions with immediate value 5314 or 70850
                    pc = 0
                    while pc < length(instructions)
                        opcode = instructions[pc + 1]
                        skip = PVM.skip_distance(opcode_mask, pc + 1)

                        if skip > 1
                            # Decode immediate
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
                            immx_unsigned = immx & 0xFFFFFFFF

                            # Check if immediate is related to our target values
                            if immx_unsigned == 70850 || immx_unsigned == 5314 || immx_signed == 5314 || immx_signed == -5314
                                reg_byte = skip >= 2 ? instructions[pc + 2] : 0
                                ra = reg_byte & 0x0F
                                rb = reg_byte >> 4
                                println("PC=0x$(string(pc, base=16)): opcode=$opcode imm=$immx_signed ra=$ra rb=$rb")
                            end
                        end

                        pc += max(1, skip)
                    end

                    println()
                    println("Now let me look for LEA or ADD patterns that compute 0x10000 + offset")

                    # Look for instructions that use 0x10000 (65536) as immediate
                    pc = 0
                    count = 0
                    while pc < length(instructions) && count < 20
                        opcode = instructions[pc + 1]
                        skip = PVM.skip_distance(opcode_mask, pc + 1)

                        if skip > 1
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
                            immx_unsigned = immx & 0xFFFFFFFF

                            # Check for ro_data base address related values
                            if immx_unsigned == 65536 || immx_unsigned == 0x10000
                                reg_byte = skip >= 2 ? instructions[pc + 2] : 0
                                ra = reg_byte & 0x0F
                                rb = reg_byte >> 4
                                println("PC=0x$(string(pc, base=16)): opcode=$opcode imm=0x10000 ra=$ra rb=$rb")
                                count += 1
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
