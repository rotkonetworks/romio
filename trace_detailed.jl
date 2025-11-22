#!/usr/bin/env julia
include("src/pvm/pvm.jl")
include("src/stf/accumulate.jl")
using JSON3

# Load a failing test
data = JSON3.read(read("jam-test-vectors/stf/accumulate/tiny/process_one_immediate_report-1.json", String))

# Get the work report
work_report = data[:input][:reports][1]

# Get service_id from work_items
service_id = work_report[:results][1][:service_id]
println("Service ID: $service_id")

# Get account info
accounts = data[:pre_state][:accounts]
acc = nothing
for a in accounts
    if a[:id] == service_id
        global acc = a
        break
    end
end

if acc === nothing
    println("Account not found!")
    exit(1)
end

# Find the code blob
code_blob = nothing
for preimage in acc[:data][:preimages_blob]
    if length(preimage[:blob]) > 10000
        blob_hex = preimage[:blob]
        hex_str = blob_hex[3:end]
        global code_blob = [parse(UInt8, hex_str[i:i+1], base=16) for i in 1:2:length(hex_str)]
        break
    end
end

if code_blob === nothing
    println("Code blob not found!")
    exit(1)
end

# Deblob and check entry point
result = PVM.deblob(code_blob)
if result === nothing
    println("Deblob failed!")
    exit(1)
end

instructions, opcode_mask, jump_table, ro_data, rw_data, stack_pages, stack_bytes = result

entry_point = jump_table[11]  # Entry 10 = accumulate
println("Entry point: 0x$(string(entry_point, base=16))")
println("Stack pages: $stack_pages")

# Create input buffer
timeslot = UInt32(data[:input][:slot])
count = UInt32(length(work_report[:results]))

input = UInt8[]
append!(input, reinterpret(UInt8, [timeslot]))
append!(input, reinterpret(UInt8, [service_id]))
append!(input, reinterpret(UInt8, [count]))

println("Input: timeslot=$timeslot, service_id=$service_id, count=$count")

# Now let's manually trace to understand the control flow better
# Decode instructions from entry point to first branch

println("\n=== Decoding from entry point ===")
let pc = entry_point
    for i in 1:15
        if pc >= length(instructions)
            break
        end

        opcode = instructions[pc + 1]
        skip = PVM.skip_distance(opcode_mask, pc + 1)

        if skip == 0
            break
        end

        # Get register byte
        reg_byte = length(instructions) > pc + 1 ? instructions[pc + 2] : 0
        ra = reg_byte & 0x0F
        rb = (reg_byte >> 4) & 0x0F

        desc = "op=$opcode"

        if opcode == 130  # load_ind_u64
            lx = min(4, max(0, skip - 1))
            offset = Int64(0)
            for j in 0:lx-1
                byte = instructions[pc + 2 + j + 1]
                offset |= Int64(byte) << (8*j)
            end
            if lx > 0 && (offset >> (8*lx - 1)) & 1 == 1
                offset |= ~((Int64(1) << (8*lx)) - 1)
            end
            desc = "load_ind_u64 r$ra = [r$rb + $offset]"
        elseif opcode == 201  # sub_64
            rd = instructions[pc + 3] & 0x0F
            desc = "sub_64 r$rd = r$ra - r$rb"
        elseif opcode == 200  # add_64
            rd = instructions[pc + 3] & 0x0F
            desc = "add_64 r$rd = r$ra + r$rb"
        elseif opcode == 100  # load_u64
            lx = min(8, skip)
            imm = UInt64(0)
            for j in 0:lx-1
                if pc + 1 + j < length(instructions)
                    byte = instructions[pc + 1 + j + 1]
                    imm |= UInt64(byte) << (8*j)
                end
            end
            desc = "load_u64 r$ra = $imm"
        elseif opcode == 78  # branch_ne_imm
            lx_nibble = (reg_byte >> 4) & 0x07
            lx = Int(min(4, lx_nibble))
            ly = max(0, skip - lx - 1)

            immx = UInt64(0)
            for j in 0:lx-1
                byte = instructions[pc + 2 + j + 1]
                immx |= UInt64(byte) << (8*j)
            end

            immy = Int64(0)
            for j in 0:ly-1
                byte = instructions[pc + 2 + lx + j + 1]
                immy |= Int64(byte) << (8*j)
            end
            if ly > 0 && (immy >> (8*ly - 1)) & 1 == 1
                immy |= ~((Int64(1) << (8*ly)) - 1)
            end

            target = pc + immy
            desc = "branch_ne_imm: if r$ra != $immx then jump 0x$(string(target, base=16))"
        elseif opcode == 83  # branch_lt_u_imm
            lx_nibble = (reg_byte >> 4) & 0x07
            lx = Int(min(4, lx_nibble))
            ly = max(0, skip - lx - 1)

            immx = UInt64(0)
            for j in 0:lx-1
                byte = instructions[pc + 2 + j + 1]
                immx |= UInt64(byte) << (8*j)
            end

            immy = Int64(0)
            for j in 0:ly-1
                byte = instructions[pc + 2 + lx + j + 1]
                immy |= Int64(byte) << (8*j)
            end
            if ly > 0 && (immy >> (8*ly - 1)) & 1 == 1
                immy |= ~((Int64(1) << (8*ly)) - 1)
            end

            target = pc + immy
            desc = "branch_lt_u_imm: if r$ra < $immx then jump 0x$(string(target, base=16))"
        end

        println("$i. PC=0x$(string(pc, base=16)): $desc (skip=$skip)")
        pc += 1 + skip
    end
end

# Now check what's at the error path (0x32c)
println("\n=== Error path at 0x32c ===")
pc = 0x32c
for i in 1:10
    if pc >= length(instructions)
        break
    end

    opcode = instructions[pc + 1]
    skip = PVM.skip_distance(opcode_mask, pc + 1)

    if skip == 0
        println("$i. PC=0x$(string(pc, base=16)): INVALID (skip=0)")
        break
    end

    println("$i. PC=0x$(string(pc, base=16)): opcode=$opcode skip=$skip")
    pc += 1 + skip
end

# And what's at the panic location (0x32a0)
println("\n=== Panic location at 0x32a0 ===")
pc = 0x32a0
opcode = instructions[pc + 1]
skip = PVM.skip_distance(opcode_mask, pc + 1)
println("PC=0x$(string(pc, base=16)): opcode=$opcode skip=$skip")

# Check if 180 is load_imm_jump_ind
if opcode == 180
    reg_byte = instructions[pc + 2]
    ra = reg_byte & 0x0F
    rb = (reg_byte >> 4) & 0x0F

    lx = min(4, max(0, skip - 1))
    imm = Int64(0)
    for j in 0:lx-1
        byte = instructions[pc + 2 + j + 1]
        imm |= Int64(byte) << (8*j)
    end
    if lx > 0 && (imm >> (8*lx - 1)) & 1 == 1
        imm |= ~((Int64(1) << (8*lx)) - 1)
    end

    println("load_imm_jump_ind: r$ra = $imm, jump [r$rb]")
end
