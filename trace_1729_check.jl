# Trace the check that fails in service 1729
# Focus on steps 32-37 (function at 0x29a3 that decides to take error path)

push!(LOAD_PATH, joinpath(@__DIR__, "src"))

include("src/pvm/pvm.jl")
using .PVM

# Load service code
include("src/test_vectors/loader.jl")
test_path = "jam-test-vectors/stf/accumulate/full/process_one_immediate_report-1.json"
tv = load_test_vector(test_path)

service_id = ServiceId(1729)
account = tv.pre_state.accounts[service_id]
service_code = account.preimages[account.code_hash]

# Parse the blob
parsed = PVM.deblob(service_code)
code, opcode_mask, jump_table = parsed

# Look at the function at 0x29a3 (called at step 32)
println("=== Function at 0x29a3 (steps 32-37) ===")
println("This function checks something and jumps to error path at 0x47b4")
println()

# Decode instructions from 0x29a3 to 0x29bf
for pc in 0x29a0:0x29c0
    if pc + 1 <= length(code) && opcode_mask[pc + 1]
        byte = code[pc + 1]
        # Find instruction length
        skip = PVM.skip_distance(opcode_mask, pc + 1)
        bytes = [code[pc + 1 + i] for i in 0:skip]
        bytes_hex = join(["$(string(b, base=16, pad=2))" for b in bytes], " ")

        # Get opcode name
        opcode_name = if byte == 0x95 "add_imm"
        elseif byte == 0x7b "load_u32"
        elseif byte == 0x47 "store_u32"
        elseif byte == 0x64 "add_imm (alt)"
        elseif byte == 0x50 "branch_eq_imm"
        else "op_$byte"
        end

        println("0x$(string(pc, base=16, pad=4)): $bytes_hex  [$opcode_name]")
    end
end

# The key is at 0x29af: opcode 0x64 followed by 0x50 (branch)
# Step 36: 0x29af, op=0x64
# Step 37: 0x29b1, op=0x50 -> jumps to 0x47b4

println("\n=== Analyzing the branch at 0x29b1 ===")
# 0x50 is branch_eq_imm - branch if register equals immediate
# Format: opcode, reg, immediate, target

pc = 0x29b1
bytes = [code[pc + 1 + i] for i in 0:5]
println("Instruction bytes: ", join(["0x$(string(b, base=16, pad=2))" for b in bytes], " "))

# Decode branch_eq_imm (opcode 50)
# Looking at encoding...

# Let me also check what opcode 0x64 does (step 36)
pc = 0x29af
println("\nInstruction at 0x29af (step 36):")
println("Bytes: 0x$(string(code[pc + 1], base=16)) 0x$(string(code[pc + 2], base=16))")

# 0x64 is... let me check
# It's executed before the branch, so it might be setting up the condition

println("\n=== Checking instruction definitions ===")
# Let me find what these opcodes are

# From graypaper, some common opcodes:
# 0x50 = branch_eq_imm (branch if rA == imm)
# 0x64 = add (rA = rB + rC) or similar

# The trace shows:
# Step 35: op=0x47 at 0x29ab
# Step 36: op=0x64 at 0x29af
# Step 37: op=0x50 at 0x29b1 -> jumps to 0x47b4

# So 0x64 might be setting up a value that 0x50 then tests

# Let me look at the register values at these steps from the trace:
println("\n=== Register values at steps 35-37 (from trace) ===")
println("Step 35: r7=4278058928, r8=71528, r10=200 (op=0x47)")
println("Step 36: r7=4278058872, r8=71528, r10=200 (op=0x64)")
println("Step 37: r7=4278058872, r8=71528, r10=200 (op=0x50 -> branch taken)")

# r7 changed from 4278058928 to 4278058872 at step 36
# That's a subtraction of 56
# 4278058872 = 0xFEFDFE38

println("\n=== Possible cause ===")
# The branch at step 37 is taken, going to error path
# This branch tests if some register equals some value
# Since error path is taken, the condition was true

# Key insight: the function at 0x29a3 receives some input and returns
# If it returns to 0x47b4, that's the error path
# Let me check what value is being tested

# Actually, I should look at what calls this function (step 31)
println("\n=== Call to function at step 31 ===")
println("Step 31: jump from 0x39c1 to 0x29a3")

# Let me look at the code before 0x29a3 to understand the calling convention
# and what the function is supposed to check
