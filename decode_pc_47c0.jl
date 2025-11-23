# Decode instructions around PC 0x47c0 where r8 becomes 0

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

# Look at bytes around PC 0x47c0
pc_start = 0x47b0
pc_end = 0x47f0

println("=== Code bytes from 0x$(string(pc_start, base=16)) to 0x$(string(pc_end, base=16)) ===")
for pc in pc_start:pc_end
    if pc + 1 <= length(code)
        byte = code[pc + 1]
        is_opcode = opcode_mask[pc + 1]
        marker = is_opcode ? "*" : " "
        println("0x$(string(pc, base=16, pad=4)): 0x$(string(byte, base=16, pad=2)) $marker")
    end
end

# Focus on the instruction at 0x47c0
println("\n=== Instruction at PC 0x47c0 ===")
pc = 0x47c0
println("Bytes: ", join(["0x$(string(code[pc + 1 + i], base=16, pad=2))" for i in 0:5], " "))

# Decode load_imm instruction
# Format: opcode (1 byte) + reg (4 bits) + immediate (variable)
opcode = code[pc + 1]
println("Opcode: 0x$(string(opcode, base=16)) ($(opcode == 51 ? "load_imm" : "unknown"))")

# The instruction encoding includes destination register and immediate
# Let me check how load_imm is encoded in the PVM

# Also check 0x47c2
println("\n=== Instruction at PC 0x47c2 ===")
pc = 0x47c2
println("Bytes: ", join(["0x$(string(code[pc + 1 + i], base=16, pad=2))" for i in 0:5], " "))
opcode = code[pc + 1]
println("Opcode: 0x$(string(opcode, base=16)) ($(opcode == 51 ? "load_imm" : "unknown"))")

# Let's trace what happens more carefully
# At step 41: executing at PC=0x47c0, after which r8=0
# So the instruction at 0x47c0 sets r8 to 0

# Actually, looking at graypaper instruction encoding:
# load_imm is opcode 51, format: reg_d is in bits after opcode
# The immediate follows

# Let me find where in the code the service checks the count or something else
println("\n=== Checking what value is being tested ===")
# The service reads input, gets count=1, then should call FETCH
# But instead it logs error with len=0

# Let's look at what the service is doing around step 38-42
# Step 38: Jump to 0x47b4
# Step 39-42: Setting up for LOG call

# The service might be checking if something is zero/nonzero
# and setting r8=0 to indicate error length for LOG
