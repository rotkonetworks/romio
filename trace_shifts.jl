# Trace what shifts happen to r7 at steps 0-1

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

# Check instruction at step 0: PC=0x01af
pc = 0x01af
bytes = [code[pc + 1 + i] for i in 0:5]
println("=== Step 0: PC=0x$(string(pc, base=16)) ===")
println("Bytes: ", join(["0x$(string(b, base=16, pad=2))" for b in bytes], " "))
println("Opcode: $(bytes[1]) = shlo_l_imm_64 (shift left)")

# Decode: ra = dest, rb = source, imm = shift amount
ra = bytes[2] & 0x0F
rb = (bytes[2] >> 4) & 0x0F
skip = PVM.skip_distance(opcode_mask, pc + 1)
println("Dest: r$ra, Src: r$rb, skip=$skip")

# Check instruction at step 1: PC=0x01b2
pc = 0x01b2
bytes = [code[pc + 1 + i] for i in 0:5]
println("\n=== Step 1: PC=0x$(string(pc, base=16)) ===")
println("Bytes: ", join(["0x$(string(b, base=16, pad=2))" for b in bytes], " "))
println("Opcode: $(bytes[1]) = shlo_r_imm_64 (shift right)")

ra = bytes[2] & 0x0F
rb = (bytes[2] >> 4) & 0x0F
skip = PVM.skip_distance(opcode_mask, pc + 1)
println("Dest: r$ra, Src: r$rb, skip=$skip")

# The immediate is the shift amount
# With lx bytes, the immediate is in bytes 3 onwards
# If skip=2, then lx=min(4, skip-1)=1 byte
lx = min(4, max(0, skip - 1))
local shift_imm = 0
for i in 0:lx-1
    shift_imm |= Int(bytes[3 + i]) << (8*i)
end
println("Shift amount: $shift_imm")

# What happens to r7 = 0xFEFF0000?
r7_init = UInt64(0xFEFF0000)
println("\n=== Computation ===")
println("Initial r7: 0x$(string(r7_init, base=16))")
# The shifts might be on different source registers, so we need exact decoding
