# Decode the conditional branch at step 2

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

# Decode branch_eq_imm at PC 0x01b5
pc = 0x01b5
println("=== Branch at PC 0x$(string(pc, base=16)) ===")
bytes = [code[pc + 1 + i] for i in 0:7]
println("Bytes: ", join(["0x$(string(b, base=16, pad=2))" for b in bytes], " "))

opcode = bytes[1]  # 0x51 = 81 = branch_eq_imm
println("Opcode: $opcode (branch_eq_imm)")

# Decode according to PVM spec
ra = bytes[2] & 0x0F
lx_field = (bytes[2] >> 4) % 8
skip = PVM.skip_distance(opcode_mask, pc + 1)
ly = min(4, max(0, skip - lx_field - 1))

println("Register index: $ra")
println("lx: $lx_field, ly: $ly, skip: $skip")

# Decode immediate
immx = 0
for i in 0:lx_field-1
    immx |= Int(bytes[3 + i]) << (8*i)
end
println("Immediate: $immx")

# Expected target from trace: 0x041d
expected_offset = 0x041d - pc
println("\nExpected offset: $expected_offset (to reach 0x041d)")
