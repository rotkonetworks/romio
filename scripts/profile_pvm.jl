# Profile PVM interpreter for bottleneck detection
using InteractiveUtils

const SRC_DIR = joinpath(dirname(@__DIR__), "src")

include(joinpath(SRC_DIR, "crypto", "Blake2b.jl"))
include(joinpath(SRC_DIR, "pvm", "pvm.jl"))
include(joinpath(SRC_DIR, "pvm", "polkavm_blob.jl"))
include(joinpath(SRC_DIR, "pvm", "corevm_extension.jl"))

using .PVM
using .PolkaVMBlob
using .CoreVMExtension

function blake2b_256(data::Vector{UInt8})::Vector{UInt8}
    output = zeros(UInt8, 32)
    Blake2b!(output, 32, UInt8[], 0, data, length(data))
    return output
end

# Load doom
doom_path = "/tmp/polkajam-v0.1.27-linux-x86_64/doom.corevm"
doom_data = read(doom_path)
pvm_magic = findfirst(b"PVM\0", doom_data)
pvm_blob = doom_data[pvm_magic[1]:end]
parsed = PolkaVMBlob.parse_polkavm_blob(pvm_blob)

# Memory setup
VM_MAX_PAGE_SIZE = UInt32(0x10000)
align_64k(x) = (x + VM_MAX_PAGE_SIZE - 1) & ~(VM_MAX_PAGE_SIZE - 1)
ro_data_address_space = align_64k(parsed.ro_data_size)
RO_BASE = UInt32(0x10000)
RW_BASE = UInt32(RO_BASE + ro_data_address_space + VM_MAX_PAGE_SIZE)
STACK_HIGH = UInt32(0xFFFF0000 - VM_MAX_PAGE_SIZE)
STACK_LOW = UInt32(STACK_HIGH - parsed.stack_size)
HEAP_BASE = UInt32(RW_BASE + parsed.rw_data_size)

rw_data_full = zeros(UInt8, parsed.rw_data_size)
copyto!(rw_data_full, 1, parsed.rw_data, 1, length(parsed.rw_data))

memory = PVM.Memory()
PVM.init_memory_regions!(memory,
    RO_BASE, UInt32(length(parsed.ro_data)), parsed.ro_data,
    RW_BASE, UInt32(length(rw_data_full)), rw_data_full,
    STACK_LOW, STACK_HIGH,
    HEAP_BASE, STACK_LOW)

opcode_mask = PolkaVMBlob.get_opcode_mask(parsed)
skip_distances = PVM.precompute_skip_distances(opcode_mask)

regs = zeros(UInt64, 13)
regs[1] = UInt64(0xFFFF0000)
regs[2] = UInt64(STACK_HIGH)

initial_gas = Int64(100_000_000_000)
state = PVM.PVMState(
    UInt32(0), PVM.CONTINUE, initial_gas,
    parsed.code, opcode_mask, skip_distances, regs, memory, parsed.jump_table,
    UInt32(0), Vector{Vector{UInt8}}(), Dict{UInt32, PVM.GuestPVM}())

corevm = CoreVMExtension.CoreVMHostCalls(width=320, height=200)
CoreVMExtension.set_heap_base!(corevm, HEAP_BASE)

println("=== Checking step! for type instabilities ===")
@code_warntype PVM.step!(state)
