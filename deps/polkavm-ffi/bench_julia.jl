# benchmark julia pvm vs polkavm-ffi
const PROJECT_DIR = dirname(dirname(dirname(@__FILE__)))
pushfirst!(LOAD_PATH, PROJECT_DIR)

using Pkg
Pkg.activate(PROJECT_DIR; io=devnull)

include("../../src/pvm/pvm.jl")
using .PVM

include("../../src/pvm/polkavm_blob.jl")
using .PolkaVMBlob

include("../../src/pvm/corevm_extension.jl")
using .CoreVMExtension

const WIDTH = 320
const HEIGHT = 200

doom_path = "/tmp/polkajam-nightly-2025-12-22-linux-x86_64/doom.corevm"
doom_data = read(doom_path)

pvm_magic = UInt8[0x50, 0x56, 0x4d, 0x00]
pvm_offset = 0
for i in 1:length(doom_data)-3
    if doom_data[i:i+3] == pvm_magic
        global pvm_offset = i
        break
    end
end
pvm_blob = doom_data[pvm_offset:end]
println("pvm blob: $(length(pvm_blob)) bytes")

prog = parse_polkavm_blob(pvm_blob)
opcode_mask = get_opcode_mask(prog)

const VM_MAX_PAGE_SIZE = UInt32(0x10000)
const VM_ADDRESS_SPACE_BOTTOM = VM_MAX_PAGE_SIZE
align_64k(x) = (x + VM_MAX_PAGE_SIZE - 1) & ~(VM_MAX_PAGE_SIZE - 1)

ro_data_address_space = align_64k(prog.ro_data_size)
const RO_BASE = UInt32(VM_ADDRESS_SPACE_BOTTOM)
const RW_BASE = UInt32(RO_BASE + ro_data_address_space + VM_MAX_PAGE_SIZE)
# Stack region must include space above initial SP for frame setup
# The code computes SP + positive offsets for storing frame data
# Stack region: polkavm-ffi uses stack_address_high = 0xfffe0000 for initial SP
# But we need to map up to 0xffff1000 for positive offsets and return-to-host area
const STACK_TOP = UInt32(0xFFFF1000)   # Highest accessible stack address
const STACK_START = UInt32(0xfffe0000) # Initial SP value (matches polkavm-ffi)
const STACK_LOW = UInt32(0xfffd0000)   # Stack grows downward
# Page-align RW size for proper memory map
const PAGE_SIZE = UInt32(0x1000)  # 4KB pages
align_4k(x) = (x + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)
const RW_SIZE_ALIGNED = align_4k(prog.rw_data_size)
# HEAP_BASE must use exact rw_data_size to match polkavm sbrk semantics
# polkavm sbrk returns heap_base + page_count, NOT byte addresses
const HEAP_BASE = UInt32(RW_BASE + prog.rw_data_size)

corevm = CoreVMHostCalls(width=WIDTH, height=HEIGHT)
set_heap_base!(corevm, HEAP_BASE)

skip_distances = PVM.precompute_skip_distances(opcode_mask)

rw_data_full = zeros(UInt8, RW_SIZE_ALIGNED)
copyto!(rw_data_full, 1, prog.rw_data, 1, length(prog.rw_data))

memory = PVM.Memory()
PVM.init_memory_regions!(memory,
    RO_BASE, UInt32(length(prog.ro_data)), prog.ro_data,
    RW_BASE, UInt32(length(rw_data_full)), rw_data_full,
    STACK_LOW, STACK_TOP,  # Stack region from LOW to TOP
    HEAP_BASE, STACK_LOW
)

regs = zeros(UInt64, 13)
regs[1] = UInt64(0xFFFF0000)      # RA (return address)
regs[2] = UInt64(STACK_START)    # SP starts below STACK_TOP (room for frame setup)

state = PVM.PVMState(
    UInt32(0),
    PVM.CONTINUE,
    Int64(100_000_000_000),
    prog.code,
    opcode_mask,
    skip_distances,
    regs,
    memory,
    prog.jump_table,
    UInt32(0),
    Vector{Vector{UInt8}}(),
    Dict{UInt32, PVM.GuestPVM}()
)

frame_count = 0
fb_callback = function(pvm_state, fb_addr, fb_size)
    global frame_count
    frame_count += 1
end
set_framebuffer_callback!(corevm, fb_callback)

println("running benchmark (100 frames)...")
start = time()

while frame_count < 100 && state.gas > 0
    PVM.step!(state)

    if state.status == PVM.HOST
        handled = handle_corevm_host_call!(state, corevm)
        if handled
            skip = PVM.skip_distance(state.opcode_mask, Int(state.pc) + 1)
            state.pc = state.pc + 1 + skip
        else
            println("unhandled host call: $(state.host_call_id)")
            break
        end
    elseif state.status != PVM.CONTINUE
        println("stopped with status $(state.status)")
        break
    end
end

elapsed = time() - start
fps = frame_count / elapsed
println("rendered $frame_count frames in $(round(elapsed, digits=2))s = $(round(fps, digits=2)) fps")
