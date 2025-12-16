#!/usr/bin/env julia
# Doom player using pure Julia PVM interpreter
# Run from project root: julia --project=. src/pvm/doom_julia.jl

const PROJECT_DIR = dirname(dirname(dirname(@__FILE__)))
pushfirst!(LOAD_PATH, PROJECT_DIR)

using Pkg
Pkg.activate(PROJECT_DIR; io=devnull)

# Include the PVM module
include(joinpath(@__DIR__, "pvm.jl"))
using .PVM

# Include the PolkaVM blob parser (for .polkavm format)
include(joinpath(@__DIR__, "polkavm_blob.jl"))
using .PolkaVMBlob

# Include the CoreVM extension
include(joinpath(@__DIR__, "corevm_extension.jl"))
using .CoreVMExtension

const WIDTH = 320
const HEIGHT = 200
const FRAME_SIZE = WIDTH * HEIGHT * 3

println("Loading Doom PVM (pure Julia interpreter)...")

# Load Doom corevm blob - try multiple paths
doom_paths = [
    "/tmp/polkajam-nightly-2025-12-15-linux-x86_64/doom.corevm",
    "/tmp/polkajam-v0.1.27-linux-x86_64/doom.corevm",
    expanduser("~/doom.corevm"),
    joinpath(PROJECT_DIR, "doom.corevm"),
]

doom_path = nothing
for p in doom_paths
    if isfile(p)
        global doom_path = p
        break
    end
end

if doom_path === nothing
    error("Doom corevm not found! Tried: $(join(doom_paths, ", "))")
end

println("Loading from: $doom_path")
doom_data = read(doom_path)

# Find PVM magic (PVM\0) and extract blob
pvm_magic = UInt8[0x50, 0x56, 0x4d, 0x00]
pvm_offset = 0
for i in 1:length(doom_data)-3
    if doom_data[i:i+3] == pvm_magic
        global pvm_offset = i
        break
    end
end

if pvm_offset == 0
    error("PVM magic not found in corevm file")
end

pvm_blob = doom_data[pvm_offset:end]
println("PVM blob found at offset $(pvm_offset-1): $(length(pvm_blob)) bytes")

# Parse using PolkaVM blob parser
println("Parsing PVM blob...")
prog = parse_polkavm_blob(pvm_blob)

println("  Code: $(length(prog.code)) bytes")
println("  RO data: $(length(prog.ro_data)) bytes (size declared: $(prog.ro_data_size))")
println("  RW data: $(length(prog.rw_data)) bytes (size declared: $(prog.rw_data_size))")
println("  Stack size: $(prog.stack_size) bytes")
println("  Jump table: $(length(prog.jump_table)) entries")
println("  Exports: $(length(prog.exports))")
for exp in prog.exports
    println("    $(exp.name) -> PC $(exp.pc)")
end

# Get opcode mask
opcode_mask = get_opcode_mask(prog)

# Calculate memory layout (matches PolkaVM)
const VM_MAX_PAGE_SIZE = UInt32(0x10000)  # 64KB
const VM_ADDRESS_SPACE_BOTTOM = VM_MAX_PAGE_SIZE

align_64k(x) = (x + VM_MAX_PAGE_SIZE - 1) & ~(VM_MAX_PAGE_SIZE - 1)

ro_data_address_space = align_64k(prog.ro_data_size)
rw_data_address_space = align_64k(prog.rw_data_size)

const RO_BASE = UInt32(VM_ADDRESS_SPACE_BOTTOM)  # 0x10000
const RW_BASE = UInt32(RO_BASE + ro_data_address_space + VM_MAX_PAGE_SIZE)  # after RO + guard
const STACK_HIGH = UInt32(0xFFFF0000 - VM_MAX_PAGE_SIZE)  # below return-to-host region
const STACK_LOW = UInt32(STACK_HIGH - prog.stack_size)
# Use declared RW size (not actual data length) for heap base calculation
# The RW region may be larger than the initialized data (BSS section)
const HEAP_BASE = UInt32(RW_BASE + prog.rw_data_size)

println("Memory layout:")
println("  RO:    0x$(string(RO_BASE, base=16)) - 0x$(string(RO_BASE + UInt32(length(prog.ro_data)), base=16))")
println("  RW:    0x$(string(RW_BASE, base=16)) - 0x$(string(RW_BASE + UInt32(length(prog.rw_data)), base=16))")
println("  Stack: 0x$(string(STACK_LOW, base=16)) - 0x$(string(STACK_HIGH, base=16))")
println("  Heap:  0x$(string(HEAP_BASE, base=16))+")

# Create CoreVM extension
corevm = CoreVMHostCalls(width=WIDTH, height=HEIGHT)
set_heap_base!(corevm, HEAP_BASE)

# Calculate skip distances
skip_distances = PVM.precompute_skip_distances(opcode_mask)

# Create PVM state with proper memory layout
println("Creating PVM state...")

# Expand RW data to full declared size (BSS section is zero-initialized)
rw_data_full = Vector{UInt8}(undef, prog.rw_data_size)
fill!(rw_data_full, 0)
copyto!(rw_data_full, 1, prog.rw_data, 1, length(prog.rw_data))
println("  Expanded RW data: $(length(prog.rw_data)) -> $(length(rw_data_full)) bytes")

memory = PVM.Memory()
PVM.init_memory_regions!(memory,
    RO_BASE, UInt32(length(prog.ro_data)), prog.ro_data,
    RW_BASE, UInt32(length(rw_data_full)), rw_data_full,
    STACK_LOW, STACK_HIGH,
    HEAP_BASE, STACK_LOW  # heap limit = stack start
)

# Initialize registers
regs = zeros(UInt64, 13)
regs[1] = UInt64(0xFFFF0000)  # ω0 = RA = return address
regs[2] = UInt64(STACK_HIGH)   # ω1 = SP = stack pointer

state = PVM.PVMState(
    UInt32(0),  # pc
    PVM.CONTINUE,  # status
    Int64(100_000_000_000),  # gas (100B - lots of gas)
    prog.code,
    opcode_mask,
    skip_distances,
    regs,
    memory,
    prog.jump_table,
    UInt32(0),  # host_call_id
    Vector{Vector{UInt8}}(),
    Dict{UInt32, PVM.GuestPVM}()
)

println("Starting mpv...")
player = open(`mpv --no-cache --demuxer=rawvideo --demuxer-rawvideo-w=$(WIDTH) --demuxer-rawvideo-h=$(HEIGHT) --demuxer-rawvideo-mp-format=rgb24 --demuxer-rawvideo-fps=35 --title="JAMit Doom (Julia PVM)" -`, "w")

# Pre-allocate RGB frame buffer
rgb_frame = Vector{UInt8}(undef, FRAME_SIZE)
frame_count = 0
start_time = time()

# Set up framebuffer callback
fb_callback = function(pvm_state, fb_addr, fb_size)
    global frame_count, rgb_frame, player

    if fb_size >= 64769  # 1 + 768 + 64000
        # Read palette + indexed pixels from PVM memory
        # Format: 1 byte header + 768 byte palette + 64000 indexed pixels
        for i in 0:WIDTH*HEIGHT-1
            pixel_addr = fb_addr + 769 + i  # Skip header + palette
            if pixel_addr < 2^32
                idx = PVM.read_u8(pvm_state, UInt64(pixel_addr))
                if pvm_state.status != PVM.CONTINUE
                    pvm_state.status = PVM.CONTINUE  # Reset status, allow to continue
                end
                base = Int(idx) * 3
                if base + 2 < 768
                    r = PVM.read_u8(pvm_state, UInt64(fb_addr + 1 + base))
                    g = PVM.read_u8(pvm_state, UInt64(fb_addr + 2 + base))
                    b = PVM.read_u8(pvm_state, UInt64(fb_addr + 3 + base))
                    if pvm_state.status != PVM.CONTINUE
                        pvm_state.status = PVM.CONTINUE
                    end
                    rgb_frame[i*3 + 1] = r
                    rgb_frame[i*3 + 2] = g
                    rgb_frame[i*3 + 3] = b
                end
            end
        end

        write(player, rgb_frame)
        flush(player)
        frame_count += 1

        if frame_count % 10 == 0
            elapsed = time() - start_time
            fps = frame_count / elapsed
            print("\rFrame $frame_count - $(round(fps, digits=2)) FPS  ")
            flush(stdout)
        end
    end
end

set_framebuffer_callback!(corevm, fb_callback)

println("Running Doom with Julia interpreter!")
println("Close the mpv window or press Ctrl+C to quit.")
flush(stdout)

try
    step_count = 0
    max_steps = 10_000_000_000  # 10B steps max

    while state.status == PVM.CONTINUE && state.gas > 0 && step_count < max_steps
        # Execute one instruction
        PVM.step!(state)
        step_count += 1

        # Handle host call
        if state.status == PVM.HOST
            handled = handle_corevm_host_call!(state, corevm)
            if handled
                # Advance PC past ecalli
                skip = PVM.skip_distance(state.opcode_mask, Int(state.pc) + 1)
                state.pc = state.pc + 1 + skip
            else
                println("\nUnhandled host call: $(state.host_call_id)")
                break
            end
        end

        # Progress indicator
        if step_count % 10_000_000 == 0
            print(".")
            flush(stdout)
        end
    end
catch e
    if isa(e, InterruptException)
        println("\nInterrupted")
    else
        println("\nError: $e")
        rethrow(e)
    end
finally
    close(player)
    elapsed = time() - start_time
    fps = frame_count / elapsed
    println("\n")
    println("=" ^ 50)
    println("Rendered $frame_count frames in $(round(elapsed, digits=2))s = $(round(fps, digits=2)) FPS")
    println("Final status: $(state.status)")
    println("Gas remaining: $(state.gas)")
    if state.gas <= 0
        println("Out of gas!")
    end
    println("=" ^ 50)
end
