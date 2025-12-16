#!/usr/bin/env julia
# Doom frame dumper - saves frames to PNG files for inspection
# Run from project root: julia --project=. src/pvm/doom_frames.jl

const PROJECT_DIR = dirname(dirname(dirname(@__FILE__)))
pushfirst!(LOAD_PATH, PROJECT_DIR)

using Pkg
Pkg.activate(PROJECT_DIR; io=devnull)

# Include the PVM module
include(joinpath(@__DIR__, "pvm.jl"))
using .PVM

# Include the PolkaVM blob parser
include(joinpath(@__DIR__, "polkavm_blob.jl"))
using .PolkaVMBlob

# Include the CoreVM extension
include(joinpath(@__DIR__, "corevm_extension.jl"))
using .CoreVMExtension

const WIDTH = 320
const HEIGHT = 200
const FRAME_SIZE = WIDTH * HEIGHT * 3
const MAX_FRAMES = 10  # Save first 10 frames
const OUTPUT_DIR = "/tmp/doom_frames"

println("Doom Frame Dumper")
println("=================")

# Create output directory
mkpath(OUTPUT_DIR)
println("Saving frames to: $OUTPUT_DIR")

# Load Doom
doom_paths = [
    "/tmp/polkajam-nightly-2025-12-15-linux-x86_64/doom.corevm",
    "/tmp/polkajam-v0.1.27-linux-x86_64/doom.corevm",
]

doom_path = nothing
for p in doom_paths
    if isfile(p)
        global doom_path = p
        break
    end
end

doom_path === nothing && error("Doom not found")
println("Loading: $doom_path")

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

prog = parse_polkavm_blob(pvm_blob)
opcode_mask = get_opcode_mask(prog)

# Memory layout
VM_MAX_PAGE_SIZE = UInt32(0x10000)
align_64k(x) = (x + VM_MAX_PAGE_SIZE - 1) & ~(VM_MAX_PAGE_SIZE - 1)
ro_data_address_space = align_64k(prog.ro_data_size)

RO_BASE = UInt32(0x10000)
RW_BASE = UInt32(RO_BASE + ro_data_address_space + VM_MAX_PAGE_SIZE)
STACK_HIGH = UInt32(0xFFFF0000 - VM_MAX_PAGE_SIZE)
STACK_LOW = UInt32(STACK_HIGH - prog.stack_size)
HEAP_BASE = UInt32(RW_BASE + prog.rw_data_size)

corevm = CoreVMHostCalls(width=WIDTH, height=HEIGHT)
set_heap_base!(corevm, HEAP_BASE)

skip_distances = PVM.precompute_skip_distances(opcode_mask)

# Expand RW data
rw_data_full = zeros(UInt8, prog.rw_data_size)
copyto!(rw_data_full, 1, prog.rw_data, 1, length(prog.rw_data))

memory = PVM.Memory()
PVM.init_memory_regions!(memory, RO_BASE, UInt32(length(prog.ro_data)), prog.ro_data,
    RW_BASE, UInt32(length(rw_data_full)), rw_data_full, STACK_LOW, STACK_HIGH, HEAP_BASE, STACK_LOW)

regs = zeros(UInt64, 13)
regs[1] = UInt64(0xFFFF0000)
regs[2] = UInt64(STACK_HIGH)

state = PVM.PVMState(UInt32(0), PVM.CONTINUE, Int64(100_000_000_000),
    prog.code, opcode_mask, skip_distances, regs, memory, prog.jump_table,
    UInt32(0), Vector{Vector{UInt8}}(), Dict{UInt32, PVM.GuestPVM}())

rgb_frame = Vector{UInt8}(undef, FRAME_SIZE)
frame_count = 0

# Framebuffer callback - save to PPM (simple format, viewable with feh/eog/etc)
fb_callback = function(pvm_state, fb_addr, fb_size)
    global frame_count, rgb_frame

    if fb_size >= 64769 && frame_count < MAX_FRAMES
        # Decode palette + indexed pixels
        for i in 0:WIDTH*HEIGHT-1
            pixel_addr = fb_addr + 769 + i
            idx = PVM.read_u8(pvm_state, UInt64(pixel_addr))
            pvm_state.status = PVM.CONTINUE
            base = Int(idx) * 3
            if base + 2 < 768
                rgb_frame[i*3 + 1] = PVM.read_u8(pvm_state, UInt64(fb_addr + 1 + base))
                rgb_frame[i*3 + 2] = PVM.read_u8(pvm_state, UInt64(fb_addr + 2 + base))
                rgb_frame[i*3 + 3] = PVM.read_u8(pvm_state, UInt64(fb_addr + 3 + base))
                pvm_state.status = PVM.CONTINUE
            end
        end

        frame_count += 1
        filename = joinpath(OUTPUT_DIR, "frame_$(lpad(frame_count, 4, '0')).ppm")

        # Write PPM (P6 binary format)
        open(filename, "w") do f
            write(f, "P6\n$WIDTH $HEIGHT\n255\n")
            write(f, rgb_frame)
        end

        println("Saved frame $frame_count -> $filename")

        if frame_count >= MAX_FRAMES
            println("\nReached $MAX_FRAMES frames, stopping.")
            println("View frames with: feh $OUTPUT_DIR/frame_*.ppm")
            println("Or: eog $OUTPUT_DIR/frame_0001.ppm")
        end
    end
end

set_framebuffer_callback!(corevm, fb_callback)

println("\nRunning Doom to capture $MAX_FRAMES frames...")
start_time = time()

try
    step_count = 0
    while state.status == PVM.CONTINUE && state.gas > 0 && frame_count < MAX_FRAMES
        PVM.step!(state)
        step_count += 1

        if state.status == PVM.HOST
            handled = handle_corevm_host_call!(state, corevm)
            if handled
                skip = PVM.skip_distance(state.opcode_mask, Int(state.pc) + 1)
                state.pc = state.pc + 1 + skip
            else
                break
            end
        end

        if step_count % 10_000_000 == 0
            print(".")
            flush(stdout)
        end
    end
catch e
    isa(e, InterruptException) || rethrow(e)
end

elapsed = time() - start_time
println("\n")
println("Done! Captured $frame_count frames in $(round(elapsed, digits=1))s")
println("View with: feh $OUTPUT_DIR/frame_*.ppm")
