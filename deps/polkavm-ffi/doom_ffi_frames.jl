#!/usr/bin/env julia
# Doom frame dumper using Rust polkavm FFI for comparison
# Run from project root: julia --project=. deps/polkavm-ffi/doom_ffi_frames.jl

const PROJECT_DIR = dirname(dirname(dirname(@__FILE__)))
pushfirst!(LOAD_PATH, PROJECT_DIR)

using Pkg
Pkg.activate(PROJECT_DIR; io=devnull)

include(joinpath(PROJECT_DIR, "src/pvm/polkavm_ffi.jl"))
using .PolkaVMFFI

const WIDTH = 320
const HEIGHT = 200
const FRAME_SIZE = WIDTH * HEIGHT * 3
const MAX_FRAMES = 260  # Capture enough to see gameplay
const OUTPUT_DIR = "/tmp/doom_frames_ffi"

println("Doom FFI Frame Dumper")
println("=====================")

mkpath(OUTPUT_DIR)

# Load doom
doom_path = "/tmp/polkajam-nightly-2025-12-22-linux-x86_64/doom.corevm"
doom_data = read(doom_path)

# Find PVM magic
pvm_magic = UInt8[0x50, 0x56, 0x4d, 0x00]
pvm_offset = 0
for i in 1:length(doom_data)-3
    if doom_data[i:i+3] == pvm_magic
        global pvm_offset = i
        break
    end
end
pvm_blob = doom_data[pvm_offset:end]
println("PVM blob: $(length(pvm_blob)) bytes")

# Create engine, module, instance using high-level wrappers
engine = PvmEngine(interpreter=true)
mod = PvmModule(engine, pvm_blob)
inst = PvmInstance(engine, mod)

# Get memory info
mem = memory_info(mod)
println("heap_base: 0x$(string(mem.heap_base, base=16))")

# Set up for execution
set_gas!(inst, Int64(100_000_000_000))
prepare_call!(inst, UInt32(0))

# Frame capture
rgb_frame = Vector{UInt8}(undef, FRAME_SIZE)
frame_count = 0

println("\nRunning Doom via FFI...")
start_time = time()

while frame_count < MAX_FRAMES
    result = run!(inst)

    if result.status == HOST
        call_id = result.host_call

        if call_id == 0  # INIT
            set_reg!(inst, REG_A0, UInt64(WIDTH))
            set_reg!(inst, REG_A1, UInt64(HEIGHT))
        elseif call_id == 1  # SBRK
            pages = UInt32(get_reg(inst, REG_A0))
            addr = sbrk!(inst, pages)
            set_reg!(inst, REG_A0, UInt64(addr))
        elseif call_id == 2  # FRAMEBUFFER
            fb_addr = UInt32(get_reg(inst, REG_A0))
            fb_size = UInt32(get_reg(inst, REG_A1))

            println("Frame $(frame_count+1): fb_addr=0x$(string(fb_addr, base=16)), size=$fb_size")

            # Dump raw framebuffer for frame 250
            if frame_count == 249  # Frame 250 (0-indexed)
                println("Dumping raw FFI framebuffer for frame 250...")
                raw_fb = read_memory(inst, fb_addr, UInt32(64769))
                if length(raw_fb) == 64769
                    open("/tmp/ffi_pvm_fb_250.bin", "w") do f
                        write(f, raw_fb[2:769])  # palette
                        write(f, raw_fb[770:end])  # pixels
                    end
                    println("Wrote /tmp/ffi_pvm_fb_250.bin")
                    println("Sample indexed pixels (first 20): ", raw_fb[770:789])
                    println("Sample palette entry 0 (RGB): ", (raw_fb[2], raw_fb[3], raw_fb[4]))
                end
            end

            if fb_size >= 64769
                # Read framebuffer using FFI optimized function
                if read_framebuffer_rgb24!(inst, fb_addr, fb_size, rgb_frame)
                    global frame_count += 1
                    filename = joinpath(OUTPUT_DIR, "frame_$(lpad(frame_count, 4, '0')).ppm")
                    open(filename, "w") do f
                        write(f, "P6\n$WIDTH $HEIGHT\n255\n")
                        write(f, rgb_frame)
                    end
                    println("Saved -> $filename")
                end
            end
        end
    elseif result.status == HALT
        println("Program halted")
        break
    elseif result.status == PANIC
        println("Program panicked")
        break
    elseif result.status == OOG
        println("Out of gas")
        break
    elseif result.status == FAULT
        println("Fault at PC=$(get_pc(inst))")
        break
    end
end

elapsed = time() - start_time
println("\nDone! Captured $frame_count frames in $(round(elapsed, digits=1))s")
println("View with: feh $OUTPUT_DIR/frame_*.ppm")
