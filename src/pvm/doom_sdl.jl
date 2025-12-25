#!/usr/bin/env julia
# Doom player using pure Julia PVM interpreter with SDL display
# Run from project root: julia -J build/romio.so --project=. src/pvm/doom_sdl.jl

using JAM: PVM, PolkaVMBlob, CoreVMExtension

# SDL2 via native system library
const libsdl2 = "/usr/lib/libSDL2.so"

const SDL_INIT_VIDEO = 0x00000020
const SDL_WINDOW_SHOWN = 0x00000004
const SDL_WINDOWPOS_CENTERED = 0x2FFF0000
const SDL_QUIT = 0x100
const SDL_KEYDOWN = 0x300
const SDL_PIXELFORMAT_RGB24 = 0x17101803

const WIDTH = 320
const HEIGHT = 200
const SCALE = 3
const FRAME_SIZE = WIDTH * HEIGHT * 3

println("Loading Doom PVM (SDL display)...")

# Load Doom corevm blob - find latest nightly
doom_path = nothing
for d in sort(filter(s -> startswith(s, "polkajam-nightly-"), readdir("/tmp")), rev=true)
    p = joinpath("/tmp", d, "doom.corevm")
    if isfile(p)
        global doom_path = p
        break
    end
end

if doom_path === nothing
    error("Doom corevm not found! Install polkajam nightly to /tmp/")
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
prog = PolkaVMBlob.parse_polkavm_blob(pvm_blob)

println("  Code: $(length(prog.code)) bytes")
println("  RO data: $(length(prog.ro_data)) bytes")
println("  RW data size: $(prog.rw_data_size) bytes")
println("  Stack size: $(prog.stack_size) bytes")

# Get opcode mask
opcode_mask = PolkaVMBlob.get_opcode_mask(prog)

# Calculate memory layout
const VM_MAX_PAGE_SIZE = UInt32(0x10000)
const VM_ADDRESS_SPACE_BOTTOM = VM_MAX_PAGE_SIZE

align_64k(x) = (x + VM_MAX_PAGE_SIZE - 1) & ~(VM_MAX_PAGE_SIZE - 1)

ro_data_address_space = align_64k(prog.ro_data_size)
rw_data_address_space = align_64k(prog.rw_data_size)

const RO_BASE = UInt32(VM_ADDRESS_SPACE_BOTTOM)
const RW_BASE = UInt32(RO_BASE + ro_data_address_space + VM_MAX_PAGE_SIZE)
const STACK_HIGH = UInt32(0xFFFF0000 - VM_MAX_PAGE_SIZE)
const STACK_LOW = UInt32(STACK_HIGH - prog.stack_size)
const HEAP_BASE = UInt32(RW_BASE + prog.rw_data_size)

# Create CoreVM extension
corevm = CoreVMExtension.CoreVMHostCalls(width=WIDTH, height=HEIGHT)
CoreVMExtension.set_heap_base!(corevm, HEAP_BASE)

# Calculate skip distances
skip_distances = PVM.precompute_skip_distances(opcode_mask)

# Create PVM state
println("Creating PVM state...")

# Expand RW data to full declared size
rw_data_full = Vector{UInt8}(undef, prog.rw_data_size)
fill!(rw_data_full, 0)
copyto!(rw_data_full, 1, prog.rw_data, 1, length(prog.rw_data))

memory = PVM.Memory()
PVM.init_memory_regions!(memory,
    RO_BASE, UInt32(length(prog.ro_data)), prog.ro_data,
    RW_BASE, UInt32(length(rw_data_full)), rw_data_full,
    STACK_LOW, STACK_HIGH,
    HEAP_BASE, STACK_LOW
)

regs = zeros(UInt64, 13)
regs[1] = UInt64(0xFFFF0000)
regs[2] = UInt64(STACK_HIGH)

state = PVM.PVMState(
    UInt32(0), PVM.CONTINUE, Int64(100_000_000_000),
    prog.code, opcode_mask, skip_distances, regs, memory, prog.jump_table,
    UInt32(0), Vector{Vector{UInt8}}(), Dict{UInt32, PVM.GuestPVM}()
)

# Initialize SDL
println("Initializing SDL...")
sdl = libsdl2

ret = ccall((:SDL_Init, sdl), Cint, (UInt32,), SDL_INIT_VIDEO)
if ret != 0
    error_msg = unsafe_string(ccall((:SDL_GetError, sdl), Cstring, ()))
    error("SDL_Init failed: $error_msg")
end

# Create window
window = ccall((:SDL_CreateWindow, sdl), Ptr{Nothing},
    (Cstring, Cint, Cint, Cint, Cint, UInt32),
    "romio Doom (Julia PVM)", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
    WIDTH * SCALE, HEIGHT * SCALE, SDL_WINDOW_SHOWN)

if window == C_NULL
    error("SDL_CreateWindow failed")
end

# Create renderer
renderer = ccall((:SDL_CreateRenderer, sdl), Ptr{Nothing},
    (Ptr{Nothing}, Cint, UInt32),
    window, -1, 0)

if renderer == C_NULL
    error("SDL_CreateRenderer failed")
end

# Create texture for framebuffer
texture = ccall((:SDL_CreateTexture, sdl), Ptr{Nothing},
    (Ptr{Nothing}, UInt32, Cint, Cint, Cint),
    renderer, SDL_PIXELFORMAT_RGB24, 1, WIDTH, HEIGHT)

if texture == C_NULL
    error("SDL_CreateTexture failed")
end

# Pre-allocate RGB frame buffer
rgb_frame = Vector{UInt8}(undef, FRAME_SIZE)
frame_count = 0
start_time = time()
running = true

# SDL event struct (simplified)
mutable struct SDL_Event
    type::UInt32
    padding::NTuple{52, UInt8}
end

# Pre-allocate buffers for bulk read
palette_buf = Vector{UInt8}(undef, 768)
pixels_buf = Vector{UInt8}(undef, WIDTH * HEIGHT)

# Set up framebuffer callback
fb_callback = function(pvm_state, fb_addr, fb_size)
    global frame_count, rgb_frame, texture, renderer, running, palette_buf, pixels_buf

    if fb_size >= 64769  # 1 + 768 + 64000
        # Bulk read palette (768 bytes at fb_addr+1)
        PVM.read_bytes!(pvm_state, UInt32(fb_addr + 1), palette_buf, 768)

        # Bulk read indexed pixels (64000 bytes at fb_addr+769)
        PVM.read_bytes!(pvm_state, UInt32(fb_addr + 769), pixels_buf, WIDTH * HEIGHT)

        # Convert indexed to RGB using palette
        @inbounds for i in 1:WIDTH*HEIGHT
            idx = pixels_buf[i]
            base = Int(idx) * 3
            rgb_frame[(i-1)*3 + 1] = palette_buf[base + 1]
            rgb_frame[(i-1)*3 + 2] = palette_buf[base + 2]
            rgb_frame[(i-1)*3 + 3] = palette_buf[base + 3]
        end

        # Update texture
        ccall((:SDL_UpdateTexture, sdl), Cint,
            (Ptr{Nothing}, Ptr{Nothing}, Ptr{UInt8}, Cint),
            texture, C_NULL, rgb_frame, WIDTH * 3)

        # Render
        ccall((:SDL_RenderClear, sdl), Cint, (Ptr{Nothing},), renderer)
        ccall((:SDL_RenderCopy, sdl), Cint,
            (Ptr{Nothing}, Ptr{Nothing}, Ptr{Nothing}, Ptr{Nothing}),
            renderer, texture, C_NULL, C_NULL)
        ccall((:SDL_RenderPresent, sdl), Cvoid, (Ptr{Nothing},), renderer)

        frame_count += 1

        if frame_count % 10 == 0
            elapsed = time() - start_time
            fps = frame_count / elapsed
            print("\rFrame $frame_count - $(round(fps, digits=2)) FPS  ")
            flush(stdout)
        end

        # Process SDL events
        event = SDL_Event(0, ntuple(_ -> UInt8(0), 52))
        while ccall((:SDL_PollEvent, sdl), Cint, (Ref{SDL_Event},), event) != 0
            if event.type == SDL_QUIT
                running = false
            end
        end
    end
end

CoreVMExtension.set_framebuffer_callback!(corevm, fb_callback)

println("Running Doom with Julia interpreter!")
println("Close the window or press Ctrl+C to quit.")
flush(stdout)

try
    step_count = 0
    max_steps = 10_000_000_000
    batch_size = 10000  # Execute in batches for better performance

    while state.status == PVM.CONTINUE && state.gas > 0 && step_count < max_steps && running
        # Batch execute until HOST call or other interrupt
        PVM.step_n!(state, batch_size)
        step_count += batch_size

        if state.status == PVM.HOST
            handled = CoreVMExtension.handle_corevm_host_call!(state, corevm)
            if handled
                skip = PVM.skip_distance(state.opcode_mask, Int(state.pc) + 1)
                state.pc = state.pc + 1 + skip
                state.status = PVM.CONTINUE
            else
                println("\nUnhandled host call: $(state.host_call_id)")
                break
            end
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
    # Cleanup SDL
    ccall((:SDL_DestroyTexture, sdl), Cvoid, (Ptr{Nothing},), texture)
    ccall((:SDL_DestroyRenderer, sdl), Cvoid, (Ptr{Nothing},), renderer)
    ccall((:SDL_DestroyWindow, sdl), Cvoid, (Ptr{Nothing},), window)
    ccall((:SDL_Quit, sdl), Cvoid, ())

    elapsed = time() - start_time
    fps = frame_count / elapsed
    println("\n")
    println("=" ^ 50)
    println("Rendered $frame_count frames in $(round(elapsed, digits=2))s = $(round(fps, digits=2)) FPS")
    println("Final status: $(state.status)")
    println("=" ^ 50)
end
