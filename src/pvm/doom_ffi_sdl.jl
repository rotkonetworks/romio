#!/usr/bin/env julia
# Doom player using Rust PolkaVM FFI (JIT) with SDL display
# Run from project root: julia --project=. src/pvm/doom_ffi_sdl.jl

const PROJECT_DIR = dirname(dirname(dirname(@__FILE__)))
pushfirst!(LOAD_PATH, PROJECT_DIR)

using Pkg
Pkg.activate(PROJECT_DIR; io=devnull)

include(joinpath(PROJECT_DIR, "src/pvm/polkavm_ffi.jl"))
using .PolkaVMFFI

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

println("Doom FFI SDL Player")
println("===================")

# Find doom.corevm
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

# Create engine - try JIT first, fall back to interpreter
println("Creating PolkaVM engine...")
engine = try
    e = PvmEngine(interpreter=false)
    println("  Using JIT compiler")
    e
catch
    println("  JIT failed, using interpreter")
    PvmEngine(interpreter=true)
end
mod = PvmModule(engine, pvm_blob)
inst = PvmInstance(engine, mod)

# Set up for execution
set_gas!(inst, Int64(100_000_000_000))
prepare_call!(inst, UInt32(0))

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
    "romio Doom (Rust JIT)", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
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

# SDL event struct
mutable struct SDL_Event
    type::UInt32
    padding::NTuple{52, UInt8}
end

println("Running Doom via Rust JIT!")
println("Close the window or press Ctrl+C to quit.")
flush(stdout)

try
    while running
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

                if fb_size >= 64769
                    # Use optimized FFI function for framebuffer conversion
                    if read_framebuffer_rgb24!(inst, fb_addr, fb_size, rgb_frame)
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

                        global frame_count += 1

                        if frame_count % 10 == 0
                            elapsed = time() - start_time
                            fps = frame_count / elapsed
                            print("\rFrame $frame_count - $(round(fps, digits=2)) FPS  ")
                            flush(stdout)
                        end
                    end
                end

                # Process SDL events
                event = SDL_Event(0, ntuple(_ -> UInt8(0), 52))
                while ccall((:SDL_PollEvent, sdl), Cint, (Ref{SDL_Event},), event) != 0
                    if event.type == SDL_QUIT
                        global running = false
                    end
                end
            end
        elseif result.status == HALT
            println("\nProgram halted")
            break
        elseif result.status == PANIC
            println("\nProgram panicked")
            break
        elseif result.status == OOG
            println("\nOut of gas")
            break
        elseif result.status == FAULT
            println("\nFault at PC=$(get_pc(inst))")
            break
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
    elapsed = time() - start_time
    fps = frame_count / elapsed
    println("\n\nFinal: $frame_count frames in $(round(elapsed, digits=1))s = $(round(fps, digits=2)) FPS")

    # Cleanup SDL
    ccall((:SDL_DestroyTexture, sdl), Cvoid, (Ptr{Nothing},), texture)
    ccall((:SDL_DestroyRenderer, sdl), Cvoid, (Ptr{Nothing},), renderer)
    ccall((:SDL_DestroyWindow, sdl), Cvoid, (Ptr{Nothing},), window)
    ccall((:SDL_Quit, sdl), Cvoid, ())
end
