# Running Doom on PVM

romio can run Doom compiled to PolkaVM bytecode.

## Get the blob

Download polkajam nightly:

```bash
curl -L https://github.com/nickkuk/polkajam/releases/download/nightly/polkajam-nightly-linux-x86_64.tar.gz | tar xz -C /tmp/
```

The `doom.corevm` file contains a PVM blob with Doom.

## Run methods

### 1. Pure Julia interpreter (slow, ~0.5 FPS)

Uses the Julia PVM interpreter. Good for debugging.

```bash
julia --project=. examples/doom/doom_julia.jl
```

Requires mpv for display.

### 2. Native PolkaVM FFI (fast, ~35 FPS)

Uses the Rust polkavm library via FFI.

```bash
# Build polkavm-ffi first
cd deps/polkavm-ffi && cargo build --release && cd ../..

# Run with mpv backend
julia --project=. examples/doom/doom_play.jl

# Or with SDL2 window
julia --project=. examples/doom/doom_sdl.jl
```

## How it works

The doom.corevm blob contains:
- CoreVM header with metadata
- PVM bytecode (starts at "PVM" magic bytes)

The PVM program uses two host calls:
- `host_call 1`: sbrk (memory allocation)
- `host_call 2`: framebuffer output

Framebuffer format:
- 1 byte header
- 768 bytes palette (256 RGB entries)
- 64000 bytes indexed pixels (320x200)

The viewer converts indexed pixels to RGB24 using the palette and displays via mpv or SDL2.

## CoreVM extension

The `corevm_extension.jl` module implements the host calls needed for Doom:

```julia
# Register extension
corevm = CoreVMHostCalls(width=320, height=200)
PVM.HostCalls.register_host_call_extension!(corevm)

# Set framebuffer callback
set_framebuffer_callback!(corevm) do state, fb_addr, fb_size
    # Read and display frame
end
```

## Performance

| Backend | FPS | Notes |
|---------|-----|-------|
| Julia interpreter | ~0.5 | Pure Julia, no FFI |
| polkavm JIT | ~35 | Native Rust via FFI |
