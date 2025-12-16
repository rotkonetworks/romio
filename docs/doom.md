# Doom on PVM

## Get the blob

```bash
curl -L https://github.com/nickkuk/polkajam/releases/download/nightly/polkajam-nightly-linux-x86_64.tar.gz | tar xz -C /tmp/
```

## Run

### Julia interpreter (~0.5 FPS)

```bash
julia --project=. examples/doom/doom_julia.jl
```

### Native polkavm FFI (~35 FPS)

```bash
cd deps/polkavm-ffi && cargo build --release && cd ../..

# mpv backend
julia --project=. examples/doom/doom_play.jl

# SDL2 window
julia --project=. examples/doom/doom_sdl.jl
```

## Blob format

doom.corevm contains:
- CoreVM header
- PVM bytecode (after "PVM" magic)

Host calls used:
- 1: sbrk (allocate pages)
- 2: framebuffer (1 byte header + 768 byte palette + 64000 indexed pixels)

The viewer converts indexed pixels to RGB24 via the palette.
