# Doom on PVM

## Get the polkajam tools (includes jamt CLI)

```bash
# Use the fetch script (requires: gh, jq)
./scripts/fetch-jamt.sh

# The script fetches the latest nightly from paritytech/polkajam-releases
# and extracts to /tmp/polkajam-nightly-YYYY-MM-DD-linux-x86_64/
```

## Performance

| Backend | FPS | Notes |
|---------|-----|-------|
| Pure Julia interpreter | ~0.5 | Educational, fully transparent implementation |
| Native polkavm FFI | ~35 | Uses Rust polkavm via ccall |
| polkajam (Rust, JIT) | ~35 | Reference implementation with JIT compilation |
| polkajam (Rust, interpreter) | ~1.5 | `POLKAVM_BACKEND=interpreter` |

The pure Julia interpreter is ~70x slower than native execution but provides a fully transparent, auditable PVM implementation for research and validation purposes.

## Run

### Pure Julia interpreter (~0.5 FPS)

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
- 0: init (returns screen width/height)
- 1: sbrk (allocate pages)
- 2: framebuffer (1 byte header + 768 byte palette + 64000 indexed pixels)

The viewer converts indexed pixels to RGB24 via the palette.

## jamt CLI compatibility

romio implements JIP-2 (JAM RPC) and is compatible with the `jamt` CLI tool from polkajam.

```bash
# Fetch latest jamt
./scripts/fetch-jamt.sh

# Start romio testnet
./bin/romio testnet -n 3 --base-rpc-port 19800

# Use jamt to interact (note: requires Bootstrap service for vm new)
/tmp/polkajam-nightly-*/jamt --help
```

Note: `jamt vm new` requires the Bootstrap service (service #0) to be pre-installed in the genesis state. This is available in polkajam-testnet but not yet in romio.
