# doom on pvm

## fetch polkajam tools

```bash
# fetch the latest release
./scripts/fetch-jamt.sh

# extracts to /tmp/polkajam-v0.1.27-linux-x86_64/
```

## performance

| backend | fps | notes |
|---------|-----|-------|
| pure julia interpreter | ~0.5 | fully transparent pvm implementation |
| rust polkavm ffi (jit) | ~35 | uses polkavm via ccall |
| polkajam (rust, jit) | ~35 | reference implementation |

## run doom

### native polkavm ffi (~35 fps)

```bash
# build the ffi library
cd deps/polkavm-ffi && cargo build --release && cd ../..

# run with sdl2 window
julia --project=. examples/doom/doom_sdl.jl
```

### pure julia interpreter (~0.5 fps)

```bash
julia --project=. examples/doom/doom_julia.jl
```

## corevm format

doom.corevm contains a metadata header + pvm bytecode:

```
header:
  - format marker (0x3c or 0x50)
  - name, version, license, author (length-prefixed)

pvm blob:
  - starts with "PVM\0" magic
  - polkavm bytecode
```

host calls used by doom:
- 0: init (returns screen width/height)
- 1: sbrk (allocate pages)
- 2: framebuffer (1 byte header + 768 byte palette + 64000 indexed pixels)

## testnet integration

romio implements jam rpc (jip-2) and works with jamt cli:

```bash
# start testnet with bootstrap service
julia --project=. -e 'using JAM; JAM.JuliaJAMTestnet.run()'

# deploy doom via jamt
jamt --rpc ws://localhost:19800 vm new /tmp/polkajam-v0.1.27-linux-x86_64/doom.corevm 1000000000
```
