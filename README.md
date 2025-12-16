# romio

JAM (Join Accumulate Machine) implementation in Julia.

## Status

149/149 STF tests passing (100%)

| Component | Tests |
|-----------|-------|
| Authorizations | 3/3 |
| Statistics | 3/3 |
| History | 4/4 |
| Accumulate | 30/30 |
| SAFROLE | 21/21 |
| Assurances | 10/10 |
| Preimages | 8/8 |
| Reports | 42/42 |
| Disputes | 28/28 |

## Requirements

- Julia 1.12+
- Rust (for bandersnatch-ffi)

## Build

```bash
# Build bandersnatch FFI
cd deps/bandersnatch-ffi && cargo build --release && cd ../..

# Run tests
julia --project=. -e 'using Pkg; Pkg.test()'

# Build standalone binary
julia --project=. build/build_app.jl
```

## Run

```bash
# Start node
julia --project=. -e 'using JAM; JAM.main()' -- --help

# Run STF tests
julia --project=. test/stf_test.jl
```

## Structure

```
src/
  types/       # JAM types (State, Block, ServiceAccount, etc)
  stf/         # State transition functions
  pvm/         # PolkaVM interpreter + host calls
  crypto/      # Blake2b, Keccak, Bandersnatch VRF
  codec/       # JAM serialization
  network/     # QUIC networking (JAMNP-S)
  rpc/         # JSON-RPC server
  consensus/   # GRANDPA, block production

deps/
  bandersnatch-ffi/   # Rust FFI for Bandersnatch VRF (ark-vrf)
  polkavm-ffi/        # Optional: native PolkaVM backend

examples/
  doom/        # Doom running on PVM
```

## PVM

The PolkaVM interpreter supports:
- 95 instructions
- 32 registers (13 general purpose)
- 4GB sparse address space (two-level page table)
- Gas metering
- 27+ host call types

## License

MIT
