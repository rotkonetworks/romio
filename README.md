# romio

JAM (Join Accumulate Machine) implementation in Julia.

## Status
<img width="949" height="601" alt="image" src="https://github.com/user-attachments/assets/c26b54be-1536-4a57-8bd1-3af5ddb9a2a8" />


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
make        # builds deps + sysimage
make test   # run tests
```

## Run

```bash
make run ARGS="--help"
make run ARGS="run --chain dev"

# or directly:
julia -J build/romio.so --project=. bin/romio --help
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
