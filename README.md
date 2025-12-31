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
# cli help
make run ARGS="--help"

# run testnet (compatible with jamt cli)
make run ARGS="testnet"

# or directly:
julia -J build/romio.so --project=. bin/romio testnet
```

## Testnet

romio runs a jam-compatible testnet with bootstrap service:

```bash
# start testnet
./bin/romio testnet

# in another terminal, use jamt to deploy services
jamt --rpc ws://localhost:19800 create-service ./myservice.corevm
jamt --rpc ws://localhost:19800 vm new ./doom.corevm 1000000000
```

see [docs/doom.md](docs/doom.md) for running doom on pvm.

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

the polkavm interpreter supports:
- 95 instructions (jam v1 isa)
- 32 registers (13 general purpose)
- 4gb sparse address space (two-level page table)
- gas metering
- 27+ host call types
- optional rust ffi backend for ~70x faster execution

## Building Services

jam services are pvm programs with refine/accumulate entry points:

```bash
# using polkaports toolchain
cd ~/rotko/polkaports
. ./activate.sh polkavm

# compile c to elf
polkavm-cc -flto -Os service.c -o service.elf

# link to jam format
polkatool link --dispatch-table '_jb_entry_refine,_jb_entry_accumulate' service.elf -o service.jam

# wrap in corevm format for jamt
# (add P + SCALE-encoded name/version/license/author header)
```

see [blc-service](https://github.com/user/blc-service) for a complete sdk.

## License

MIT
