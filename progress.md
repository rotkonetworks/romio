# Progress

## STF Tests: 149/149

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

## Done

- All STF components
- PVM interpreter (95 instructions, gas metering, 27+ host calls)
- JAM codec (encoder/decoder)
- Bandersnatch VRF via Rust FFI (ark-vrf)
- Blake2b, Keccak-256
- JAMNP-S networking (QUIC)
- Block production framework
- GRANDPA vote types

## TODO

### Host calls
- Selectors 3-6, 8-13
- Deep copy in checkpoint
- Full on_transfer invocation

### RPC
- Block/state/preimage lookups
- Work package/bundle submission

### Crypto
- Ed25519 signing
- BLS signing/verification/aggregation

### Consensus
- Multi-node GRANDPA testing
- Dispute slashing
