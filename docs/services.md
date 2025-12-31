# jam services

## overview

jam services are pvm programs that run on the jam blockchain. the relationship between the jam host (blockchain) and guest (service) is:

```
┌─────────────────────────────────────────────────────────────┐
│                      JAM HOST (blockchain)                  │
│                                                             │
│  provides: storage, transfers, chain data, pvm execution    │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              GUEST SERVICE (your code)               │   │
│  │                                                      │   │
│  │  implements: refine, accumulate                      │   │
│  │  calls: host functions (read, write, transfer...)    │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## guest functions (you implement)

services must implement two entry points:

| function | context | purpose |
|----------|---------|---------|
| `refine` | pure | computation only, no state changes, produces export data |
| `accumulate` | stateful | processes work items, updates storage, transfers funds |

**refine** runs on validators off-chain. it takes work item payload and produces an exported result. multiple validators run the same refine to verify correctness.

**accumulate** runs on-chain after refine completes. it receives the refined output and can modify state (storage, balances, create services).

```c
// guest entry points
void jb_refine(void) {
    // read input via host_fetch()
    // do pure computation
    // export result via host_export()
}

void jb_accumulate(void) {
    // read work items via host_fetch()
    // read/write storage via host_read()/host_write()
    // transfer funds via host_transfer()
}
```

## host functions (jam provides)

the host provides functions that services can call. they're organized by which context they're available in:

### general (both refine & accumulate)

| index | function | purpose |
|-------|----------|---------|
| 0 | `gas` | get remaining gas |
| 1 | `fetch` | get chain data, work items, entropy |
| 3 | `read` | read storage (any service's) |
| 4 | `write` | write storage (own service only) |
| 5 | `info` | get service metadata |
| 100 | `log` | debug logging |

### refine only (pure computation)

| index | function | purpose |
|-------|----------|---------|
| 6 | `historical_lookup` | get preimage by hash from history |
| 7 | `export` | export result data for accumulate |
| 8 | `machine` | create new pvm instance |
| 9 | `peek` | read pvm memory |
| 10 | `poke` | write pvm memory |
| 11 | `pages` | allocate/free pvm pages |
| 12 | `invoke` | execute pvm code |
| 13 | `expunge` | destroy pvm instance |

the `machine/peek/poke/invoke/expunge` functions let you run arbitrary pvm code during refine. this is how one service can call another's code.

### accumulate only (state changes)

| index | function | purpose |
|-------|----------|---------|
| 14 | `bless` | set privileged services |
| 15 | `assign` | assign cores to services |
| 16 | `designate` | set validator keys |
| 17 | `checkpoint` | create state checkpoint |
| 18 | `new` | create new service |
| 19 | `upgrade` | upgrade service code |
| 20 | `transfer` | send funds to another service |
| 21 | `eject` | destroy service, recover funds |
| 22 | `query` | check if preimage exists |
| 23 | `solicit` | request preimage |
| 24 | `forget` | forget preimage |
| 25 | `yield` | yield execution |
| 26 | `provide` | provide preimage data |

## service types

### jam services (on-chain)

standard jam services deployed via bootstrap:

```bash
jamt --rpc ws://localhost:19800 create-service ./service.corevm
```

### corevm services (interactive)

corevm services run interactively with video/audio output (like doom):

```bash
jamt --rpc ws://localhost:19800 vm new ./doom.corevm 1000000000
```

## building services

### prerequisites

```bash
# clone and build polkaports toolchain
git clone https://github.com/jambrains/polkaports
cd polkaports
env CC=clang CXX=clang++ LLD=lld ./setup.sh

# activate for corevm target
. ./activate.sh polkavm
```

### compile and link

```bash
# compile c to elf
polkavm-cc -flto -Os -I./sdk service.c sdk/*.c -o service.elf

# link to jam format with dispatch table
polkatool link \
  --min-stack-size 131072 \
  --dispatch-table '_jb_entry_refine,_jb_entry_accumulate' \
  service.elf -o service.jam
```

### wrap as corevm

jamt expects corevm format: metadata header + pvm blob.

```bash
# using the justfile target (in blc-service/services)
just -f Justfile.local corevm service-name "my-service" "0.1.0" "MIT" "author"

# or manually with python
python3 << 'EOF'
def scale_compact(n):
    if n < 64:
        return bytes([n << 2])
    raise ValueError("string too long")

def wrap_corevm(jam_path, name, version, license, author):
    with open(jam_path, 'rb') as f:
        jam = f.read()

    header = b'P'
    header += scale_compact(len(name)) + name.encode()
    header += scale_compact(len(version)) + version.encode()
    header += scale_compact(len(license)) + license.encode()
    header += scale_compact(len(author)) + author.encode()

    return header + jam

corevm = wrap_corevm('service.jam', 'my-service', '0.1.0', 'MIT', 'rotko')
with open('service.corevm', 'wb') as f:
    f.write(corevm)
EOF
```

## corevm format

two formats exist, both accepted by jamt:

### P format (preferred)

```
0x50 'P'                    # magic byte
SCALE-compact name_len      # length << 2 for values < 64
name bytes
SCALE-compact version_len
version bytes
SCALE-compact license_len
license bytes
SCALE-compact author_len
author bytes
PVM blob                    # starts with "PVM\0"
```

example header for "blc-lambda":
```
50 28 62 6c 63 2d 6c 61 6d 62 64 61 14 30 2e 31 2e 30 0c 4d 49 54 14 72 6f 74 6b 6f
P  10 b  l  c  -  l  a  m  b  d  a  5  0  .  1  .  0  3  M  I  T  5  r  o  t  k  o
```

### < format (doom.corevm style)

```
0x3c 0x00                   # format marker
1-byte name_len
name bytes
1-byte version_len
version bytes
1-byte license_len
license bytes
0x01                        # type byte
1-byte author_len
author bytes
PVM blob
```

## deploying to testnet

### start romio testnet

```bash
./bin/romio testnet
# or: julia --project=. -e 'using JAM; JAM.JuliaJAMTestnet.run()'
```

### deploy jam service

```bash
# create service (returns service id)
jamt --rpc ws://localhost:19800 create-service ./service.corevm

# with initial balance
jamt --rpc ws://localhost:19800 create-service ./service.corevm 1000000
```

### deploy corevm service

```bash
# for interactive services like doom
jamt --rpc ws://localhost:19800 vm new ./doom.corevm 1000000000

# with command line args
jamt --rpc ws://localhost:19800 vm new ./app.corevm 1000000 -- arg1 arg2
```

### query service

```bash
# inspect service storage
jamt --rpc ws://localhost:19800 inspect storage <service_id>

# check service state
jamt --rpc ws://localhost:19800 inspect service <service_id>
```

## minimal service example

```c
#include <stdint.h>

// jam entry points
void _jb_entry_refine(void);
void _jb_entry_accumulate(void);

// host calls
extern uint64_t gas(void);
extern void write(uint32_t service, const uint8_t* key, uint32_t key_len,
                  const uint8_t* value, uint32_t value_len);

void _jb_entry_refine(void) {
    // pure computation - no state access
    // result goes to accumulate
}

void _jb_entry_accumulate(void) {
    // state updates
    uint8_t key[] = "counter";
    uint8_t value[] = {1, 0, 0, 0};
    write(0, key, 7, value, 4);
}
```

## host function details

### fetch discriminators

the `fetch` function uses discriminators to select what data to retrieve:

| discriminator | value | returns |
|---------------|-------|---------|
| `CHAIN_PARAMS` | 0 | chain configuration |
| `CHAIN_ENTROPY32` | 1 | 32-byte random entropy |
| `AUTH_TRACE` | 2 | authorization trace |
| `NTH_ITEM_PAYLOAD` | 13 | nth work item payload |
| `INPUTS` | 14 | refine inputs |

### error codes

host functions return error codes:

| code | name | meaning |
|------|------|---------|
| 0 | `OK` | success |
| -1 | `NONE` | not found |
| -2 | `WHAT` | invalid argument |
| -3 | `OOB` | out of bounds |
| -4 | `WHO` | unknown service |
| -5 | `FULL` | storage full |
| -6 | `CORE` | core error |
| -7 | `CASH` | insufficient funds |
| -8 | `LOW` | insufficient gas |
| -9 | `HUH` | unknown error |

see graypaper appendix for full host function specifications.
