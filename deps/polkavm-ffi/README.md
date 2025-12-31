# polkavm-ffi

C FFI bindings for [PolkaVM](https://github.com/koute/polkavm) - execute PVM programs from any language.

## Overview

This crate provides a C-compatible FFI layer for PolkaVM, enabling:
- Loading and compiling PVM blobs
- JIT or interpreter execution
- Gas metering
- Memory read/write
- Register access
- Step tracing for debugging

## Usage from C/C++

```c
#include <stdint.h>

// Opaque handles
typedef void* PvmEngine;
typedef void* PvmModule;
typedef void* PvmInstance;

typedef struct {
    uint32_t status;      // 0=HALT, 1=PANIC, 2=OOG, 3=FAULT, 4=HOST, 5=STEP
    int64_t gas_remaining;
    uint32_t host_call;
} PvmResult;

// Load and run a PVM program
PvmEngine engine = pvm_engine_new();
PvmModule module = pvm_module_new(engine, blob_data, blob_len);
PvmInstance instance = pvm_instance_new(engine, module);

pvm_instance_set_gas(instance, 1000000);
pvm_instance_prepare_call(instance, entry_pc);
PvmResult result = pvm_instance_run(instance);

if (result.status == 0) {
    // Program completed successfully
    uint64_t ret = pvm_instance_get_reg(instance, 7); // A0
}

// Cleanup
pvm_instance_free(instance);
pvm_module_free(module);
pvm_engine_free(engine);
```

## Usage from Julia

```julia
using Libdl

const libpvm = dlopen("libpolkavm_ffi.so")

# Function bindings
pvm_engine_new = dlsym(libpvm, :pvm_engine_new)
pvm_module_new = dlsym(libpvm, :pvm_module_new)
pvm_instance_new = dlsym(libpvm, :pvm_instance_new)
pvm_instance_set_gas = dlsym(libpvm, :pvm_instance_set_gas)
pvm_instance_run = dlsym(libpvm, :pvm_instance_run)

# Load and run
engine = @ccall $pvm_engine_new()::Ptr{Cvoid}
module = @ccall $pvm_module_new(engine::Ptr{Cvoid}, blob::Ptr{UInt8}, len::Csize_t)::Ptr{Cvoid}
instance = @ccall $pvm_instance_new(engine::Ptr{Cvoid}, module::Ptr{Cvoid})::Ptr{Cvoid}

@ccall $pvm_instance_set_gas(instance::Ptr{Cvoid}, 1_000_000::Int64)::Cvoid
result = @ccall $pvm_instance_run(instance::Ptr{Cvoid})::NTuple{3,UInt32}
```

## API Reference

### Engine

- `pvm_engine_new()` - Create engine with JIT backend
- `pvm_engine_new_interpreter()` - Create engine with interpreter backend
- `pvm_engine_free(engine)` - Free engine

### Module

- `pvm_module_new(engine, blob, len)` - Load module from PVM blob
- `pvm_module_new_step(engine, blob, len)` - Load with step tracing enabled
- `pvm_module_free(module)` - Free module
- `pvm_module_memory_info(module)` - Get memory map info
- `pvm_module_exports_count(module)` - Number of exports
- `pvm_module_export_name(module, idx, buf, len)` - Get export name
- `pvm_module_export_pc(module, idx)` - Get export program counter

### Instance

- `pvm_instance_new(engine, module)` - Create instance
- `pvm_instance_free(instance)` - Free instance
- `pvm_instance_reset(instance)` - Reset to initial state
- `pvm_instance_set_gas(instance, gas)` - Set gas limit
- `pvm_instance_get_gas(instance)` - Get remaining gas
- `pvm_instance_set_reg(instance, reg, value)` - Set register
- `pvm_instance_get_reg(instance, reg)` - Get register
- `pvm_instance_get_pc(instance)` - Get program counter
- `pvm_instance_prepare_call(instance, pc)` - Prepare entry point
- `pvm_instance_run(instance)` - Execute until completion/interrupt
- `pvm_instance_read_memory(instance, addr, buf, len)` - Read memory
- `pvm_instance_write_memory(instance, addr, data, len)` - Write memory
- `pvm_instance_sbrk(instance, pages)` - Grow heap
- `pvm_instance_heap_size(instance)` - Get heap size

### Registers

| Index | Register | Purpose |
|-------|----------|---------|
| 0 | RA | Return address |
| 1 | SP | Stack pointer |
| 2-4 | T0-T2 | Temporaries |
| 5-6 | S0-S1 | Saved registers |
| 7-12 | A0-A5 | Arguments/return |

### Execution Status

| Code | Status | Description |
|------|--------|-------------|
| 0 | HALT | Normal completion |
| 1 | PANIC | Trap/panic instruction |
| 2 | OOG | Out of gas |
| 3 | FAULT | Memory access violation |
| 4 | HOST | Host call (ecalli) |
| 5 | STEP | Step trace (debug mode) |

## Features

- `doom` - Enables Doom-specific framebuffer conversion helpers

## Building

```bash
cargo build --release
# Output: target/release/libpolkavm_ffi.so (or .dylib on macOS)
```

## License

MIT OR Apache-2.0
