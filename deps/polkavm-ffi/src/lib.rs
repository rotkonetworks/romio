//! PolkaVM FFI wrapper for Julia
//!
//! Provides C-compatible functions to load and execute PolkaVM programs.

use polkavm::{
    Config, Engine, GasMeteringKind, Instance, Linker, Module, ModuleConfig, ProgramBlob,
    ProgramCounter, Reg,
};
use std::slice;

/// Opaque handle to a PolkaVM engine
pub struct PvmEngine {
    engine: Engine,
}

/// Opaque handle to a compiled module
pub struct PvmModule {
    module: Module,
}

/// Opaque handle to an instance
pub struct PvmInstance {
    instance: Instance<()>,
}

/// Execution result returned to Julia
#[repr(C)]
pub struct PvmResult {
    /// Status: 0 = HALT, 1 = PANIC, 2 = OOG (out of gas), 3 = FAULT, 4 = HOST
    pub status: u32,
    /// Gas remaining after execution
    pub gas_remaining: i64,
    /// For HOST status, the host call number
    pub host_call: u32,
}

/// Create a new PolkaVM engine with JIT backend (default for max performance)
#[no_mangle]
pub extern "C" fn pvm_engine_new() -> *mut PvmEngine {
    // Always use JIT/Compiler backend for best performance
    let mut config = Config::new();
    config.set_backend(Some(polkavm::BackendKind::Compiler));
    match Engine::new(&config) {
        Ok(engine) => Box::into_raw(Box::new(PvmEngine { engine })),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Create a new PolkaVM engine with interpreter backend (for compatibility)
#[no_mangle]
pub extern "C" fn pvm_engine_new_interpreter() -> *mut PvmEngine {
    let mut config = Config::new();
    config.set_backend(Some(polkavm::BackendKind::Interpreter));
    match Engine::new(&config) {
        Ok(engine) => Box::into_raw(Box::new(PvmEngine { engine })),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Load a module with step tracing enabled (for debugging)
#[no_mangle]
pub extern "C" fn pvm_module_new_step(
    engine: *mut PvmEngine,
    blob_ptr: *const u8,
    blob_len: usize,
) -> *mut PvmModule {
    if engine.is_null() || blob_ptr.is_null() {
        return std::ptr::null_mut();
    }

    let engine = unsafe { &(*engine).engine };
    let blob = unsafe { slice::from_raw_parts(blob_ptr, blob_len) };

    // Parse the blob
    let program_blob = match ProgramBlob::parse(blob.into()) {
        Ok(blob) => blob,
        Err(_) => return std::ptr::null_mut(),
    };

    // Configure module with gas metering AND step tracing
    let mut module_config = ModuleConfig::default();
    module_config.set_gas_metering(Some(GasMeteringKind::Sync));
    module_config.set_step_tracing(true);

    // Compile the module
    match Module::from_blob(engine, &module_config, program_blob) {
        Ok(module) => Box::into_raw(Box::new(PvmModule { module })),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Free a PolkaVM engine
#[no_mangle]
pub extern "C" fn pvm_engine_free(engine: *mut PvmEngine) {
    if !engine.is_null() {
        unsafe {
            drop(Box::from_raw(engine));
        }
    }
}

/// Load a module from a blob
#[no_mangle]
pub extern "C" fn pvm_module_new(
    engine: *mut PvmEngine,
    blob_ptr: *const u8,
    blob_len: usize,
) -> *mut PvmModule {
    if engine.is_null() || blob_ptr.is_null() {
        return std::ptr::null_mut();
    }

    let engine = unsafe { &(*engine).engine };
    let blob = unsafe { slice::from_raw_parts(blob_ptr, blob_len) };

    // Parse the blob
    let program_blob = match ProgramBlob::parse(blob.into()) {
        Ok(blob) => blob,
        Err(_) => return std::ptr::null_mut(),
    };

    // Configure module with gas metering
    let mut module_config = ModuleConfig::default();
    module_config.set_gas_metering(Some(GasMeteringKind::Sync));

    // Compile the module
    match Module::from_blob(engine, &module_config, program_blob) {
        Ok(module) => Box::into_raw(Box::new(PvmModule { module })),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Free a module
#[no_mangle]
pub extern "C" fn pvm_module_free(module: *mut PvmModule) {
    if !module.is_null() {
        unsafe {
            drop(Box::from_raw(module));
        }
    }
}

/// Get module memory map info
#[repr(C)]
pub struct PvmMemoryInfo {
    pub ro_data_address: u32,
    pub ro_data_size: u32,
    pub rw_data_address: u32,
    pub rw_data_size: u32,
    pub stack_address_low: u32,
    pub stack_address_high: u32,
    pub heap_base: u32,
}

#[no_mangle]
pub extern "C" fn pvm_module_memory_info(module: *const PvmModule) -> PvmMemoryInfo {
    if module.is_null() {
        return PvmMemoryInfo {
            ro_data_address: 0,
            ro_data_size: 0,
            rw_data_address: 0,
            rw_data_size: 0,
            stack_address_low: 0,
            stack_address_high: 0,
            heap_base: 0,
        };
    }

    let module = unsafe { &(*module).module };
    let mem = module.memory_map();

    PvmMemoryInfo {
        ro_data_address: mem.ro_data_address(),
        ro_data_size: mem.ro_data_size(),
        rw_data_address: mem.rw_data_address(),
        rw_data_size: mem.rw_data_size(),
        stack_address_low: mem.stack_address_low(),
        stack_address_high: mem.stack_address_high(),
        heap_base: mem.heap_base(),
    }
}

/// Create an instance from a module (no host functions linked)
#[no_mangle]
pub extern "C" fn pvm_instance_new(
    engine: *mut PvmEngine,
    module: *mut PvmModule,
) -> *mut PvmInstance {
    if engine.is_null() || module.is_null() {
        return std::ptr::null_mut();
    }

    let _engine = unsafe { &(*engine).engine };
    let module = unsafe { &(*module).module };

    let linker = Linker::<()>::new();

    match linker.instantiate_pre(module) {
        Ok(instance_pre) => match instance_pre.instantiate() {
            Ok(instance) => Box::into_raw(Box::new(PvmInstance { instance })),
            Err(_) => std::ptr::null_mut(),
        },
        Err(_) => std::ptr::null_mut(),
    }
}

/// Free an instance
#[no_mangle]
pub extern "C" fn pvm_instance_free(instance: *mut PvmInstance) {
    if !instance.is_null() {
        unsafe {
            drop(Box::from_raw(instance));
        }
    }
}

/// Set gas for an instance
#[no_mangle]
pub extern "C" fn pvm_instance_set_gas(instance: *mut PvmInstance, gas: i64) {
    if instance.is_null() {
        return;
    }
    let instance = unsafe { &mut (*instance).instance };
    instance.set_gas(gas);
}

/// Get remaining gas from an instance
#[no_mangle]
pub extern "C" fn pvm_instance_get_gas(instance: *const PvmInstance) -> i64 {
    if instance.is_null() {
        return 0;
    }
    let instance = unsafe { &(*instance).instance };
    instance.gas()
}

/// Set a register value
#[no_mangle]
pub extern "C" fn pvm_instance_set_reg(instance: *mut PvmInstance, reg: u32, value: u64) {
    if instance.is_null() {
        return;
    }
    let instance = unsafe { &mut (*instance).instance };
    if let Some(r) = reg_from_u32(reg) {
        instance.set_reg(r, value);
    }
}

/// Get a register value
#[no_mangle]
pub extern "C" fn pvm_instance_get_reg(instance: *const PvmInstance, reg: u32) -> u64 {
    if instance.is_null() {
        return 0;
    }
    let instance = unsafe { &(*instance).instance };
    if let Some(r) = reg_from_u32(reg) {
        instance.reg(r)
    } else {
        0
    }
}

/// Read memory from instance
#[no_mangle]
pub extern "C" fn pvm_instance_read_memory(
    instance: *const PvmInstance,
    address: u32,
    buffer: *mut u8,
    length: u32,
) -> i32 {
    if instance.is_null() || buffer.is_null() {
        return -1;
    }
    let instance = unsafe { &(*instance).instance };
    let buf = unsafe { slice::from_raw_parts_mut(buffer, length as usize) };

    match instance.read_memory_into(address, buf) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

/// Write memory to instance
#[no_mangle]
pub extern "C" fn pvm_instance_write_memory(
    instance: *mut PvmInstance,
    address: u32,
    data: *const u8,
    length: u32,
) -> i32 {
    if instance.is_null() || data.is_null() {
        return -1;
    }
    let instance = unsafe { &mut (*instance).instance };
    let buf = unsafe { slice::from_raw_parts(data, length as usize) };

    match instance.write_memory(address, buf) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

/// Run the instance until completion or host call
/// Returns result with status and gas remaining
#[no_mangle]
pub extern "C" fn pvm_instance_run(instance: *mut PvmInstance) -> PvmResult {
    if instance.is_null() {
        return PvmResult {
            status: 1, // PANIC
            gas_remaining: 0,
            host_call: 0,
        };
    }

    let instance = unsafe { &mut (*instance).instance };

    match instance.run() {
        Ok(polkavm::InterruptKind::Finished) => PvmResult {
            status: 0, // HALT
            gas_remaining: instance.gas(),
            host_call: 0,
        },
        Ok(polkavm::InterruptKind::Trap) => PvmResult {
            status: 1, // PANIC
            gas_remaining: instance.gas(),
            host_call: 0,
        },
        Ok(polkavm::InterruptKind::Ecalli(n)) => PvmResult {
            status: 4, // HOST
            gas_remaining: instance.gas(),
            host_call: n,
        },
        Ok(polkavm::InterruptKind::Segfault(_)) => PvmResult {
            status: 3, // FAULT
            gas_remaining: instance.gas(),
            host_call: 0,
        },
        Ok(polkavm::InterruptKind::NotEnoughGas) => PvmResult {
            status: 2, // OOG
            gas_remaining: instance.gas(),
            host_call: 0,
        },
        Ok(polkavm::InterruptKind::Step) => PvmResult {
            status: 5, // STEP (step tracing mode, continue running)
            gas_remaining: instance.gas(),
            host_call: 0,
        },
        Err(_) => PvmResult {
            status: 1, // PANIC
            gas_remaining: instance.gas(),
            host_call: 0,
        },
    }
}

/// Get program counter
#[no_mangle]
pub extern "C" fn pvm_instance_get_pc(instance: *const PvmInstance) -> u32 {
    if instance.is_null() {
        return 0;
    }
    let instance = unsafe { &(*instance).instance };
    instance.program_counter().map(|pc| pc.0).unwrap_or(0)
}

/// Set program counter (for entry point)
#[no_mangle]
pub extern "C" fn pvm_instance_set_pc(instance: *mut PvmInstance, _pc: u32) {
    if instance.is_null() {
        return;
    }
    // Note: Setting PC directly may not be supported in polkavm public API
    // Use prepare_call_untyped for entry points instead
}

/// Helper to convert register number to Reg enum
fn reg_from_u32(n: u32) -> Option<Reg> {
    match n {
        0 => Some(Reg::RA),
        1 => Some(Reg::SP),
        2 => Some(Reg::T0),
        3 => Some(Reg::T1),
        4 => Some(Reg::T2),
        5 => Some(Reg::S0),
        6 => Some(Reg::S1),
        7 => Some(Reg::A0),
        8 => Some(Reg::A1),
        9 => Some(Reg::A2),
        10 => Some(Reg::A3),
        11 => Some(Reg::A4),
        12 => Some(Reg::A5),
        _ => None,
    }
}

/// Reset instance to initial state
#[no_mangle]
pub extern "C" fn pvm_instance_reset(instance: *mut PvmInstance) {
    if instance.is_null() {
        return;
    }
    let instance = unsafe { &mut (*instance).instance };
    let _ = instance.reset_memory();
    // Reset all registers to 0
    for i in 0..13 {
        if let Some(r) = reg_from_u32(i) {
            instance.set_reg(r, 0);
        }
    }
}

/// Grow heap by specified number of pages
#[no_mangle]
pub extern "C" fn pvm_instance_sbrk(instance: *mut PvmInstance, pages: u32) -> u32 {
    if instance.is_null() {
        return 0;
    }
    let instance = unsafe { &mut (*instance).instance };
    match instance.sbrk(pages) {
        Ok(Some(addr)) => addr,
        Ok(None) => 0,
        Err(_) => 0,
    }
}

/// Get the current heap pointer
#[no_mangle]
pub extern "C" fn pvm_instance_heap_size(instance: *const PvmInstance) -> u32 {
    if instance.is_null() {
        return 0;
    }
    let instance = unsafe { &(*instance).instance };
    instance.heap_size()
}

/// Prepare a call to an exported function by program counter
/// This sets up the entry point - call run() after this
#[no_mangle]
pub extern "C" fn pvm_instance_prepare_call(
    instance: *mut PvmInstance,
    pc: u32,
) -> i32 {
    if instance.is_null() {
        return -1;
    }
    let instance = unsafe { &mut (*instance).instance };

    // prepare_call_untyped takes a ProgramCounter
    instance.prepare_call_untyped(ProgramCounter(pc), &[]);
    0
}

/// Get the number of exports in a module
#[no_mangle]
pub extern "C" fn pvm_module_exports_count(module: *const PvmModule) -> u32 {
    if module.is_null() {
        return 0;
    }
    let module = unsafe { &(*module).module };
    module.exports().count() as u32
}

/// Get export name by index - returns length, writes to buffer
#[no_mangle]
pub extern "C" fn pvm_module_export_name(
    module: *const PvmModule,
    index: u32,
    buffer: *mut u8,
    buffer_len: u32,
) -> i32 {
    if module.is_null() || buffer.is_null() {
        return -1;
    }
    let module = unsafe { &(*module).module };

    if let Some(export) = module.exports().nth(index as usize) {
        let name = export.symbol().as_bytes();
        let copy_len = std::cmp::min(name.len(), buffer_len as usize);
        unsafe {
            std::ptr::copy_nonoverlapping(name.as_ptr(), buffer, copy_len);
        }
        name.len() as i32
    } else {
        -1
    }
}

/// Get export program counter by index
#[no_mangle]
pub extern "C" fn pvm_module_export_pc(module: *const PvmModule, index: u32) -> u32 {
    if module.is_null() {
        return 0;
    }
    let module = unsafe { &(*module).module };

    if let Some(export) = module.exports().nth(index as usize) {
        export.program_counter().0
    } else {
        0
    }
}

/// Read framebuffer from instance and convert indexed color to RGB24
/// Doom format: 1 byte header + 768 byte palette (256*3 RGB) + 64000 indexed pixels
/// Returns 0 on success, -1 on error
#[cfg(feature = "doom")]
#[no_mangle]
pub extern "C" fn pvm_instance_read_framebuffer_rgb24(
    instance: *const PvmInstance,
    fb_address: u32,
    fb_size: u32,
    rgb_buffer: *mut u8,
    rgb_buffer_len: u32,
) -> i32 {
    if instance.is_null() || rgb_buffer.is_null() {
        return -1;
    }

    // Expected Doom framebuffer: 1 + 768 + 64000 = 64769 bytes minimum
    if fb_size < 64769 || rgb_buffer_len < 64000 * 3 {
        return -1;
    }

    let instance = unsafe { &(*instance).instance };
    let rgb_out = unsafe { slice::from_raw_parts_mut(rgb_buffer, rgb_buffer_len as usize) };

    // Read palette (768 bytes at offset 1)
    let mut palette = [0u8; 768];
    if instance.read_memory_into(fb_address + 1, &mut palette).is_err() {
        return -1;
    }

    // Read indexed pixels (64000 bytes at offset 769)
    let mut pixels = [0u8; 64000];
    if instance.read_memory_into(fb_address + 769, &mut pixels).is_err() {
        return -1;
    }

    // Convert indexed to RGB24 - this is the hot loop, now in Rust
    for (i, &idx) in pixels.iter().enumerate() {
        let palette_offset = (idx as usize) * 3;
        let rgb_offset = i * 3;
        if palette_offset + 2 < 768 && rgb_offset + 2 < rgb_out.len() {
            rgb_out[rgb_offset] = palette[palette_offset];
            rgb_out[rgb_offset + 1] = palette[palette_offset + 1];
            rgb_out[rgb_offset + 2] = palette[palette_offset + 2];
        }
    }

    0
}
