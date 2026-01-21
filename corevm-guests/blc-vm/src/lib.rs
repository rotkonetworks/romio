//! blc-vm: binary lambda calculus evaluator for corevm
//!
//! minimal version without dynamic allocation

#![no_std]
#![no_main]

/// refine entry point - evaluates BLC payload
/// for now, just returns input as identity (testing the service works)
#[polkavm_derive::polkavm_export]
extern "C" fn refine(input_ptr: u32, input_len: u32, output_ptr: u32, _output_cap: u32) -> u32 {
    // simple identity - copy input to output
    let input = unsafe { core::slice::from_raw_parts(input_ptr as *const u8, input_len as usize) };
    let output = unsafe { core::slice::from_raw_parts_mut(output_ptr as *mut u8, input_len as usize) };
    output.copy_from_slice(input);
    input_len
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::arch::asm!("unimp", options(noreturn)) }
}
