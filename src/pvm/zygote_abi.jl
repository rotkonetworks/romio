# Zygote ABI - Host-VM boundary definitions matching Rust implementation
# This module defines the exact memory layout and communication protocol

module ZygoteABI

using Base: @kwdef

# File descriptors used by the zygote
const FD_DUMMY_STDIN = Int32(0)
const FD_LOGGER_STDOUT = Int32(1)
const FD_LOGGER_STDERR = Int32(2)
const FD_SHM = Int32(3)           # Shared memory
const FD_MEM = Int32(4)           # Memory file descriptor
const FD_SOCKET = Int32(5)        # Communication socket
const FD_VMCTX = Int32(6)         # VM context memfd
const FD_LIFETIME_PIPE = Int32(7) # Lifetime monitoring pipe
const LAST_USED_FD = FD_LIFETIME_PIPE

# Virtual memory addresses - must match Rust implementation exactly
const VM_ADDR_NATIVE_CODE = UInt64(0x100000000)     # 4GB - Native code start
const VM_ADDR_VMCTX = UInt64(0x400000000)           # 16GB - VM context struct
const VM_ADDR_SIGSTACK = UInt64(0x500000000)        # 20GB - Signal stack
const VM_ADDR_NATIVE_STACK_LOW = UInt64(0x600000000)  # 24GB - Native stack bottom
const VM_ADDR_NATIVE_STACK_SIZE = UInt64(0x4000)    # 16KB stack
const VM_ADDR_NATIVE_STACK_HIGH = VM_ADDR_NATIVE_STACK_LOW + VM_ADDR_NATIVE_STACK_SIZE
const VM_ADDR_SHARED_MEMORY = UInt64(0x700000000)   # 28GB - Shared memory
const VM_ADDR_JUMP_TABLE = UInt64(0x800000000)      # 32GB - Jump table

# Return-to-host jump table address
const VM_ADDR_RETURN_TO_HOST = UInt32(0x1FFE0000)
const VM_ADDR_JUMP_TABLE_RETURN_TO_HOST = VM_ADDR_JUMP_TABLE + (UInt64(VM_ADDR_RETURN_TO_HOST) << 3)

# Size limits
const VM_SHARED_MEMORY_SIZE = UInt64(typemax(UInt32))  # 4GB
const VM_COMPILER_MAXIMUM_INSTRUCTION_LENGTH = UInt32(67)
const VM_SANDBOX_MAXIMUM_JUMP_TABLE_SIZE = UInt64(0x100000)  # Simplified
const VM_SANDBOX_MAXIMUM_JUMP_TABLE_VIRTUAL_SIZE = UInt64(0x800000000)  # 32GB
const VM_SANDBOX_MAXIMUM_NATIVE_CODE_SIZE = UInt32(2176 * 1024 * 1024 - 1)

# Futex states for VM synchronization
const VMCTX_FUTEX_BUSY = UInt32(0)
const VMCTX_FUTEX_IDLE = UInt32(1)
const VMCTX_FUTEX_GUEST_ECALLI = UInt32(VMCTX_FUTEX_IDLE | (1 << 1))
const VMCTX_FUTEX_GUEST_TRAP = UInt32(VMCTX_FUTEX_IDLE | (2 << 1))
const VMCTX_FUTEX_GUEST_SIGNAL = UInt32(VMCTX_FUTEX_IDLE | (3 << 1))
const VMCTX_FUTEX_GUEST_STEP = UInt32(VMCTX_FUTEX_IDLE | (4 << 1))
const VMCTX_FUTEX_GUEST_NOT_ENOUGH_GAS = UInt32(VMCTX_FUTEX_IDLE | (5 << 1))
const VMCTX_FUTEX_GUEST_PAGEFAULT = UInt32(VMCTX_FUTEX_IDLE | (6 << 1))

const MESSAGE_BUFFER_SIZE = 512
const REG_COUNT = 13  # Number of VM registers

# Jump buffer for setjmp/longjmp
mutable struct JmpBuf
    rip::UInt64
    rbx::UInt64
    rsp::UInt64
    rbp::UInt64
    r12::UInt64
    r13::UInt64
    r14::UInt64
    r15::UInt64
end

# VM initialization parameters
@kwdef mutable struct VmInit
    stack_address::UInt64 = 0
    stack_length::UInt64 = 0
    vdso_address::UInt64 = 0
    vdso_length::UInt64 = 0
    vvar_address::UInt64 = 0
    vvar_length::UInt64 = 0
    uffd_available::Bool = false
    sandbox_disabled::Bool = false
    logging_enabled::Bool = false
end

# Heap information
mutable struct VmCtxHeapInfo
    heap_top::UInt64
    heap_threshold::UInt64
end

# Performance counters
mutable struct VmCtxCounters
    syscall_wait_loop_start::UInt64
    syscall_futex_wait::UInt64
end

# Memory map file descriptor type
@enum VmFd::UInt8 begin
    VM_FD_NONE = 0
    VM_FD_SHM = 1
    VM_FD_MEM = 2
end

# Memory map entry
struct VmMap
    address::UInt64
    length::UInt64
    protection::UInt32
    flags::UInt32
    fd::VmFd
    fd_offset::UInt64
end

# Main VM context - must match Rust layout exactly
# This is mapped in shared memory at VM_ADDR_VMCTX
mutable struct VmCtx
    # Cache line 1 (64 bytes)
    _align_1::UInt64  # Alignment padding
    futex::UInt32
    program_counter::UInt32
    jump_into::UInt64
    next_native_program_counter::UInt64
    tmp_reg::UInt64
    rip::UInt64

    # Cache line 2
    next_program_counter::UInt32
    arg::UInt32
    arg2::UInt32
    arg3::UInt32
    _align_2_pad::UInt32  # Padding

    # Dummy alignment array
    _align_dummy::NTuple{4, UInt64}

    # Gas counter at specific offset (0x60 from start)
    gas::Int64

    # Cache line 3 - Registers
    regs::Vector{UInt64}  # 13 registers

    # Heap management
    heap_info::VmCtxHeapInfo

    # Shared memory offsets
    shm_memory_map_offset::UInt64
    shm_memory_map_count::UInt64
    shm_code_offset::UInt64
    shm_code_length::UInt64
    shm_jump_table_offset::UInt64
    shm_jump_table_length::UInt64

    # Configuration
    sysreturn_address::UInt64
    uffd_enabled::Bool
    heap_base::UInt32
    heap_initial_threshold::UInt32
    heap_max_size::UInt32
    page_size::UInt32

    # Performance counters
    counters::VmCtxCounters

    # Initialization parameters
    init::VmInit

    # Error message buffer
    message_length::UInt32
    message_buffer::Vector{UInt8}

    function VmCtx()
        new(
            0,  # _align_1
            VMCTX_FUTEX_BUSY,  # futex
            0,  # program_counter
            0,  # jump_into
            0,  # next_native_program_counter
            0,  # tmp_reg
            0,  # rip
            0,  # next_program_counter
            0,  # arg
            0,  # arg2
            0,  # arg3
            0,  # _align_2_pad
            (0, 0, 0, 0),  # _align_dummy
            0,  # gas
            zeros(UInt64, REG_COUNT),  # regs
            VmCtxHeapInfo(0, 0),  # heap_info
            0,  # shm_memory_map_offset
            0,  # shm_memory_map_count
            0,  # shm_code_offset
            0,  # shm_code_length
            0,  # shm_jump_table_offset
            0,  # shm_jump_table_length
            0,  # sysreturn_address
            false,  # uffd_enabled
            0,  # heap_base
            0,  # heap_initial_threshold
            0,  # heap_max_size
            0,  # page_size
            VmCtxCounters(0, 0),  # counters
            VmInit(),  # init
            0,  # message_length
            zeros(UInt8, MESSAGE_BUFFER_SIZE)  # message_buffer
        )
    end
end

# Address table for syscalls callable from inside VM
struct AddressTable
    syscall_hostcall::UInt64
    syscall_trap::UInt64
    syscall_return::UInt64
    syscall_step::UInt64
    syscall_sbrk::UInt64
    syscall_not_enough_gas::UInt64
end

# External table for functions callable from outside VM
struct ExtTable
    ext_sbrk::UInt64
    ext_reset_memory::UInt64
    ext_zero_memory_chunk::UInt64
    ext_load_program::UInt64
    ext_recycle::UInt64
    ext_set_accessible_aux_size::UInt64
end

# Helper functions for VM context management
function reset_message!(vmctx::VmCtx)
    vmctx.message_length = 0
end

function append_to_message!(vmctx::VmCtx, data::Vector{UInt8})
    available = MESSAGE_BUFFER_SIZE - vmctx.message_length
    to_copy = min(length(data), available)

    if to_copy > 0
        vmctx.message_buffer[vmctx.message_length+1:vmctx.message_length+to_copy] = data[1:to_copy]
        vmctx.message_length += to_copy
    end
end

# Memory protection constants (matching Linux)
const PROT_NONE = UInt32(0)
const PROT_READ = UInt32(1)
const PROT_WRITE = UInt32(2)
const PROT_EXEC = UInt32(4)

# Memory mapping flags
const MAP_FIXED = UInt32(0x10)
const MAP_PRIVATE = UInt32(0x02)
const MAP_SHARED = UInt32(0x01)
const MAP_ANONYMOUS = UInt32(0x20)

# Signal numbers
const SIGSEGV = 11
const SIGBUS = 7
const SIGILL = 4
const SIGFPE = 8
const SIGIO = 29

# Syscall numbers (x86_64)
const SYS_mmap = 9
const SYS_munmap = 11
const SYS_mprotect = 10
const SYS_madvise = 28
const SYS_futex = 202
const SYS_exit = 60
const SYS_write = 1
const SYS_rt_sigreturn = 15
const SYS_sched_yield = 24

# Memory advisories
const MADV_DONTNEED = 4

# Futex operations
const FUTEX_WAIT = 0
const FUTEX_WAKE = 1

# Calculate gas field offset (critical for codegen)
function gas_offset()::Int
    # The gas field must be at exactly 0x60 bytes from start
    return 0x60
end

# Verify structure sizes fit requirements
function verify_layout()
    # VmCtx must fit in single 4KB page
    @assert sizeof(VmCtx) <= 4096 "VmCtx too large for single page"

    # Verify address alignments
    @assert VM_ADDR_JUMP_TABLE_RETURN_TO_HOST > VM_ADDR_JUMP_TABLE
    @assert VM_ADDR_JUMP_TABLE_RETURN_TO_HOST % 0x4000 == 0
    @assert count_ones(VM_ADDR_JUMP_TABLE) == 1  # Power of 2

    # Verify address ranges don't overlap
    @assert VM_ADDR_NATIVE_CODE > 0xffffffff
    @assert VM_ADDR_VMCTX > 0xffffffff
    @assert VM_ADDR_NATIVE_STACK_LOW > 0xffffffff

    return true
end

export VmCtx, VmInit, VmCtxHeapInfo, VmCtxCounters, VmMap, VmFd,
       JmpBuf, AddressTable, ExtTable,
       VM_ADDR_NATIVE_CODE, VM_ADDR_JUMP_TABLE, VM_ADDR_VMCTX,
       VM_ADDR_SHARED_MEMORY, VM_ADDR_SIGSTACK,
       VM_ADDR_NATIVE_STACK_LOW, VM_ADDR_NATIVE_STACK_HIGH,
       VM_ADDR_JUMP_TABLE_RETURN_TO_HOST,
       VMCTX_FUTEX_BUSY, VMCTX_FUTEX_IDLE,
       VMCTX_FUTEX_GUEST_ECALLI, VMCTX_FUTEX_GUEST_TRAP,
       VMCTX_FUTEX_GUEST_SIGNAL, VMCTX_FUTEX_GUEST_STEP,
       VMCTX_FUTEX_GUEST_NOT_ENOUGH_GAS, VMCTX_FUTEX_GUEST_PAGEFAULT,
       FD_SHM, FD_MEM, FD_SOCKET, FD_VMCTX, FD_LIFETIME_PIPE,
       PROT_NONE, PROT_READ, PROT_WRITE, PROT_EXEC,
       MAP_FIXED, MAP_PRIVATE, MAP_SHARED, MAP_ANONYMOUS,
       reset_message!, append_to_message!, verify_layout

end # module