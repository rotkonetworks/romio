# Register mapping between PVM/JAM registers and native x86-64 registers
# Maps virtual machine registers to physical CPU registers for efficient execution

module RegMap

# PVM/JAM register definitions (following RISC-V-like convention)
@enum Reg::UInt8 begin
    RA = 0   # Return address
    SP = 1   # Stack pointer
    T0 = 2   # Temporary 0
    T1 = 3   # Temporary 1
    T2 = 4   # Temporary 2
    S0 = 5   # Saved register 0
    S1 = 6   # Saved register 1
    A0 = 7   # Argument 0 / Return value
    A1 = 8   # Argument 1
    A2 = 9   # Argument 2
    A3 = 10  # Argument 3
    A4 = 11  # Argument 4
    A5 = 12  # Argument 5
end

# All registers in order
const REG_ALL = [RA, SP, T0, T1, T2, S0, S1, A0, A1, A2, A3, A4, A5]
const REG_COUNT = length(REG_ALL)

# x86-64 native register indices
@enum NativeReg::UInt8 begin
    rax = 0
    rcx = 1
    rdx = 2
    rbx = 3
    rsp = 4  # Stack pointer (not used for guest regs)
    rbp = 5
    rsi = 6
    rdi = 7
    r8 = 8
    r9 = 9
    r10 = 10
    r11 = 11
    r12 = 12
    r13 = 13
    r14 = 14
    r15 = 15
end

# Temporary registers for code generation
const TMP_REG = rcx       # Can be freely used
const AUX_TMP_REG = r15   # Must be saved/restored

# Map PVM register to native x86-64 register
# Optimized assignment: frequently used PVM registers get compact x86-64 encodings
function to_native_reg(reg::Reg)::NativeReg
    # This mapping is carefully chosen for code density:
    # - Common registers (A0, A1, SP) get registers with shorter encodings
    # - rdi, rax, rsi are efficient for common operations
    if reg == A0
        return rdi  # First argument in x86-64 ABI
    elseif reg == A1
        return rax  # Return value register, accumulator
    elseif reg == SP
        return rsi  # Source index
    elseif reg == RA
        return rbx  # Base register (callee-saved)
    elseif reg == A2
        return rdx  # Data register
    elseif reg == A3
        return rbp  # Base pointer (callee-saved)
    elseif reg == S0
        return r8
    elseif reg == S1
        return r9
    elseif reg == A4
        return r10
    elseif reg == A5
        return r11
    elseif reg == T0
        return r13
    elseif reg == T1
        return r14
    elseif reg == T2
        return r12
    else
        error("Unknown register: $reg")
    end
end

# Reverse mapping: native register to PVM register
function to_guest_reg(native::NativeReg)::Union{Reg, Nothing}
    for reg in REG_ALL
        if to_native_reg(reg) == native
            return reg
        end
    end
    return nothing
end

# Check if a native register is mapped to a guest register
function is_guest_reg(native::NativeReg)::Bool
    return to_guest_reg(native) !== nothing
end

# Get register name for debugging
function reg_name(reg::Reg)::String
    names = Dict(
        RA => "ra",
        SP => "sp",
        T0 => "t0",
        T1 => "t1",
        T2 => "t2",
        S0 => "s0",
        S1 => "s1",
        A0 => "a0",
        A1 => "a1",
        A2 => "a2",
        A3 => "a3",
        A4 => "a4",
        A5 => "a5"
    )
    return get(names, reg, "unknown")
end

function native_reg_name(reg::NativeReg)::String
    names = Dict(
        rax => "rax",
        rcx => "rcx",
        rdx => "rdx",
        rbx => "rbx",
        rsp => "rsp",
        rbp => "rbp",
        rsi => "rsi",
        rdi => "rdi",
        r8 => "r8",
        r9 => "r9",
        r10 => "r10",
        r11 => "r11",
        r12 => "r12",
        r13 => "r13",
        r14 => "r14",
        r15 => "r15"
    )
    return get(names, reg, "unknown")
end

# Register classes for allocation
const CALLER_SAVED = [rax, rcx, rdx, rsi, rdi, r8, r9, r10, r11]
const CALLEE_SAVED = [rbx, rbp, r12, r13, r14, r15]

# Check register properties
is_caller_saved(reg::NativeReg) = reg in CALLER_SAVED
is_callee_saved(reg::NativeReg) = reg in CALLEE_SAVED

# Get all native registers used by guest
function guest_native_regs()::Vector{NativeReg}
    return [to_native_reg(reg) for reg in REG_ALL]
end

# Register allocation hints for JIT
struct RegAllocHint
    preferred::NativeReg
    avoid::Vector{NativeReg}
    save_required::Bool
end

# Get allocation hint for a given PVM register
function get_alloc_hint(reg::Reg)::RegAllocHint
    native = to_native_reg(reg)

    # Avoid using guest-mapped registers for temporaries
    avoid = guest_native_regs()

    # Callee-saved registers need save/restore
    save_required = is_callee_saved(native)

    return RegAllocHint(native, avoid, save_required)
end

# Generate register mapping for debugging
function dump_register_mapping()
    println("PVM Register Mapping:")
    println("======================")
    for reg in REG_ALL
        native = to_native_reg(reg)
        saved = is_callee_saved(native) ? " (callee-saved)" : ""
        println("  $(reg_name(reg)) (r$(Int(reg))) -> $(native_reg_name(native))$saved")
    end
    println("\nTemporary registers:")
    println("  TMP_REG: $(native_reg_name(TMP_REG)) (free use)")
    println("  AUX_TMP_REG: $(native_reg_name(AUX_TMP_REG)) (save/restore)")
end

# Verify register mapping consistency
function verify_mapping()::Bool
    # Check no duplicate native registers
    native_regs = guest_native_regs()
    if length(native_regs) != length(unique(native_regs))
        return false
    end

    # Check reverse mapping works
    for reg in REG_ALL
        native = to_native_reg(reg)
        if to_guest_reg(native) != reg
            return false
        end
    end

    # Check temp registers aren't used by guests
    if TMP_REG in native_regs
        return false
    end

    # rsp should never be used for guest registers
    if rsp in native_regs
        return false
    end

    return true
end

export Reg, NativeReg, REG_ALL, REG_COUNT,
       to_native_reg, to_guest_reg, is_guest_reg,
       TMP_REG, AUX_TMP_REG,
       reg_name, native_reg_name,
       CALLER_SAVED, CALLEE_SAVED,
       is_caller_saved, is_callee_saved,
       guest_native_regs, RegAllocHint, get_alloc_hint,
       dump_register_mapping, verify_mapping,
       # Individual register exports
       RA, SP, T0, T1, T2, S0, S1, A0, A1, A2, A3, A4, A5,
       rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi,
       r8, r9, r10, r11, r12, r13, r14, r15

end # module