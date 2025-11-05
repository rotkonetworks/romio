# src/pvm/host_calls.jl
# Host call interface for PVM as per Gray Paper specification

"""
Host Call Interface for the Polka Virtual Machine (PVM)

This module implements the host call interface that allows PVM code to interact
with the JAM chain state. There are three invocation contexts:
1. Is-Authorized: Stateless validation (limited host calls)
2. Refine: Work package refinement with historical lookup
3. Accumulate: Full state access for service execution

Host calls are invoked via special instruction and are identified by a call ID.
Each host call has specific gas costs and can return various result codes.
"""

module HostCalls

using StaticArrays

# Import BLAKE2b - REQUIRED, no fallback
# Security-critical: never silently degrade to insecure hash functions
include("../crypto/Blake2b.jl")

# Import unified accumulate types
# These types are now centralized in src/types/accumulate.jl
include("../types/accumulate.jl")

# ===== Host Call IDs =====
# General functions (available in all contexts)
const GAS = 0
const FETCH = 1
const LOOKUP = 2
const READ = 3
const WRITE = 4
const INFO = 5

# Refine functions (available in Refine and Is-Authorized contexts)
const HISTORICAL_LOOKUP = 6
const EXPORT = 7
const MACHINE = 8
const PEEK = 9
const POKE = 10
const PAGES = 11
const INVOKE = 12
const EXPUNGE = 13

# Accumulate functions (only in Accumulate context)
const BLESS = 14
const ASSIGN = 15
const DESIGNATE = 16
const CHECKPOINT = 17
const NEW = 18
const UPGRADE = 19
const TRANSFER = 20
const EJECT = 21
const QUERY = 22
const SOLICIT = 23
const FORGET = 24
const YIELD = 25
const PROVIDE = 26

# ===== Return Codes =====
const OK = UInt64(0)                              # Success
const NONE = typemax(UInt64)                      # Item does not exist (2^64 - 1)
const WHAT = typemax(UInt64) - UInt64(1)         # Name/function unknown (2^64 - 2)
const OOB = typemax(UInt64) - UInt64(2)          # Memory index not accessible (2^64 - 3)
const WHO = typemax(UInt64) - UInt64(3)          # Index unknown (2^64 - 4)
const FULL = typemax(UInt64) - UInt64(4)         # Storage full / insufficient balance (2^64 - 5)
const CORE = typemax(UInt64) - UInt64(5)         # Core index unknown (2^64 - 6)
const CASH = typemax(UInt64) - UInt64(6)         # Insufficient funds (2^64 - 7)
const LOW = typemax(UInt64) - UInt64(7)          # Gas limit too low (2^64 - 8)
const HUH = typemax(UInt64) - UInt64(8)          # Invalid operation/parameter (2^64 - 9)

# ===== Unified Types =====
#
# All accumulate types now imported from src/types/accumulate.jl:
# - PreimageRequest: 4-state machine ([], [x], [x,y], [x,y,z])
# - DeferredTransfer: balance transfer with memo
# - ServiceAccount: complete 14-field service account
# - PrivilegedState: chain-level privileged services
# - ImplicationsContext: mutable state tracking (imX/imY)
# - HostCallContext: host call execution context
#
# These are now centralized and used across the entire codebase.
# See docs/TYPE_UNIFICATION.md for details.

# ===== Constants =====

const Cexpungeperiod = 19200  # timeslots after which unreferenced preimages can be expunged
const Cauthqueuesize = 80     # authorization queue size
const Cvalcount = 1023        # validator count
const Cmemosize = 128         # transfer memo size (bytes)
const Cminpublicindex = 2^16  # minimum public service index
const Ccorecount = 2          # tiny chainspec (will be 341 in production)

# ===== Helper Functions =====

"""
Create a minimal service account for testing
"""
function create_service_account(
    code_hash::Vector{UInt8},
    balance::UInt64 = 0,
    min_balance::UInt64 = 0
)::ServiceAccount
    return ServiceAccount(
        code_hash,
        Dict{Vector{UInt8}, Vector{UInt8}}(),  # storage
        Dict{Vector{UInt8}, Vector{UInt8}}(),  # preimages
        Dict{Tuple{Vector{UInt8}, UInt64}, PreimageRequest}(),  # requests
        balance,
        min_balance,
        0,  # min_acc_gas
        0,  # min_memo_gas
        0,  # octets
        0,  # items
        0,  # gratis
        0,  # created
        0,  # last_acc
        0   # parent
    )
end

"""
Create default privileged state for testing
"""
function create_privileged_state()::PrivilegedState
    return PrivilegedState(
        0,  # manager
        fill(UInt32(0), Ccorecount),  # assigners
        0,  # delegator
        0,  # registrar
        Vector{Vector{UInt8}}(),  # staging_set
        [Vector{Vector{UInt8}}() for _ in 1:Ccorecount],  # auth_queue
        Vector{Tuple{UInt32, UInt64}}()  # always_access
    )
end

"""
Create implications context for testing
"""
function create_implications_context(
    service_id::UInt32,
    service_account::ServiceAccount,
    accounts::Dict{UInt32, ServiceAccount},
    privileged_state::PrivilegedState,
    current_time::UInt32 = 0
)::ImplicationsContext
    return ImplicationsContext(
        service_id,
        service_account,
        privileged_state,
        accounts,
        Vector{DeferredTransfer}(),  # transfers
        Set{Tuple{UInt32, Vector{UInt8}}}(),  # provisions
        nothing,  # yield_hash
        Cminpublicindex,  # next_free_id
        current_time,  # current_time
        nothing  # exceptional_state
    )
end

# ===== Encoding Helpers =====

"""
Compute BLAKE2b-256 hash of data
Uses RFC 7693 BLAKE2b implementation - REQUIRED for security
"""
function blake2b_256(data::Vector{UInt8})::Vector{UInt8}
    output = zeros(UInt8, 32)
    Blake2b!(output, 32, UInt8[], 0, data, length(data))
    return output
end

"""
Encode a UInt64 value in little-endian format
"""
function encode_u64(val::UInt64)::Vector{UInt8}
    return [UInt8((val >> (8*i)) & 0xFF) for i in 0:7]
end

"""
Encode a UInt32 value in little-endian format
"""
function encode_u32(val::UInt32)::Vector{UInt8}
    return [UInt8((val >> (8*i)) & 0xFF) for i in 0:3]
end

"""
Encode a UInt16 value in little-endian format
"""
function encode_u16(val::UInt16)::Vector{UInt8}
    return [UInt8((val >> (8*i)) & 0xFF) for i in 0:1]
end

"""
Encode a hash (32 bytes)
"""
function encode_hash(hash::Vector{UInt8})::Vector{UInt8}
    if length(hash) != 32
        return zeros(UInt8, 32)
    end
    return hash
end

# ===== Memory Helper Functions =====

"""
Check if memory range is readable
memory_permissions is indexed by page (4096 bytes per page)
"""
function is_readable(memory_permissions, offset::UInt32, len::UInt32)
    # Check if range [offset, offset+len) is readable
    if len == 0
        return true
    end

    end_addr = offset + len - 1  # inclusive end
    start_page = div(offset, 4096)
    end_page = div(end_addr, 4096)

    # Check all pages in the range
    for page in start_page:end_page
        page_idx = page + 1  # Julia 1-indexed
        if page_idx > Base.length(memory_permissions)
            return false
        end
        perm = memory_permissions[page_idx]
        if perm === nothing || perm == :none
            return false
        end
    end
    return true
end

"""
Check if memory range is writable
memory_permissions is indexed by page (4096 bytes per page)
"""
function is_writable(memory_permissions, offset::UInt32, len::UInt32)
    # Check if range [offset, offset+len) is writable
    if len == 0
        return true
    end

    end_addr = offset + len - 1  # inclusive end
    start_page = div(offset, 4096)
    end_page = div(end_addr, 4096)

    # Check all pages in the range
    for page in start_page:end_page
        page_idx = page + 1  # Julia 1-indexed
        if page_idx > Base.length(memory_permissions)
            return false
        end
        perm = memory_permissions[page_idx]
        if perm !== :W  # WRITE constant from pvm.jl
            return false
        end
    end
    return true
end

# ===== Host Call Dispatcher =====

"""
    dispatch_host_call(call_id, state, context, invocation_type)

Dispatch a host call to the appropriate handler function.

Arguments:
- call_id: The host call identifier (0-26)
- state: PVM state (gas, registers, memory, etc.)
- context: Invocation context (varies by type)
- invocation_type: :is_authorized, :refine, or :accumulate

Returns: Updated state
"""
function dispatch_host_call(call_id::Int, state, context, invocation_type::Symbol)
    # All host calls cost at least 10 gas (base cost)
    # Additional costs may be added by specific functions

    if call_id == 100
        # Test-only host call
        state.gas -= 10
        if state.gas < 0
            state.status = :oog
            return state
        end
        state.registers[8] = 0  # Return OK (0)
        # Status remains :host so execution resumes
        return state
    end

    if call_id == GAS
        return host_call_gas(state, context)
    elseif call_id == FETCH
        return host_call_fetch(state, context, invocation_type)
    elseif call_id == LOOKUP
        return host_call_lookup(state, context)
    elseif call_id == READ
        return host_call_read(state, context)
    elseif call_id == WRITE
        return host_call_write(state, context)
    elseif call_id == INFO
        return host_call_info(state, context)
    elseif call_id == HISTORICAL_LOOKUP && invocation_type in [:refine, :is_authorized]
        return host_call_historical_lookup(state, context)
    elseif call_id == EXPORT && invocation_type in [:refine, :is_authorized]
        return host_call_export(state, context)
    elseif call_id == MACHINE && invocation_type in [:refine, :is_authorized]
        return host_call_machine(state, context)
    elseif call_id == PEEK && invocation_type in [:refine, :is_authorized]
        return host_call_peek(state, context)
    elseif call_id == POKE && invocation_type in [:refine, :is_authorized]
        return host_call_poke(state, context)
    elseif call_id == PAGES && invocation_type in [:refine, :is_authorized]
        return host_call_pages(state, context)
    elseif call_id == INVOKE && invocation_type in [:refine, :is_authorized]
        return host_call_invoke(state, context)
    elseif call_id == EXPUNGE && invocation_type in [:refine, :is_authorized]
        return host_call_expunge(state, context)
    elseif call_id == BLESS && invocation_type == :accumulate
        return host_call_bless(state, context)
    elseif call_id == ASSIGN && invocation_type == :accumulate
        return host_call_assign(state, context)
    elseif call_id == DESIGNATE && invocation_type == :accumulate
        return host_call_designate(state, context)
    elseif call_id == CHECKPOINT && invocation_type == :accumulate
        return host_call_checkpoint(state, context)
    elseif call_id == NEW && invocation_type == :accumulate
        return host_call_new(state, context)
    elseif call_id == UPGRADE && invocation_type == :accumulate
        return host_call_upgrade(state, context)
    elseif call_id == TRANSFER && invocation_type == :accumulate
        return host_call_transfer(state, context)
    elseif call_id == EJECT && invocation_type == :accumulate
        return host_call_eject(state, context)
    elseif call_id == QUERY && invocation_type == :accumulate
        return host_call_query(state, context)
    elseif call_id == SOLICIT && invocation_type == :accumulate
        return host_call_solicit(state, context)
    elseif call_id == FORGET && invocation_type == :accumulate
        return host_call_forget(state, context)
    elseif call_id == YIELD && invocation_type == :accumulate
        return host_call_yield(state, context)
    elseif call_id == PROVIDE && invocation_type == :accumulate
        return host_call_provide(state, context)
    else
        # Unknown host call or invalid for this invocation type
        # Charge base gas and return WHAT error
        state.gas -= 10
        if state.gas < 0
            state.status = :oog
            return state
        end
        state.registers[8] = WHAT  # r7 in spec (0-indexed) = register 8 (1-indexed)
        return state
    end
end

# ===== Host Call Implementations =====
# Note: All implementations follow the spec from Gray Paper Appendix B

"""
    host_call_gas(state, context)

Host call 0: gas
Returns the remaining gas in r7.
Gas cost: 10
"""
function host_call_gas(state, context)
    # Charge gas
    state.gas -= 10
    if state.gas < 0
        state.status = :oog
        return state
    end

    # r7 = remaining gas after this call
    state.registers[8] = UInt64(state.gas)  # r7 in spec = register 8 (1-indexed)
    return state
end

"""
    host_call_fetch(state, context, invocation_type)

Host call 1: fetch
Fetch environment data based on selector in r10.

Registers:
- r7: output offset (o)
- r8: source offset within fetched data (f)
- r9: length to copy (l)
- r10: selector (0-15)
- r11, r12: additional indices for some selectors

Returns:
- r7: length of available data, or NONE if not available
- memory[o:o+l]: filled with data[f:f+l]
"""
function host_call_fetch(state, context, invocation_type)
    # Charge gas
    state.gas -= 10
    if state.gas < 0
        state.status = :oog
        return state
    end

    # Get parameters from registers
    output_offset = state.registers[8]  # r7
    source_offset = state.registers[9]  # r8
    copy_length = state.registers[10]   # r9
    selector = state.registers[11]      # r10
    idx1 = state.registers[12]          # r11
    idx2 = state.registers[13]          # r12

    step = something(get(task_local_storage(), :pvm_step_count, nothing), 0)
    if step > 280 || selector != 0
        println("    [FETCH step=$step] selector=$selector, idx1=$idx1, idx2=$idx2, out=0x$(string(output_offset, base=16)), src=$source_offset, len=$copy_length")
    end

    # Determine what data to fetch based on selector
    data = nothing

    if selector == 0
        # Configuration constants (from tiny chainspec)
        data = encode_config_constants()
        println("    [FETCH] selector=0 (config) returned $(length(data)) bytes")
    elseif selector == 1
        # Entropy/timeslot hash (n)
        if context.entropy !== nothing
            data = context.entropy
        end
    elseif selector == 2
        # Recent blocks (r)
        if context.recent_blocks !== nothing && length(context.recent_blocks) > 0
            # Encode as sequence of hashes
            data = vcat(context.recent_blocks...)
        end
    elseif selector == 7
        # Work package encoded (p)
        if context.work_package !== nothing
            data = encode_work_package(context.work_package)
        end
    elseif selector == 14
        # All accumulate inputs (work results) encoded: encode(var(i))
        if context.work_package !== nothing && haskey(context.work_package, :results)
            results = context.work_package[:results]
            # Encode as JAM sequence: JAM compact length + items
            include("../encoding/jam.jl")
            data = UInt8[]
            # Encode length as JAM compact integer
            append!(data, encode_jam_compact(length(results)))
            # Append each result (each is already JAM-encoded operandtuple)
            for result in results
                # Each result is a blob, encode with JAM var(x) = len + data
                append!(data, encode_jam_blob(result))
            end
            println("    [FETCH] selector=14 (all inputs) returned $(length(results)) items, $(length(data)) bytes total")
        end
    elseif selector == 15
        # Specific accumulate input at index idx1: encode(i[idx1])
        if context.work_package !== nothing && haskey(context.work_package, :results)
            results = context.work_package[:results]
            if idx1 < length(results)
                # Julia is 1-indexed, return the raw operandtuple (already JAM-encoded)
                data = results[idx1 + 1]
                println("    [FETCH] selector=15 (input[$idx1]) returned $(length(data)) bytes")
            else
                println("    [FETCH] selector=15 (input[$idx1]) OUT OF BOUNDS (have $(length(results)) items)")
            end
        end
    # TODO: Implement other selectors (3-6, 8-13) as needed
    end

    # If data is not available, return NONE
    if data === nothing
        step = something(get(task_local_storage(), :pvm_step_count, nothing), 0)
        println("    [FETCH step=$step] selector=$selector returned NONE (no data available) - SERVICE WILL LIKELY ERROR!")
        state.registers[8] = NONE
        return state
    end

    # println("    [FETCH] selector=$selector returned $(length(data)) bytes")

    # Calculate actual offsets and length
    total_length = length(data)
    f = min(UInt64(source_offset), UInt64(total_length))
    l = min(UInt64(copy_length), UInt64(total_length - f))

    # Check if output memory is writable
    if !is_writable(state.memory.access, UInt32(output_offset), UInt32(l))
        state.status = :panic
        return state
    end

    # Copy data to memory (optimized bulk copy)
    if l > 0
        # Calculate safe copy range
        src_start = Int(f) + 1
        src_end = min(Int(f + l), total_length)
        dst_start = Int(output_offset) + 1
        dst_end = min(Int(output_offset + l), length(state.memory.data))
        copy_len = min(src_end - src_start + 1, dst_end - dst_start + 1)

        if copy_len > 0
            # Bulk copy - much faster than byte-by-byte
            copyto!(state.memory.data, dst_start, data, src_start, copy_len)
        end
    end

    # Return total length of available data in r7
    state.registers[8] = UInt64(total_length)
    return state
end

"""
Encode JAM configuration constants for fetch selector 0.
Uses "tiny" chainspec values for testing.
"""
function encode_config_constants()::Vector{UInt8}
    # Configuration constants from tiny chainspec
    # These are test values - adjust based on actual chainspec
    result = UInt8[]

    append!(result, encode_u64(UInt64(10)))      # C_I: item_deposit
    append!(result, encode_u64(UInt64(1)))       # C_B: byte_deposit
    append!(result, encode_u64(UInt64(100)))     # C_D: base_deposit
    append!(result, encode_u16(UInt16(2)))       # C_C: core_count (tiny=2)
    append!(result, encode_u32(UInt32(32)))      # C_P: expunge_period (tiny=32)
    append!(result, encode_u32(UInt32(12)))      # C_E: epoch_len (tiny=12)
    append!(result, encode_u64(UInt64(1000000000)))  # C_R: report_acc_gas
    append!(result, encode_u64(UInt64(1000000)))     # C_A: package_auth_gas
    append!(result, encode_u64(UInt64(5000000000)))  # C_F: package_ref_gas
    append!(result, encode_u64(UInt64(20000000)))    # C_G: block_acc_gas
    append!(result, encode_u16(UInt16(8)))       # C_H: recent_history_len
    append!(result, encode_u16(UInt16(128)))     # C_W: max_package_items
    append!(result, encode_u16(UInt16(8)))       # C_Q: max_report_deps
    append!(result, encode_u16(UInt16(3)))       # C_M: max_block_tickets (tiny=3)
    append!(result, encode_u32(UInt32(24)))      # C_L: max_lookup_anchorage
    append!(result, encode_u16(UInt16(6)))       # C_T: ticket_entries
    append!(result, encode_u16(UInt16(12)))      # C_O: auth_pool_size
    append!(result, encode_u16(UInt16(6)))       # C_S: slot_seconds
    append!(result, encode_u16(UInt16(16)))      # C_U: auth_queue_size
    append!(result, encode_u16(UInt16(4)))       # C_K: rotation_period (tiny=4)
    append!(result, encode_u16(UInt16(256)))     # C_X: max_package_exts
    append!(result, encode_u16(UInt16(10)))      # C_N: assurance_timeout_period
    append!(result, encode_u16(UInt16(6)))       # C_V: val_count (tiny=6)
    append!(result, encode_u32(UInt32(16384)))   # C_Z: max_auth_code_size
    append!(result, encode_u32(UInt32(13794305))) # C_Y: max_bundle_size (updated from spec)
    append!(result, encode_u32(UInt32(4194304))) # max_service_code_size
    append!(result, encode_u32(UInt32(4104)))    # C_J: ec_piece_size
    append!(result, encode_u32(UInt32(128)))     # max_package_imports
    append!(result, encode_u32(UInt32(1026)))    # C_J: segment_ec_pieces (tiny=1026)
    append!(result, encode_u32(UInt32(4194304))) # max_report_var_size
    append!(result, encode_u32(UInt32(128)))     # C_m: memo_size
    append!(result, encode_u32(UInt32(128)))     # max_package_exports
    append!(result, encode_u32(UInt32(8)))       # C_e: epoch_tail_start

    return result
end

"""
Encode work package (simplified for basic testing)
"""
function encode_work_package(pkg::Dict{Symbol, Any})::Vector{UInt8}
    # Simplified encoding - expand as needed
    result = UInt8[]
    # This is a placeholder - actual encoding would be more complex
    return result
end

"""
    host_call_lookup(state, context)

Host call 2: lookup
Preimage lookup in service account storage.

Registers:
- r7: service ID (2^64-1 for self)
- r8: hash offset in memory (32 bytes)
- r9: output offset
- r10: source offset in preimage
- r11: length to copy

Returns in r7: total length of preimage (or NONE if not found)
Gas cost: 10
"""
function host_call_lookup(state, context)
    # Charge gas
    state.gas -= 10
    if state.gas < 0
        state.status = :oog
        return state
    end

    # Get parameters
    service_id_param = state.registers[8]   # r7
    hash_offset = state.registers[9]        # r8
    output_offset = state.registers[10]     # r9
    source_offset = state.registers[11]     # r10
    copy_length = state.registers[12]       # r11

    # Check context
    if context === nothing || context.accounts === nothing
        state.registers[8] = NONE
        return state
    end

    # Determine target service
    target_service_id = if service_id_param == typemax(UInt64)
        context.service_id
    else
        UInt32(service_id_param)
    end

    # Look up account
    if !haskey(context.accounts, target_service_id)
        state.registers[8] = NONE
        return state
    end

    account = context.accounts[target_service_id]

    # Check if hash memory is readable
    if !is_readable(state.memory.access, UInt32(hash_offset), UInt32(32))
        state.status = :panic
        return state
    end

    # Read hash from memory (32 bytes)
    hash = state.memory.data[hash_offset+1:hash_offset+32]

    # Look up preimage
    if !haskey(account.preimages, hash)
        state.registers[8] = NONE
        return state
    end

    preimage = account.preimages[hash]
    total_length = length(preimage)

    # Calculate actual copy parameters
    actual_source_offset = min(source_offset, UInt64(total_length))
    actual_length = min(copy_length, UInt64(total_length) - actual_source_offset)

    # Check if output memory is writable
    if !is_writable(state.memory.access, UInt32(output_offset), UInt32(actual_length))
        state.status = :panic
        return state
    end

    # Copy preimage to memory
    for i in 0:(actual_length-1)
        src_idx = actual_source_offset + i + 1
        dst_idx = output_offset + i + 1
        if src_idx <= length(preimage) && dst_idx <= length(state.memory.data)
            state.memory.data[dst_idx] = preimage[src_idx]
        end
    end

    # Return total length in r7
    state.registers[8] = UInt64(total_length)
    return state
end

"""
    host_call_read(state, context)

Host call 3: read
Read from service account storage.

Registers:
- r7: service ID (2^64-1 for self)
- r8: key offset in memory
- r9: key length
- r10: output offset
- r11: source offset in value
- r12: length to copy

Returns in r7: total length of value (or NONE if key doesn't exist)
Gas cost: 10
"""
function host_call_read(state, context)
    # Charge gas
    state.gas -= 10
    if state.gas < 0
        state.status = :oog
        return state
    end

    # Get parameters
    service_id_param = state.registers[8]   # r7
    key_offset = state.registers[9]         # r8
    key_length = state.registers[10]        # r9
    output_offset = state.registers[11]     # r10
    value_source_offset = state.registers[12]  # r11
    copy_length = state.registers[13]       # r12

    # Check context
    if context === nothing || context.accounts === nothing
        state.registers[8] = NONE
        return state
    end

    # Determine target service
    target_service_id = if service_id_param == typemax(UInt64)
        context.service_id
    else
        UInt32(service_id_param)
    end

    # Look up account
    if !haskey(context.accounts, target_service_id)
        state.registers[8] = NONE
        return state
    end

    account = context.accounts[target_service_id]

    # Check if key memory is readable
    if !is_readable(state.memory.access, UInt32(key_offset), UInt32(key_length))
        state.status = :panic
        return state
    end

    # Read key from memory
    key = state.memory.data[key_offset+1:key_offset+key_length]

    # Look up value in storage
    if !haskey(account.storage, key)
        state.registers[8] = NONE
        return state
    end

    value = account.storage[key]
    total_length = length(value)

    # Calculate actual copy parameters
    actual_source_offset = min(value_source_offset, UInt64(total_length))
    actual_length = min(copy_length, UInt64(total_length) - actual_source_offset)

    # Check if output memory is writable
    if !is_writable(state.memory.access, UInt32(output_offset), UInt32(actual_length))
        state.status = :panic
        return state
    end

    # Copy value to memory
    for i in 0:(actual_length-1)
        src_idx = actual_source_offset + i + 1
        dst_idx = output_offset + i + 1
        if src_idx <= length(value) && dst_idx <= length(state.memory.data)
            state.memory.data[dst_idx] = value[src_idx]
        end
    end

    # Return total length in r7
    state.registers[8] = UInt64(total_length)
    return state
end

"""
    host_call_write(state, context)

Host call 4: write
Write to service account storage.

Registers:
- r7: key offset in memory
- r8: key length
- r9: value offset in memory
- r10: value length (0 to delete the key)

Returns in r7: previous value length (or NONE if key didn't exist, or FULL if insufficient balance)
Gas cost: 10
"""
function host_call_write(state, context)
    # Charge gas
    state.gas -= 10
    if state.gas < 0
        state.status = :oog
        return state
    end

    # Get parameters
    key_offset = state.registers[8]    # r7
    key_length = state.registers[9]    # r8
    value_offset = state.registers[10] # r9
    value_length = state.registers[11] # r10


    # Check context
    if context === nothing || context.implications === nothing
        state.registers[8] = NONE
        return state
    end

    account = context.implications.self

    # Check if key memory is readable
    if !is_readable(state.memory.access, UInt32(key_offset), UInt32(key_length))
        state.status = :panic
        return state
    end

    # Read key from memory
    key = state.memory.data[key_offset+1:key_offset+key_length]

    # Check if value exists (for return value)
    old_value_length = if haskey(account.storage, key)
        UInt64(length(account.storage[key]))
    else
        NONE
    end

    if value_length == 0
        # Delete the key
        if haskey(account.storage, key)
            delete!(account.storage, key)
            account.items -= 1
            # Update octets (remove key and value sizes)
            account.octets -= UInt64(34 + length(key) + length(account.storage[key]))
        end
    else
        # Check if value memory is readable
        if !is_readable(state.memory.access, UInt32(value_offset), UInt32(value_length))
            state.status = :panic
            return state
        end

        # Read value from memory
        value = state.memory.data[value_offset+1:value_offset+value_length]

        # Calculate new storage size
        new_octets_delta = if haskey(account.storage, key)
            # Updating existing key: only value size changes
            UInt64(length(value) - length(account.storage[key]))
        else
            # New key: add key overhead + key size + value size
            UInt64(34 + length(key) + length(value))
        end

        # Check if account has sufficient balance
        # (Simplified: just check if min_balance threshold would be exceeded)
        # In full implementation, would need to calculate actual min_balance requirement
        new_octets = account.octets + new_octets_delta
        # Simplified balance check - in reality this would check against computed threshold
        if account.balance < account.min_balance
            state.registers[8] = FULL
            return state
        end

        # Store the value
        was_new = !haskey(account.storage, key)
        account.storage[key] = value
        if was_new
            account.items += 1
        end
        account.octets = new_octets
    end

    # Return old value length (or NONE if didn't exist)
    state.registers[8] = old_value_length
    return state
end

"""
    host_call_info(state, context)

Host call 5: info
Get service account information.

Registers:
- r7: service ID (2^64-1 for self)
- r8: output memory offset
- r9: source offset (where to start reading from encoded data)
- r10: length to copy

Returns in r7: total length of encoded data (or NONE if account doesn't exist)
Gas cost: 10
"""
function host_call_info(state, context)
    # Charge gas
    state.gas -= 10
    if state.gas < 0
        state.status = :oog
        return state
    end

    # Get parameters from registers
    service_id_param = state.registers[8]  # r7
    output_offset = state.registers[9]     # r8
    source_offset = state.registers[10]    # r9
    copy_length = state.registers[11]      # r10

    # Determine which service account to query
    if context === nothing || context.accounts === nothing
        state.registers[8] = NONE
        return state
    end

    target_service_id = if service_id_param == typemax(UInt64)
        # 2^64-1 means self
        context.service_id
    else
        UInt32(service_id_param)
    end

    # Look up the account
    if !haskey(context.accounts, target_service_id)
        state.registers[8] = NONE
        return state
    end

    account = context.accounts[target_service_id]

    # Encode account info according to spec:
    # code_hash (32 bytes) + balance (8) + min_balance (8) + min_acc_gas (8) + min_memo_gas (8) + octets (8) +
    # items (4) + gratis (8) + created (4) + last_acc (4) + parent (4)
    encoded = Vector{UInt8}()
    append!(encoded, encode_hash(account.code_hash))
    append!(encoded, encode_u64(account.balance))
    append!(encoded, encode_u64(account.min_balance))
    append!(encoded, encode_u64(account.min_acc_gas))
    append!(encoded, encode_u64(account.min_memo_gas))
    append!(encoded, encode_u64(account.octets))
    append!(encoded, encode_u32(account.items))
    append!(encoded, encode_u64(account.gratis))
    append!(encoded, encode_u32(account.created))
    append!(encoded, encode_u32(account.last_acc))
    append!(encoded, encode_u32(account.parent))

    total_length = length(encoded)

    # Calculate actual copy parameters (with bounds checking)
    actual_source_offset = min(source_offset, UInt64(total_length))
    actual_length = min(copy_length, UInt64(total_length) - actual_source_offset)

    # Check if output memory is writable
    if !is_writable(state.memory.access, UInt32(output_offset), UInt32(actual_length))
        state.status = :panic
        return state
    end

    # Copy data to memory
    for i in 0:(actual_length-1)
        src_idx = actual_source_offset + i + 1  # Julia 1-indexed
        dst_idx = output_offset + i + 1
        if src_idx <= length(encoded) && dst_idx <= length(state.memory.data)
            state.memory.data[dst_idx] = encoded[src_idx]
        end
    end

    # Return total length in r7
    state.registers[8] = UInt64(total_length)
    return state
end

"""
    host_call_historical_lookup(state, context)

Host call 6: historical_lookup
Look up historical service account data at a specific time and code hash.
Used in Refine context to access historical state for auditing.

Inputs:
  r7: service ID (2^64-1 for self)
  r8: hash offset in memory (32 bytes - code hash to lookup)
  r9: output offset for result
  r10: source offset in result
  r11: length to copy

Returns in r7:
  - total length of historical data (success)
  - NONE if not found

Gas cost: 10
"""
function host_call_historical_lookup(state, context)
    # Charge gas
    state.gas -= 10
    if state.gas < 0
        state.status = :oog
        return state
    end

    # Get parameters
    service_id_param = state.registers[8]   # r7
    hash_offset = state.registers[9]        # r8
    output_offset = state.registers[10]     # r9
    source_offset = state.registers[11]     # r10
    copy_length = state.registers[12]       # r11

    # Check context has accounts dictionary
    if context === nothing || context.accounts === nothing
        state.registers[8] = NONE
        return state
    end

    # Determine target service (r7 = 2^64-1 means self)
    target_service_id = if service_id_param == typemax(UInt64)
        context.service_id
    else
        UInt32(service_id_param)
    end

    # Look up account
    if !haskey(context.accounts, target_service_id)
        state.registers[8] = NONE
        return state
    end

    account = context.accounts[target_service_id]

    # Check if hash memory is readable (32 bytes)
    if !is_readable(state.memory.access, UInt32(hash_offset), UInt32(32))
        state.status = :panic
        return state
    end

    # Read code hash from memory
    code_hash = state.memory.data[hash_offset+1:hash_offset+32]

    # Historical lookup: Check if code hash matches account's current code hash
    # In a full implementation, this would lookup historical state at lookup_anchor_time
    # For now, we check against current account code hash
    if account.code_hash != code_hash
        state.registers[8] = NONE
        return state
    end

    # For historical lookup, we would return encoded service account data
    # For now, return a placeholder indicating historical data would be here
    # In full implementation: encode account state (balance, storage, etc.)
    historical_data = account.code_hash  # Simplified: just return code hash

    total_length = length(historical_data)

    # Calculate actual copy parameters
    actual_source_offset = min(source_offset, UInt64(total_length))
    actual_length = min(copy_length, UInt64(total_length) - actual_source_offset)

    # Check if output memory is writable
    if !is_writable(state.memory.access, UInt32(output_offset), UInt32(actual_length))
        state.status = :panic
        return state
    end

    # Copy historical data to memory
    for i in 0:(actual_length-1)
        src_idx = actual_source_offset + i + 1
        dst_idx = output_offset + i + 1
        if src_idx <= length(historical_data) && dst_idx <= length(state.memory.data)
            state.memory.data[dst_idx] = historical_data[src_idx]
        end
    end

    # Return total length in r7
    state.registers[8] = UInt64(total_length)
    return state
end

"""
    host_call_export(state, context)

Host call 7: export
Export a memory segment to the export list (Refine and Is-Authorized contexts).
Inputs:
  r7: memory address to read from
  r8: length of data to export
  r9: memory address to write gas consumed

Returns in r7: result code (OK, OOB)
Gas cost: 10 + length
"""
function host_call_export(state, context)
    # Get parameters
    mem_addr = UInt32(state.registers[8])  # r7
    length = UInt32(state.registers[9])     # r8
    gas_addr = UInt32(state.registers[10])  # r9

    # Calculate gas cost: 10 base + length
    gas_cost = 10 + Int64(length)
    state.gas -= gas_cost

    if state.gas < 0
        state.status = :oog
        return state
    end

    # Check if memory range is readable
    if !is_readable(state.memory.access, mem_addr, length)
        state.registers[8] = OOB
        return state
    end

    # Check if gas_addr is writable (8 bytes for UInt64)
    if !is_writable(state.memory.access, gas_addr, UInt32(8))
        state.registers[8] = OOB
        return state
    end

    # Read memory segment
    segment = Vector{UInt8}(undef, length)
    for i in 1:length
        segment[i] = state.memory.data[mem_addr + i]
    end

    # Add to exports list
    push!(state.exports, segment)

    # Write gas consumed to memory (little-endian UInt64)
    gas_consumed = UInt64(gas_cost)
    for i in 0:7
        state.memory.data[gas_addr + i + 1] = UInt8((gas_consumed >> (8*i)) & 0xFF)
    end

    # Return success
    state.registers[8] = OK
    return state
end

"""
    host_call_machine(state, context)

Host call 8: machine
Create a new inner PVM instance (Refine context only).

Inputs:
  r7: program offset in memory (p_O)
  r8: program length (p_Z)
  r9: initial PC (i)

Returns in r7:
  - machine ID (success)
  - HUH if program invalid

Gas cost: 10
"""
function host_call_machine(state, context)
    # Charge gas
    state.gas -= 10
    if state.gas < 0
        state.status = :oog
        return state
    end

    # Get parameters
    prog_offset = UInt32(state.registers[8])  # r7: program offset
    prog_length = UInt32(state.registers[9])  # r8: program length
    initial_pc = UInt32(state.registers[10])  # r9: initial PC

    # Check if program memory is readable
    if !is_readable(state.memory.access, prog_offset, prog_length)
        state.status = :panic
        return state
    end

    # Read program blob from memory
    program = state.memory.data[prog_offset+1:prog_offset+prog_length]

    # Try to decode the program (validate it)
    # deblob is defined in pvm.jl
    # For now, do a simple check - full deblob would be better
    if length(program) < 3
        state.registers[8] = HUH
        return state
    end

    # Find next available machine ID
    machine_id = UInt32(0)
    while haskey(state.machines, machine_id)
        machine_id += 1
    end

    # Create new guest PVM with empty RAM
    guest_ram = Memory()  # Initialize with empty memory

    # Import Memory type from parent module if needed
    guest = GuestPVM(program, guest_ram, initial_pc)

    # Add to machines dictionary
    state.machines[machine_id] = guest

    # Return machine ID in r7
    state.registers[8] = UInt64(machine_id)
    return state
end

"""
    host_call_peek(state, context)

Host call 9: peek
Read from inner PVM memory (Refine context only).

Inputs:
  r7: machine ID (n)
  r8: output offset in parent memory (o)
  r9: source offset in guest memory (s)
  r10: length (z)

Returns in r7:
  - OK (success)
  - WHO (machine doesn't exist)
  - OOB (guest memory not readable)

Gas cost: 10
"""
function host_call_peek(state, context)
    # Charge gas
    state.gas -= 10
    if state.gas < 0
        state.status = :oog
        return state
    end

    # Get parameters
    machine_id = UInt32(state.registers[8])   # r7
    output_offset = UInt32(state.registers[9])  # r8
    source_offset = UInt32(state.registers[10]) # r9
    length = UInt32(state.registers[11])        # r10

    # Check if output memory in parent is writable
    if !is_writable(state.memory.access, output_offset, length)
        state.status = :panic
        return state
    end

    # Check if machine exists
    if !haskey(state.machines, machine_id)
        state.registers[8] = WHO
        return state
    end

    guest = state.machines[machine_id]

    # Check if source memory in guest is readable
    if !is_readable(guest.ram.access, source_offset, length)
        state.registers[8] = OOB
        return state
    end

    # Copy from guest to parent memory
    for i in 0:(length-1)
        state.memory.data[output_offset + i + 1] = guest.ram.data[source_offset + i + 1]
    end

    state.registers[8] = OK
    return state
end

"""
    host_call_poke(state, context)

Host call 10: poke
Write to inner PVM memory (Refine context only).

Inputs:
  r7: machine ID (n)
  r8: source offset in parent memory (s)
  r9: output offset in guest memory (o)
  r10: length (z)

Returns in r7:
  - OK (success)
  - WHO (machine doesn't exist)
  - OOB (guest memory not writable)

Gas cost: 10
"""
function host_call_poke(state, context)
    # Charge gas
    state.gas -= 10
    if state.gas < 0
        state.status = :oog
        return state
    end

    # Get parameters
    machine_id = UInt32(state.registers[8])   # r7
    source_offset = UInt32(state.registers[9])  # r8
    output_offset = UInt32(state.registers[10]) # r9
    length = UInt32(state.registers[11])        # r10

    # Check if source memory in parent is readable
    if !is_readable(state.memory.access, source_offset, length)
        state.status = :panic
        return state
    end

    # Check if machine exists
    if !haskey(state.machines, machine_id)
        state.registers[8] = WHO
        return state
    end

    guest = state.machines[machine_id]

    # Check if output memory in guest is writable
    if !is_writable(guest.ram.access, output_offset, length)
        state.registers[8] = OOB
        return state
    end

    # Copy from parent to guest memory
    for i in 0:(length-1)
        guest.ram.data[output_offset + i + 1] = state.memory.data[source_offset + i + 1]
    end

    state.registers[8] = OK
    return state
end

"""
    host_call_pages(state, context)

Host call 11: pages
Manage memory pages for inner PVM (Refine context only).

Inputs:
  r7: machine ID (n)
  r8: starting page (p)
  r9: page count (c)
  r10: rights (r): 0=none, 1=read, 2=write, 3=keep+read, 4=keep+write

Returns in r7:
  - OK (success)
  - WHO (machine doesn't exist)
  - HUH (invalid parameters)

Gas cost: 10
"""
function host_call_pages(state, context)
    # Charge gas
    state.gas -= 10
    if state.gas < 0
        state.status = :oog
        return state
    end

    # Get parameters
    machine_id = UInt32(state.registers[8])  # r7
    start_page = UInt32(state.registers[9])  # r8
    page_count = UInt32(state.registers[10]) # r9
    rights = UInt32(state.registers[11])     # r10

    # Check if machine exists
    if !haskey(state.machines, machine_id)
        state.registers[8] = WHO
        return state
    end

    # Validate parameters
    if rights > 4 || start_page < 16 || start_page + page_count >= div(2^32, UInt32(PAGE_SIZE))
        state.registers[8] = HUH
        return state
    end

    guest = state.machines[machine_id]

    # If rights > 2, check that pages are already allocated
    if rights > 2
        for page_idx in start_page:(start_page + page_count - 1)
            if page_idx + 1 <= length(guest.ram.access) && guest.ram.access[page_idx + 1] === nothing
                state.registers[8] = HUH
                return state
            end
        end
    end

    # Apply page operations
    for page_idx in start_page:(start_page + page_count - 1)
        if page_idx + 1 <= length(guest.ram.access)
            # Zero out pages if rights < 3
            if rights < 3
                page_start = page_idx * PAGE_SIZE
                for i in 1:PAGE_SIZE
                    if page_start + i <= length(guest.ram.data)
                        guest.ram.data[page_start + i] = 0x00
                    end
                end
            end

            # Set access permissions
            if rights == 0
                guest.ram.access[page_idx + 1] = nothing
            elseif rights == 1 || rights == 3
                guest.ram.access[page_idx + 1] = READ
            elseif rights == 2 || rights == 4
                guest.ram.access[page_idx + 1] = :write
            end
        end
    end

    state.registers[8] = OK
    return state
end

"""
    host_call_invoke(state, context)

Host call 12: invoke
Execute inner PVM (Refine context only).

Inputs:
  r7: machine ID (n)
  r8: memory offset for gas+registers (o) - 112 bytes

Memory layout at offset o:
  - 8 bytes: gas limit
  - 13 x 8 bytes: register values

Returns in r7:
  - execution status (HOST/FAULT/OOG/PANIC/HALT/CONTINUE)
  - WHO (machine doesn't exist)

Gas cost: 10 + guest execution gas
"""
function host_call_invoke(state, context)
    # Charge gas
    state.gas -= 10
    if state.gas < 0
        state.status = :oog
        return state
    end

    # Get parameters
    machine_id = UInt32(state.registers[8])  # r7
    mem_offset = UInt32(state.registers[9])  # r8

    # Check if memory is writable (112 bytes: 8 for gas + 13*8 for registers)
    if !is_writable(state.memory.access, mem_offset, UInt32(112))
        state.status = :panic
        return state
    end

    # Check if machine exists
    if !haskey(state.machines, machine_id)
        state.registers[8] = WHO
        return state
    end

    # TODO: Full implementation would:
    # 1. Read gas limit and registers from memory
    # 2. Execute guest PVM from current PC
    # 3. Write back gas and registers to memory
    # 4. Return execution status

    # Simplified: Return HALT status
    state.registers[8] = UInt64(1)  # HALT status
    return state
end

"""
    host_call_expunge(state, context)

Host call 13: expunge
Destroy inner PVM instance (Refine context only).

Inputs:
  r7: machine ID (n)

Returns in r7:
  - OK (success)
  - WHO (machine doesn't exist)

Gas cost: 10
"""
function host_call_expunge(state, context)
    # Charge gas
    state.gas -= 10
    if state.gas < 0
        state.status = :oog
        return state
    end

    # Get parameter
    machine_id = UInt32(state.registers[8])  # r7

    # Check if machine exists
    if !haskey(state.machines, machine_id)
        state.registers[8] = WHO
        return state
    end

    # Remove machine from dictionary
    delete!(state.machines, machine_id)

    state.registers[8] = OK
    return state
end

# ===== Accumulate Functions =====
# These are only available during Accumulate invocation
# They allow services to interact with chain state

"""
    host_call_bless(state, context)

Host call 14: bless
Set privileged state (manager, validators, core authorizers, etc.).

Inputs:
  r7: manager service ID (m)
  r8: authorizers array offset (a) - 4*C_core_count bytes
  r9: validator service ID (v)
  r10: registrar service ID (r)
  r11: always-access array offset (o) - 12*n bytes
  r12: always-access count (n)

Returns in r7:
  - OK (success)
  - WHO (invalid service ID)

Gas cost: 10
"""
function host_call_bless(state, context)
    state.gas -= 10
    if state.gas < 0
        state.status = :oog
        return state
    end

    # Get parameters
    manager_id = state.registers[8]      # r7
    auth_offset = UInt32(state.registers[9])  # r8
    validator_id = state.registers[10]   # r9
    registrar_id = state.registers[11]   # r10
    access_offset = UInt32(state.registers[12]) # r11
    access_count = UInt32(state.registers[13])  # r12

    core_count = Ccorecount

    # Check if authorizers memory is readable (4 bytes per core)
    if !is_readable(state.memory.access, auth_offset, UInt32(4 * core_count))
        state.status = :panic
        return state
    end

    # Check if always-access memory is readable (12 bytes per entry)
    if !is_readable(state.memory.access, access_offset, UInt32(12 * access_count))
        state.status = :panic
        return state
    end

    # Validate service IDs are in valid range (must be < 2^32)
    if manager_id >= 2^32 || validator_id >= 2^32 || registrar_id >= 2^32
        state.registers[8] = WHO
        return state
    end

    # Read authorizers array (one per core)
    authorizers = Vector{UInt32}(undef, core_count)
    for i in 1:core_count
        offset = auth_offset + UInt32((i-1) * 4)
        bytes = state.memory.data[offset+1:offset+4]
        auth_id = UInt32(bytes[1]) | (UInt32(bytes[2]) << 8) | (UInt32(bytes[3]) << 16) | (UInt32(bytes[4]) << 24)

        # Validate authorizer ID
        if auth_id >= 2^32
            state.registers[8] = WHO
            return state
        end
        authorizers[i] = auth_id
    end

    # Read always-access entries (service_id: 4 bytes, gas: 8 bytes)
    always_access = Vector{Tuple{UInt32, UInt64}}(undef, access_count)
    for i in 1:access_count
        offset = access_offset + UInt32((i-1) * 12)

        # Read service ID (4 bytes)
        id_bytes = state.memory.data[offset+1:offset+4]
        service_id = UInt32(id_bytes[1]) | (UInt32(id_bytes[2]) << 8) |
                     (UInt32(id_bytes[3]) << 16) | (UInt32(id_bytes[4]) << 24)

        # Read gas (8 bytes)
        gas_bytes = state.memory.data[offset+5:offset+12]
        gas = UInt64(0)
        for j in 1:8
            gas |= UInt64(gas_bytes[j]) << (8 * (j-1))
        end

        always_access[i] = (service_id, gas)
    end

    # Update privileged state if we have implications context
    if !isnothing(context.implications)
        im = context.implications
        im.privileged_state.manager = UInt32(manager_id)
        im.privileged_state.assigners = authorizers
        im.privileged_state.delegator = UInt32(validator_id)
        im.privileged_state.registrar = UInt32(registrar_id)
        im.privileged_state.always_access = always_access
    end

    state.registers[8] = OK
    return state
end

"""
    host_call_assign(state, context)

Host call 15: assign
Assign cores and authorization queue.
Parameters:
  r7: core index (c)
  r8: queue offset (o) - 32*Cauthqueuesize bytes
  r9: assigner service id (a)
Gas cost: 10
Returns: OK, CORE, HUH, WHO
"""
function host_call_assign(state, context)
    state.gas -= 10
    if state.gas < 0
        state.status = :oog
        return state
    end

    # Parse parameters
    core_index = state.registers[8]     # r7
    queue_offset = UInt32(state.registers[9])  # r8
    assigner_id = state.registers[10]   # r9

    # Check memory bounds for auth queue (32 * Cauthqueuesize bytes)
    queue_bytes = UInt32(32 * Cauthqueuesize)
    if !is_readable(state.memory.access, queue_offset, queue_bytes)
        state.status = :panic
        return state
    end

    # Validate core index
    if core_index >= Ccorecount
        state.registers[8] = CORE
        return state
    end

    # Check if caller owns this core
    if !isnothing(context.implications)
        im = context.implications
        if length(im.privileged_state.assigners) > core_index &&
           im.service_id != im.privileged_state.assigners[core_index + 1]  # Julia 1-indexed
            state.registers[8] = HUH
            return state
        end
    end

    # Validate assigner_id is valid service id
    if assigner_id >= 2^32
        state.registers[8] = WHO
        return state
    end

    # Read authorization queue
    auth_queue = Vector{Vector{UInt8}}(undef, Cauthqueuesize)
    for i in 1:Cauthqueuesize
        offset = queue_offset + UInt32((i-1) * 32)
        auth_queue[i] = state.memory.data[offset+1:offset+32]
    end

    # Update privileged state
    if !isnothing(context.implications)
        im = context.implications
        # Ensure auth_queue has enough entries
        while length(im.privileged_state.auth_queue) <= core_index
            push!(im.privileged_state.auth_queue, Vector{Vector{UInt8}}())
        end
        # Ensure assigners has enough entries
        while length(im.privileged_state.assigners) <= core_index
            push!(im.privileged_state.assigners, UInt32(0))
        end

        im.privileged_state.auth_queue[core_index + 1] = auth_queue  # Julia 1-indexed
        im.privileged_state.assigners[core_index + 1] = UInt32(assigner_id)
    end

    state.registers[8] = OK
    return state
end

"""
    host_call_designate(state, context)

Host call 16: designate
Designate validator staging set.
Parameters:
  r7: offset (o) - 336*Cvalcount bytes
Gas cost: 10
Returns: OK, HUH
"""
function host_call_designate(state, context)
    state.gas -= 10
    if state.gas < 0
        state.status = :oog
        return state
    end

    # Parse parameters
    offset = UInt32(state.registers[8])  # r7

    # Constants
    val_count = 1023  # Cvalcount from graypaper
    validator_size = 336  # bytes per validator entry

    # Check memory bounds for validator staging set
    staging_bytes = UInt32(validator_size * val_count)
    if !is_readable(state.memory.access, offset, staging_bytes)
        state.status = :panic
        return state
    end

    # Read validator staging set
    staging_set = Vector{Vector{UInt8}}(undef, val_count)
    for i in 1:val_count
        entry_offset = offset + UInt32((i-1) * validator_size)
        staging_set[i] = state.memory.data[entry_offset+1:entry_offset+validator_size]
    end

    # Get implications context
    if isnothing(context.implications)
        state.registers[8] = HUH
        return state
    end
    im = context.implications

    # Check if caller is the delegator
    if context.service_id != im.privileged_state.delegator
        state.registers[8] = HUH
        return state
    end

    # Update privileged state staging_set
    im.privileged_state.staging_set = staging_set

    state.registers[8] = OK
    return state
end

"""
    host_call_checkpoint(state, context)

Host call 17: checkpoint
Create execution checkpoint for exceptional exit.
Sets imY' = imX (checkpoint exceptional state to equal current state).
Returns gas remaining in r7.
Gas cost: 10
"""
function host_call_checkpoint(state, context)
    state.gas -= 10
    if state.gas < 0
        state.status = :oog
        return state
    end

    # Set r7 to remaining gas
    state.registers[8] = UInt64(max(0, state.gas))

    # Checkpoint exceptional state: imY = imX
    # The exceptional state becomes a copy of the current state
    # Note: We create a shallow copy since deep copy of recursive structure is complex
    # In practice, if panic occurs after checkpoint, the exceptional state would be used
    if !isnothing(context.implications)
        im = context.implications
        # Create a copy of current state to use as exceptional exit state
        im.exceptional_state = ImplicationsContext(
            im.service_id,
            im.self,  # TODO: should be deep copy
            im.privileged_state,  # TODO: should be deep copy
            im.accounts,  # shared reference for now
            copy(im.transfers),
            copy(im.provisions),
            im.yield_hash !== nothing ? copy(im.yield_hash) : nothing,
            im.next_free_id,
            im.current_time,
            nothing  # no nested exceptional state
        )
    end

    return state
end

"""
    host_call_new(state, context)

Host call 18: new
Create new service account.
Parameters:
  r7: code hash offset (o) - 32 bytes
  r8: code length (l) - must fit in 32 bits
  r9: min accumulate gas (min_acc_gas)
  r10: min on-transfer gas (min_memo_gas)
  r11: gratis flag
  r12: desired service id (0 for auto-assign)
Gas cost: 10
Returns: service_id, HUH, CASH, FULL
"""
function host_call_new(state, context)
    state.gas -= 10
    if state.gas < 0
        state.status = :oog
        return state
    end

    # Parse parameters
    hash_offset = UInt32(state.registers[8])   # r7
    code_length = state.registers[9]           # r8
    min_acc_gas = state.registers[10]          # r9
    min_memo_gas = state.registers[11]         # r10
    gratis = state.registers[12]               # r11
    desired_id = state.registers[13]           # r12

    # Check if code_length fits in 32 bits
    if code_length >= 2^32
        state.status = :panic
        return state
    end

    # Check memory bounds for code hash
    if !is_readable(state.memory.access, hash_offset, UInt32(32))
        state.status = :panic
        return state
    end

    # Read code hash
    code_hash = state.memory.data[hash_offset+1:hash_offset+32]

    # Constants
    min_public_index = UInt32(2^16)  # Cminpublicindex
    min_balance_constant = UInt64(10^15)  # Graypaper Cminbalance

    # Get implications context
    if isnothing(context.implications)
        state.registers[8] = HUH
        return state
    end
    im = context.implications

    # Check if caller is registrar when trying to create privileged service (desired_id != 0)
    if desired_id != 0 && desired_id < min_public_index
        if context.service_id != im.privileged_state.registrar
            state.registers[8] = HUH
            return state
        end
    end

    # Check if caller has sufficient balance to create service
    if im.self.balance < min_balance_constant + im.self.min_balance
        state.registers[8] = FULL
        return state
    end

    # Assign service id
    assigned_id = if desired_id != 0 && desired_id < min_public_index
        # Registrar creating privileged service
        # Check if id already exists
        if haskey(im.accounts, UInt32(desired_id))
            state.registers[8] = HUH
            return state
        end
        UInt32(desired_id)
    else
        # Auto-assign public service id from next_free_id
        next_id = im.next_free_id
        # Find next available slot
        while haskey(im.accounts, next_id)
            next_id += UInt32(1)
            if next_id < min_public_index
                next_id = min_public_index
            end
        end
        im.next_free_id = next_id + UInt32(1)
        next_id
    end

    # Create new service account
    new_account = ServiceAccount(
        copy(code_hash),                                    # code_hash
        Dict{Vector{UInt8}, Vector{UInt8}}(),              # storage: empty
        Dict{Vector{UInt8}, Vector{UInt8}}(),              # preimages: empty
        Dict{Tuple{Vector{UInt8}, UInt64}, PreimageRequest}(),  # requests: empty initially
        min_balance_constant,                               # balance
        min_balance_constant,                               # min_balance
        UInt64(min_acc_gas),                               # min_acc_gas
        UInt64(min_memo_gas),                              # min_memo_gas
        UInt64(0),                                         # octets
        UInt32(0),                                         # items
        UInt64(gratis),                                    # gratis
        im.current_time,                                   # created
        UInt32(0),                                         # last_acc
        context.service_id                                 # parent
    )

    # Add initial preimage request for code: (code_hash, code_length) -> []
    if code_length > 0
        new_account.requests[(copy(code_hash), UInt64(code_length))] = PreimageRequest(Vector{UInt64}())
        new_account.items += UInt32(1)
    end

    # Add to accounts
    im.accounts[assigned_id] = new_account

    # Deduct min_balance from caller's balance
    im.self.balance -= min_balance_constant

    state.registers[8] = UInt64(assigned_id)
    return state
end

"""
    host_call_upgrade(state, context)

Host call 19: upgrade
Upgrade service code hash and gas parameters.
Parameters:
  r7: code hash offset (o) - 32 bytes
  r8: min accumulate gas (g)
  r9: min on-transfer gas (m)
Gas cost: 10
Returns: OK
"""
function host_call_upgrade(state, context)
    state.gas -= 10
    if state.gas < 0
        state.status = :oog
        return state
    end

    # Parse parameters
    hash_offset = UInt32(state.registers[8])  # r7
    min_acc_gas = state.registers[9]          # r8
    min_memo_gas = state.registers[10]        # r9

    # Check memory bounds for code hash
    if !is_readable(state.memory.access, hash_offset, UInt32(32))
        state.status = :panic
        return state
    end

    # Read code hash
    code_hash = state.memory.data[hash_offset+1:hash_offset+32]

    # Update self's account in implications context
    if !isnothing(context.implications)
        im = context.implications
        im.self.code_hash = copy(code_hash)
        im.self.min_acc_gas = UInt64(min_acc_gas)
        im.self.min_memo_gas = UInt64(min_memo_gas)
    end

    state.registers[8] = OK
    return state
end

"""
    host_call_transfer(state, context)

Host call 20: transfer
Transfer balance to another service with memo.
Parameters:
  r7: destination service id
  r8: amount to transfer
  r9: gas limit for transfer (l)
  r10: memo offset (o) - 128 bytes
Gas cost: 10 + l (gas limit is consumed)
Returns: OK, WHO, LOW, CASH
"""
function host_call_transfer(state, context)
    # Parse parameters first (before charging gas)
    dest_service_id = state.registers[8]      # r7
    amount = state.registers[9]                # r8
    gas_limit = Int64(state.registers[10])     # r9
    memo_offset = UInt32(state.registers[11])  # r10

    # Gas cost is 10 + gas_limit
    gas_cost = 10 + gas_limit
    state.gas -= gas_cost
    if state.gas < 0
        state.status = :oog
        return state
    end

    # Constants
    memo_size = 128  # Cmemosize

    # Check memory bounds for memo
    if !is_readable(state.memory.access, memo_offset, UInt32(memo_size))
        state.status = :panic
        return state
    end

    # Read memo
    memo = state.memory.data[memo_offset+1:memo_offset+memo_size]

    # Get implications context
    if isnothing(context.implications)
        state.registers[8] = HUH
        return state
    end
    im = context.implications

    # Check if destination service id is valid (< 2^32)
    if dest_service_id >= 2^32
        state.registers[8] = WHO
        return state
    end

    dest_id = UInt32(dest_service_id)

    # Check if destination exists (either in accounts or is self)
    dest_account = if dest_id == context.service_id
        im.self
    elseif haskey(im.accounts, dest_id)
        im.accounts[dest_id]
    else
        state.registers[8] = WHO
        return state
    end

    # Check if gas_limit meets destination's minimum
    if UInt64(gas_limit) < dest_account.min_memo_gas
        state.registers[8] = LOW
        return state
    end

    # Check if caller has sufficient balance after transfer
    if im.self.balance < amount + im.self.min_balance
        state.registers[8] = CASH
        return state
    end

    # Create deferred transfer
    transfer = DeferredTransfer(
        context.service_id,      # source
        dest_id,                 # dest
        UInt64(amount),          # amount
        copy(memo),              # memo
        UInt64(gas_limit)        # gas
    )

    # Append to transfers list
    push!(im.transfers, transfer)

    # Deduct amount from caller's balance
    im.self.balance -= UInt64(amount)

    state.registers[8] = OK
    return state
end

"""
    host_call_eject(state, context)

Host call 21: eject
Eject a service account that is ready for removal.
Parameters:
  r7: service id to eject (d)
  r8: hash offset (o) - 32 bytes
Gas cost: 10
Returns: OK, WHO, HUH
"""
function host_call_eject(state, context)
    state.gas -= 10
    if state.gas < 0
        state.status = :oog
        return state
    end

    # Parse parameters
    service_to_eject = state.registers[8]      # r7
    hash_offset = UInt32(state.registers[9])   # r8

    # Check memory bounds for hash
    if !is_readable(state.memory.access, hash_offset, UInt32(32))
        state.status = :panic
        return state
    end

    # Read hash
    hash = state.memory.data[hash_offset+1:hash_offset+32]

    # Get implications context
    if isnothing(context.implications)
        state.registers[8] = HUH
        return state
    end
    im = context.implications

    # Check if service_to_eject is valid (< 2^32)
    if service_to_eject >= 2^32
        state.registers[8] = WHO
        return state
    end

    eject_id = UInt32(service_to_eject)

    # Check if trying to eject self (not allowed)
    if eject_id == context.service_id
        state.registers[8] = HUH
        return state
    end

    # Check if service exists
    if !haskey(im.accounts, eject_id)
        state.registers[8] = WHO
        return state
    end

    target_account = im.accounts[eject_id]

    # Check if service's parent matches caller (encoded as parent field)
    if target_account.parent != context.service_id
        state.registers[8] = HUH
        return state
    end

    # Check if service has exactly 2 items (code request + one other)
    if target_account.items != 2
        state.registers[8] = HUH
        return state
    end

    # Find the non-code request and verify it's expired
    # Constants
    expunge_period = UInt32(19200)  # Cexpungeperiod from graypaper

    found_valid_request = false
    for ((req_hash, req_length), req) in target_account.requests
        # Skip code request (hash matches code_hash)
        if req_hash == target_account.code_hash
            continue
        end

        # Check if this is the request being ejected
        if req_hash == hash
            # Must be in [x, y, z] state where y < current_time - expunge_period
            if length(req.state) == 3
                y = UInt32(req.state[2])
                # Safe subtraction - check if expunge period would underflow
                expunge_threshold = if im.current_time >= expunge_period
                    im.current_time - expunge_period
                else
                    UInt32(0)
                end
                if y < expunge_threshold
                    found_valid_request = true
                    break
                end
            end
        end
    end

    if !found_valid_request
        state.registers[8] = HUH
        return state
    end

    # Remove service account and transfer balance to caller
    removed_balance = target_account.balance
    delete!(im.accounts, eject_id)

    # Add balance to caller's balance
    im.self.balance += removed_balance

    state.registers[8] = OK
    return state
end

"""
    host_call_query(state, context)

Host call 22: query
Query preimage request status.
Parameters:
  r7: hash offset (o) - 32 bytes
  r8: length (z)
Gas cost: 10
Returns in r7/r8: encoded status
  - r7=NONE, r8=0: request doesn't exist
  - r7=0, r8=0: request exists but not satisfied ([])
  - r7=1+2^32*x, r8=0: request partially satisfied ([x])
  - r7=2+2^32*x, r8=y: request fully satisfied, pending ([x, y])
  - r7=3+2^32*x, r8=y+2^32*z: request fully satisfied, available ([x, y, z])
"""
function host_call_query(state, context)
    state.gas -= 10
    if state.gas < 0
        state.status = :oog
        return state
    end

    # Parse parameters
    hash_offset = UInt32(state.registers[8])  # r7
    req_length = state.registers[9]           # r8

    # Check memory bounds for hash
    if !is_readable(state.memory.access, hash_offset, UInt32(32))
        state.status = :panic
        return state
    end

    # Read hash
    hash = state.memory.data[hash_offset+1:hash_offset+32]

    # Look up request status in self.requests[(hash, req_length)]
    if !isnothing(context.implications)
        im = context.implications
        key = (hash, UInt64(req_length))

        if haskey(im.self.requests, key)
            req = im.self.requests[key]
            state_vec = req.state

            # Encode based on request state
            if length(state_vec) == 0
                # []: request exists but not satisfied
                state.registers[8] = 0
                state.registers[9] = 0
            elseif length(state_vec) == 1
                # [x]: partial
                state.registers[8] = 1 + (state_vec[1] << 32)
                state.registers[9] = 0
            elseif length(state_vec) == 2
                # [x, y]: satisfied pending
                state.registers[8] = 2 + (state_vec[1] << 32)
                state.registers[9] = state_vec[2]
            elseif length(state_vec) == 3
                # [x, y, z]: satisfied available
                state.registers[8] = 3 + (state_vec[1] << 32)
                state.registers[9] = state_vec[2] + (state_vec[3] << 32)
            else
                # Invalid state
                state.registers[8] = NONE
                state.registers[9] = 0
            end
        else
            # Request doesn't exist
            state.registers[8] = NONE
            state.registers[9] = 0
        end
    else
        # No context - return not found
        state.registers[8] = NONE
        state.registers[9] = 0
    end

    return state
end

"""
    host_call_solicit(state, context)

Host call 23: solicit
Solicit preimage data by creating or updating request.
Parameters:
  r7: hash offset (o) - 32 bytes
  r8: length (z)
Gas cost: 10
Returns: OK, HUH, FULL
"""
function host_call_solicit(state, context)
    state.gas -= 10
    if state.gas < 0
        state.status = :oog
        return state
    end

    # Parse parameters
    hash_offset = UInt32(state.registers[8])  # r7
    req_length = state.registers[9]           # r8

    # Check memory bounds for hash
    if !is_readable(state.memory.access, hash_offset, UInt32(32))
        state.status = :panic
        return state
    end

    # Read hash
    hash = state.memory.data[hash_offset+1:hash_offset+32]

    # Update self.requests
    if !isnothing(context.implications)
        im = context.implications
        key = (hash, UInt64(req_length))

        if haskey(im.self.requests, key)
            req = im.self.requests[key]
            state_vec = req.state

            # Valid transitions:
            # [] -> [] (no-op, but allowed)
            # [x, y] -> [x, y, current_time]
            if length(state_vec) == 0
                # Already in [] state, no change needed
                # (In practice, this might be redundant, but graypaper allows it)
            elseif length(state_vec) == 2
                # Transition from [x, y] to [x, y, time]
                push!(req.state, UInt64(im.current_time))
            else
                # Invalid state transition
                state.registers[8] = HUH
                return state
            end
        else
            # Create new request with [] state
            im.self.requests[key] = PreimageRequest(Vector{UInt64}())
        end

        # Check balance after request creation
        if im.self.balance < im.self.min_balance
            state.registers[8] = FULL
            return state
        end
    end

    state.registers[8] = OK
    return state
end

"""
    host_call_forget(state, context)

Host call 24: forget
Forget preimage data by removing or updating request.
Parameters:
  r7: hash offset (o) - 32 bytes
  r8: length (z)
Gas cost: 10
Returns: OK, HUH
"""
function host_call_forget(state, context)
    state.gas -= 10
    if state.gas < 0
        state.status = :oog
        return state
    end

    # Parse parameters
    hash_offset = UInt32(state.registers[8])  # r7
    req_length = state.registers[9]           # r8

    # Check memory bounds for hash
    if !is_readable(state.memory.access, hash_offset, UInt32(32))
        state.status = :panic
        return state
    end

    # Read hash
    hash = state.memory.data[hash_offset+1:hash_offset+32]

    # Get implications context
    if isnothing(context.implications)
        state.registers[8] = HUH
        return state
    end
    im = context.implications

    # Constants
    expunge_period = UInt32(19200)  # Cexpungeperiod from graypaper

    # Look up request
    key = (hash, UInt64(req_length))
    if !haskey(im.self.requests, key)
        state.registers[8] = HUH
        return state
    end

    req = im.self.requests[key]
    state_vec = req.state

    # Update based on current state:
    if length(state_vec) == 0
        # [] state - remove request and preimage
        delete!(im.self.requests, key)
        if haskey(im.self.preimages, hash)
            delete!(im.self.preimages, hash)
        end
        im.self.items = max(UInt32(0), im.self.items - UInt32(1))

    elseif length(state_vec) == 1
        # [x] state - update to [x, current_time]
        push!(req.state, UInt64(im.current_time))

    elseif length(state_vec) == 2
        # [x, y] state - check if expired
        y = UInt32(state_vec[2])
        expunge_threshold = if im.current_time >= expunge_period
            im.current_time - expunge_period
        else
            UInt32(0)
        end
        if y < expunge_threshold
            # Remove request and preimage
            delete!(im.self.requests, key)
            if haskey(im.self.preimages, hash)
                delete!(im.self.preimages, hash)
            end
            im.self.items = max(UInt32(0), im.self.items - UInt32(1))
        else
            state.registers[8] = HUH
            return state
        end

    elseif length(state_vec) == 3
        # [x, y, w] state - check if y expired
        y = UInt32(state_vec[2])
        w = state_vec[3]
        expunge_threshold = if im.current_time >= expunge_period
            im.current_time - expunge_period
        else
            UInt32(0)
        end
        if y < expunge_threshold
            # Update to [w, current_time]
            req.state = [w, UInt64(im.current_time)]
        else
            state.registers[8] = HUH
            return state
        end

    else
        # Invalid state
        state.registers[8] = HUH
        return state
    end

    state.registers[8] = OK
    return state
end

"""
    host_call_yield(state, context)

Host call 25: yield
Yield accumulation result hash.
Parameters:
  r7: hash offset (o) - 32 bytes
Gas cost: 10
Returns: OK
"""
function host_call_yield(state, context)
    state.gas -= 10
    if state.gas < 0
        state.status = :oog
        return state
    end

    # Parse parameters
    hash_offset = UInt32(state.registers[8])  # r7

    # Check memory bounds for hash
    if !is_readable(state.memory.access, hash_offset, UInt32(32))
        state.status = :panic
        return state
    end

    # Read hash
    hash = state.memory.data[hash_offset+1:hash_offset+32]

    # Set yield hash in implications context
    if !isnothing(context.implications)
        im = context.implications
        im.yield_hash = copy(hash)
    end

    state.registers[8] = OK
    return state
end

"""
    host_call_provide(state, context)

Host call 26: provide
Provide preimage data for a service.
Parameters:
  r7: service id (s) - use 2^64-1 for self
  r8: data offset (o)
  r9: data length (z)
Gas cost: 10
Returns: OK, WHO, HUH
"""
function host_call_provide(state, context)
    state.gas -= 10
    if state.gas < 0
        state.status = :oog
        return state
    end

    # Parse parameters
    service_id_param = state.registers[8]      # r7
    data_offset = UInt32(state.registers[9])   # r8
    data_length = UInt32(state.registers[10])  # r9

    # Determine target service (2^64-1 means self)
    target_service_id = if service_id_param == typemax(UInt64)
        context.service_id
    else
        UInt32(service_id_param)
    end

    # Check memory bounds for data
    if !is_readable(state.memory.access, data_offset, data_length)
        state.status = :panic
        return state
    end

    # Read data
    data = state.memory.data[data_offset+1:data_offset+data_length]

    if !isnothing(context.implications)
        im = context.implications

        # Check if target service exists
        if !haskey(im.accounts, target_service_id) && target_service_id != im.service_id
            state.registers[8] = WHO
            return state
        end

        # Get target account
        target_account = target_service_id == im.service_id ? im.self : im.accounts[target_service_id]

        # Compute BLAKE2b-256 hash of data
        data_hash = blake2b_256(data)

        # Check if service has request for this preimage in [] state
        key = (data_hash, UInt64(data_length))
        if haskey(target_account.requests, key)
            req = target_account.requests[key]
            if length(req.state) != 0
                # Request not in [] state - already provided or invalid
                state.registers[8] = HUH
                return state
            end
        else
            # No request for this preimage
            state.registers[8] = HUH
            return state
        end

        # Check if provision already exists
        provision_key = (target_service_id, data)
        if provision_key in im.provisions
            state.registers[8] = HUH
            return state
        end

        # Add to provisions set
        push!(im.provisions, provision_key)
    end

    state.registers[8] = OK
    return state
end

# Export public types and functions
export dispatch_host_call, HostCallContext, ServiceAccount
export OK, NONE, WHAT, OOB, WHO, FULL, CORE, CASH, LOW, HUH

end
