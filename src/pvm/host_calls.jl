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

# Try to use StaticArrays if available, but don't require it
# (StaticArrays is only needed if using SVector types from parent modules)
try
    using StaticArrays
catch
    # Not available in standalone testing - that's OK
end

# Import parent serialization modules (will be available when used from JAM)
# For now, we'll add fallbacks for standalone testing

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

# ===== Context Types =====

"""
Service account structure (simplified for host calls)
"""
mutable struct ServiceAccount
    storage::Dict{Vector{UInt8}, Vector{UInt8}}  # key => value
    preimages::Dict{Vector{UInt8}, Vector{UInt8}}  # hash => preimage data
    code_hash::Vector{UInt8}  # 32 bytes
    balance::UInt64
    min_balance::UInt64
    min_acc_gas::UInt64
    min_memo_gas::UInt64
    octets::UInt64  # total storage bytes
    items::UInt32   # number of storage items
    gratis::UInt64  # gratis offset
    created::UInt32  # timeslot when created
    last_acc::UInt32  # timeslot of last accumulation
    parent::UInt32  # parent service ID
end

"""
Host call context - contains state needed for host call execution
For now, this is a simplified version. Will be expanded as needed.
"""
struct HostCallContext
    service_account::Union{ServiceAccount, Nothing}
    service_id::UInt32
    accounts::Union{Dict{UInt32, ServiceAccount}, Nothing}  # all service accounts (for read/info calls)

    # Environment data for fetch host call
    entropy::Union{Vector{UInt8}, Nothing}  # 32-byte entropy/timeslot hash (n)
    config::Union{Dict{Symbol, Any}, Nothing}  # JAM configuration constants
    work_package::Union{Dict{Symbol, Any}, Nothing}  # Work package data (p)
    recent_blocks::Union{Vector{Vector{UInt8}}, Nothing}  # Recent block hashes (r)
end

# Constructor with defaults for backward compatibility
function HostCallContext(service_account, service_id, accounts)
    HostCallContext(service_account, service_id, accounts, nothing, nothing, nothing, nothing)
end

# ===== Encoding Helpers =====

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
        if perm !== :write && perm !== :rw
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

    # Determine what data to fetch based on selector
    data = nothing

    if selector == 0
        # Configuration constants (from tiny chainspec)
        data = encode_config_constants()
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
    # TODO: Implement other selectors (3-6, 8-15) as needed
    end

    # If data is not available, return NONE
    if data === nothing
        state.registers[8] = NONE
        return state
    end

    # Calculate actual offsets and length
    total_length = length(data)
    f = min(UInt64(source_offset), UInt64(total_length))
    l = min(UInt64(copy_length), UInt64(total_length - f))

    # Check if output memory is writable
    if !is_writable(state.memory.access, UInt32(output_offset), UInt32(l))
        state.status = :panic
        return state
    end

    # Copy data to memory
    for i in 0:(l-1)
        if f + i < total_length
            addr = output_offset + i
            if addr < length(state.memory.data)
                state.memory.data[addr + 1] = data[f + i + 1]
            end
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
    if context === nothing || context.service_account === nothing
        state.registers[8] = NONE
        return state
    end

    account = context.service_account

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
Gas cost: 10
"""
function host_call_machine(state, context)
    # Charge gas
    state.gas -= 10
    if state.gas < 0
        state.status = :oog
        return state
    end

    # TODO: Implement inner PVM creation
    # Returns new machine ID in r7
    state.registers[8] = OK
    return state
end

"""
    host_call_peek(state, context)

Host call 9: peek
Read from inner PVM memory (Refine context only).
Gas cost: 10
"""
function host_call_peek(state, context)
    # Charge gas
    state.gas -= 10
    if state.gas < 0
        state.status = :oog
        return state
    end

    # TODO: Implement inner PVM memory read
    state.registers[8] = WHO  # No machine exists yet
    return state
end

"""
    host_call_poke(state, context)

Host call 10: poke
Write to inner PVM memory (Refine context only).
Gas cost: 10
"""
function host_call_poke(state, context)
    # Charge gas
    state.gas -= 10
    if state.gas < 0
        state.status = :oog
        return state
    end

    # TODO: Implement inner PVM memory write
    state.registers[8] = WHO  # No machine exists yet
    return state
end

"""
    host_call_pages(state, context)

Host call 11: pages
Manage memory pages for inner PVM (Refine context only).
Gas cost: 10
"""
function host_call_pages(state, context)
    # Charge gas
    state.gas -= 10
    if state.gas < 0
        state.status = :oog
        return state
    end

    # TODO: Implement page management
    state.registers[8] = WHO  # No machine exists yet
    return state
end

"""
    host_call_invoke(state, context)

Host call 12: invoke
Execute inner PVM (Refine context only).
Gas cost: 10
"""
function host_call_invoke(state, context)
    # Charge gas
    state.gas -= 10
    if state.gas < 0
        state.status = :oog
        return state
    end

    # TODO: Implement inner PVM invocation
    state.registers[8] = WHO  # No machine exists yet
    return state
end

"""
    host_call_expunge(state, context)

Host call 13: expunge
Destroy inner PVM instance (Refine context only).
Gas cost: 10
"""
function host_call_expunge(state, context)
    # Charge gas
    state.gas -= 10
    if state.gas < 0
        state.status = :oog
        return state
    end

    # TODO: Implement inner PVM destruction
    state.registers[8] = WHO  # No machine exists yet
    return state
end

# ===== Accumulate Functions =====
# These are only available during Accumulate invocation
# They allow services to interact with chain state

"""
    host_call_bless(state, context)

Host call 14: bless
Bless preimage data for availability.
Gas cost: 10
"""
function host_call_bless(state, context)
    state.gas -= 10
    if state.gas < 0
        state.status = :oog
        return state
    end

    # TODO: Implement bless
    state.registers[8] = OK
    return state
end

"""
    host_call_assign(state, context)

Host call 15: assign
Assign cores.
Gas cost: 10
"""
function host_call_assign(state, context)
    state.gas -= 10
    if state.gas < 0
        state.status = :oog
        return state
    end

    # TODO: Implement assign
    state.registers[8] = OK
    return state
end

"""
    host_call_designate(state, context)

Host call 16: designate
Designate validators.
Gas cost: 10
"""
function host_call_designate(state, context)
    state.gas -= 10
    if state.gas < 0
        state.status = :oog
        return state
    end

    # TODO: Implement designate
    state.registers[8] = OK
    return state
end

"""
    host_call_checkpoint(state, context)

Host call 17: checkpoint
Create execution checkpoint.
Gas cost: 10
"""
function host_call_checkpoint(state, context)
    state.gas -= 10
    if state.gas < 0
        state.status = :oog
        return state
    end

    # TODO: Implement checkpoint
    state.registers[8] = OK
    return state
end

"""
    host_call_new(state, context)

Host call 18: new
Create new service account.
Gas cost: 10
"""
function host_call_new(state, context)
    state.gas -= 10
    if state.gas < 0
        state.status = :oog
        return state
    end

    # TODO: Implement new service creation
    state.registers[8] = OK
    return state
end

"""
    host_call_upgrade(state, context)

Host call 19: upgrade
Upgrade service code.
Gas cost: 10
"""
function host_call_upgrade(state, context)
    state.gas -= 10
    if state.gas < 0
        state.status = :oog
        return state
    end

    # TODO: Implement service upgrade
    state.registers[8] = OK
    return state
end

"""
    host_call_transfer(state, context)

Host call 20: transfer
Transfer balance between accounts.
Gas cost: 10
"""
function host_call_transfer(state, context)
    state.gas -= 10
    if state.gas < 0
        state.status = :oog
        return state
    end

    # TODO: Implement transfer
    state.registers[8] = OK
    return state
end

"""
    host_call_eject(state, context)

Host call 21: eject
Eject service.
Gas cost: 10
"""
function host_call_eject(state, context)
    state.gas -= 10
    if state.gas < 0
        state.status = :oog
        return state
    end

    # TODO: Implement eject
    state.registers[8] = OK
    return state
end

"""
    host_call_query(state, context)

Host call 22: query
Query service.
Gas cost: 10
"""
function host_call_query(state, context)
    state.gas -= 10
    if state.gas < 0
        state.status = :oog
        return state
    end

    # TODO: Implement query
    state.registers[8] = OK
    return state
end

"""
    host_call_solicit(state, context)

Host call 23: solicit
Solicit service.
Gas cost: 10
"""
function host_call_solicit(state, context)
    state.gas -= 10
    if state.gas < 0
        state.status = :oog
        return state
    end

    # TODO: Implement solicit
    state.registers[8] = OK
    return state
end

"""
    host_call_forget(state, context)

Host call 24: forget
Forget preimage.
Gas cost: 10
"""
function host_call_forget(state, context)
    state.gas -= 10
    if state.gas < 0
        state.status = :oog
        return state
    end

    # TODO: Implement forget
    state.registers[8] = OK
    return state
end

"""
    host_call_yield(state, context)

Host call 25: yield
Yield work result.
Gas cost: 10
"""
function host_call_yield(state, context)
    state.gas -= 10
    if state.gas < 0
        state.status = :oog
        return state
    end

    # TODO: Implement yield
    state.registers[8] = OK
    return state
end

"""
    host_call_provide(state, context)

Host call 26: provide
Provide data for next accumulation.
Gas cost: 10
"""
function host_call_provide(state, context)
    state.gas -= 10
    if state.gas < 0
        state.status = :oog
        return state
    end

    # TODO: Implement provide
    state.registers[8] = OK
    return state
end

# Export public types and functions
export dispatch_host_call, HostCallContext, ServiceAccount
export OK, NONE, WHAT, OOB, WHO, FULL, CORE, CASH, LOW, HUH

end
