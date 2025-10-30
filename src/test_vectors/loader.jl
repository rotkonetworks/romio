# Test Vector Loader
# Loads JAM test vectors from JSON and converts to internal State representation

using JSON3

# Include necessary types
include("../types/basic.jl")
include("../types/accumulate.jl")

# Simplified State type for test vectors
struct State
    slot::TimeSlot
    entropy::Blob
    accounts::Dict{ServiceId, ServiceAccount}
    privileges::PrivilegedState
    accumulated::Dict{ServiceId, Blob}
    ready_queue::Vector{Any}
    statistics::Vector{Any}
    validators::Vector{Any}
    epoch::UInt32
    validators_next_epoch::UInt32
end

# Parse hex string to bytes
function parse_hex(hex_str::String)::Vector{UInt8}
    # Remove 0x prefix if present
    hex_str = startswith(hex_str, "0x") ? hex_str[3:end] : hex_str
    # Handle empty string
    if isempty(hex_str)
        return UInt8[]
    end
    # Convert pairs of hex digits to bytes
    return [parse(UInt8, hex_str[i:i+1], base=16) for i in 1:2:length(hex_str)]
end

# Parse service account from JSON
function parse_service_account(json_data)::ServiceAccount
    # Check if this is accumulate test vector format (has :service field)
    if haskey(json_data, :service)
        service_data = json_data[:service]
        code_hash = parse_hex(service_data[:code_hash])
        balance = UInt64(service_data[:balance])
        min_acc_gas = UInt64(service_data[:min_item_gas])
        min_memo_gas = UInt64(service_data[:min_memo_gas])

        # Create account with accumulate format fields
        account = ServiceAccount(
            code_hash,
            balance,
            min_acc_gas,
            min_memo_gas,
            gratis = UInt64(get(service_data, :gratis, 0)),
            created = UInt32(service_data[:creation_slot]),
            parent = UInt32(service_data[:parent_service])
        )

        # Set additional fields from service data
        account.octets = UInt64(service_data[:bytes])
        account.items = UInt32(service_data[:items])
        account.min_balance = UInt64(get(service_data, :deposit_offset, 0))
        account.last_acc = UInt32(service_data[:last_accumulation_slot])

    else
        # Preimage test vector format (direct fields)
        code_hash = parse_hex(get(json_data, :code_hash, "0x" * "00"^32))
        balance = UInt64(get(json_data, :balance, 0))
        min_acc_gas = UInt64(get(json_data, :threshold_gas, 0))
        min_memo_gas = UInt64(get(json_data, :min_gas_limit, 0))

        # Create account with defaults
        account = ServiceAccount(
            code_hash,
            balance,
            min_acc_gas,
            min_memo_gas,
            gratis = UInt64(get(json_data, :gratis, 0)),
            created = UInt32(get(json_data, :creation_slot, 0)),
            parent = UInt32(get(json_data, :parent, 0))
        )

        # Set account metadata
        account.octets = UInt64(get(json_data, :octets, 0))
        account.items = UInt32(get(json_data, :items, 0))
        account.min_balance = UInt64(get(json_data, :threshold_balance, 0))
        account.last_acc = UInt32(get(json_data, :last_accumulate_slot, 0))
    end

    # Load storage if present
    if haskey(json_data, :storage)
        for item in json_data[:storage]
            key = parse_hex(item[:key])
            value = parse_hex(item[:value])
            account.storage[key] = value
        end
    end

    # Load preimages if present (check both :preimages and :preimages_blob)
    preimage_field = if haskey(json_data, :preimages)
        :preimages
    elseif haskey(json_data, :preimages_blob)
        :preimages_blob
    else
        nothing
    end

    if preimage_field !== nothing
        for item in json_data[preimage_field]
            hash = parse_hex(item[:hash])
            blob = parse_hex(item[:blob])
            account.preimages[hash] = blob
        end
    end

    # Load preimage metadata (lookup_meta) if present
    if haskey(json_data, :lookup_meta)
        for item in json_data[:lookup_meta]
            hash = parse_hex(item[:key][:hash])
            preimage_length = UInt64(item[:key][:length])
            timeslots = UInt64.(get(item, :value, UInt64[]))

            # Convert to PreimageRequest state machine
            key = (hash, preimage_length)
            num_slots = Base.length(timeslots)
            if num_slots == 0
                # [] state
                account.requests[key] = PreimageRequest([])
            elseif num_slots == 1
                # [x] state
                account.requests[key] = PreimageRequest([timeslots[1]])
            elseif num_slots == 2
                # [x, y] state
                account.requests[key] = PreimageRequest([timeslots[1], timeslots[2]])
            else
                # [x, y, z] state
                account.requests[key] = PreimageRequest([timeslots[1], timeslots[2], timeslots[3]])
            end
        end
    end

    return account
end

# Parse privileged state from JSON
function parse_privileges(json_data)::PrivilegedState
    priv = PrivilegedState(
        ServiceId(0),
        Vector{ServiceId}(),
        ServiceId(0),
        ServiceId(0),
        Vector{Blob}(),
        Vector{Vector{Blob}}(),
        Vector{Tuple{ServiceId, Gas}}()
    )

    if haskey(json_data, :bless)
        priv.manager = ServiceId(json_data[:bless])
    end

    if haskey(json_data, :assign)
        priv.assigners = ServiceId.(json_data[:assign])
    end

    if haskey(json_data, :designate)
        priv.delegator = ServiceId(json_data[:designate])
    end

    if haskey(json_data, :register)
        priv.registrar = ServiceId(json_data[:register])
    end

    # TODO: staging_set, auth_queue, always_access parsing

    return priv
end

# Load full state from JSON
function load_state_from_json(json_data)::State
    slot = UInt32(get(json_data, :slot, 0))

    # Parse entropy
    entropy = if haskey(json_data, :entropy)
        parse_hex(json_data[:entropy])
    else
        zeros(UInt8, 32)
    end

    # Parse accounts
    accounts = Dict{ServiceId, ServiceAccount}()
    if haskey(json_data, :accounts)
        for acc_entry in json_data[:accounts]
            service_id = ServiceId(acc_entry[:id])
            account_data = acc_entry[:data]
            accounts[service_id] = parse_service_account(account_data)
        end
    end

    # Parse privileges
    privileges = if haskey(json_data, :privileges)
        parse_privileges(json_data[:privileges])
    else
        PrivilegedState(
            ServiceId(0), Vector{ServiceId}(), ServiceId(0), ServiceId(0),
            Vector{Blob}(), Vector{Vector{Blob}}(), Vector{Tuple{ServiceId, Gas}}()
        )
    end

    # TODO: Parse other state fields (accumulated, ready_queue, statistics, etc.)

    return State(
        slot,
        entropy,
        accounts,
        privileges,
        Dict{ServiceId, Vector{UInt8}}(),  # accumulated (placeholder)
        Vector{Any}(),  # ready_queue (placeholder)
        Vector{Any}(),  # statistics (placeholder)
        Vector{Any}(),  # validators (placeholder)
        UInt32(0),      # epoch
        UInt32(0)       # validators_next_epoch
    )
end

# Load test vector from JSON file
function load_test_vector(filepath::String)
    json_str = read(filepath, String)
    data = JSON3.read(json_str)

    return (
        input = data[:input],
        pre_state = load_state_from_json(data[:pre_state]),
        post_state = load_state_from_json(data[:post_state]),
        output = data[:output]
    )
end

# Export functions
export parse_hex, parse_service_account, parse_privileges
export load_state_from_json, load_test_vector
