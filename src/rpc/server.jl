# JIP-2: Node RPC Implementation
# JSON-RPC 2.0 server over WebSocket (port 19800)

module RPC

using JSON
using Sockets
using Base64
using SHA
using Dates

export RPCServer, start!, stop!, register_handler!

# ===== JSON-RPC 2.0 Types =====

struct RPCError
    code::Int
    message::String
    data::Any
end

# JIP-2 Error Codes
const ERR_BLOCK_UNAVAILABLE = 1
const ERR_WORK_REPORT_UNAVAILABLE = 2
const ERR_DA_SEGMENT_UNAVAILABLE = 3
const ERR_OTHER = 0

# Standard JSON-RPC errors
const ERR_PARSE = -32700
const ERR_INVALID_REQUEST = -32600
const ERR_METHOD_NOT_FOUND = -32601
const ERR_INVALID_PARAMS = -32602
const ERR_INTERNAL = -32603

# ===== Subscription Management =====

mutable struct Subscription
    id::Int
    method::String
    params::Vector{Any}
    client_id::UInt64
    created_at::Float64
end

mutable struct SubscriptionManager
    subscriptions::Dict{Int, Subscription}
    next_id::Int
    lock::ReentrantLock
end

SubscriptionManager() = SubscriptionManager(Dict{Int, Subscription}(), 1, ReentrantLock())

function create_subscription!(mgr::SubscriptionManager, method::String, params::Vector{Any}, client_id::UInt64)::Int
    lock(mgr.lock) do
        id = mgr.next_id
        mgr.next_id += 1
        mgr.subscriptions[id] = Subscription(id, method, params, client_id, time())
        return id
    end
end

function remove_subscription!(mgr::SubscriptionManager, id::Int)::Bool
    lock(mgr.lock) do
        if haskey(mgr.subscriptions, id)
            delete!(mgr.subscriptions, id)
            return true
        end
        return false
    end
end

function get_subscriptions_for_client(mgr::SubscriptionManager, client_id::UInt64)::Vector{Subscription}
    lock(mgr.lock) do
        return [s for s in values(mgr.subscriptions) if s.client_id == client_id]
    end
end

# ===== Block Descriptor =====

struct BlockDescriptor
    header_hash::Vector{UInt8}  # 32 bytes
    slot::UInt64
end

function block_descriptor_to_json(bd::BlockDescriptor)::Dict{String, Any}
    Dict{String, Any}(
        "header_hash" => base64encode(bd.header_hash),
        "slot" => bd.slot
    )
end

# ===== Chain State Interface =====

abstract type ChainState end

# Mock chain state for testing
mutable struct MockChainState <: ChainState
    best_block::BlockDescriptor
    finalized_block::BlockDescriptor
    blocks::Dict{Vector{UInt8}, Any}
    services::Dict{UInt32, Dict{String, Any}}
    parameters::Dict{String, Any}
end

function MockChainState()
    genesis_hash = zeros(UInt8, 32)
    MockChainState(
        BlockDescriptor(genesis_hash, 0),
        BlockDescriptor(genesis_hash, 0),
        Dict{Vector{UInt8}, Any}(),
        Dict{UInt32, Dict{String, Any}}(),
        default_parameters()
    )
end

"""
    register_block!(chain_state, header_hash, slot, parent_hash, parent_slot)

Register a block in the chain state for parent lookup.
"""
function register_block!(
    chain_state::MockChainState,
    header_hash::Vector{UInt8},
    slot::UInt64,
    parent_hash::Vector{UInt8},
    parent_slot::UInt64
)
    chain_state.blocks[header_hash] = Dict{String, Any}(
        "slot" => slot,
        "parent_hash" => parent_hash,
        "parent_slot" => parent_slot
    )
end

"""
    update_chain_state!(chain_state, best_hash, best_slot, finalized_hash, finalized_slot)

Update best and finalized block in chain state.
"""
function update_chain_state!(
    chain_state::MockChainState,
    best_hash::Vector{UInt8},
    best_slot::UInt64,
    finalized_hash::Vector{UInt8},
    finalized_slot::UInt64
)
    chain_state.best_block = BlockDescriptor(best_hash, best_slot)
    chain_state.finalized_block = BlockDescriptor(finalized_hash, finalized_slot)
end

function default_parameters()::Dict{String, Any}
    Dict{String, Any}(
        "V1" => Dict{String, Any}(
            "deposit_per_item" => 10,
            "deposit_per_byte" => 1,
            "deposit_per_account" => 100000,
            "core_count" => 341,
            "min_turnaround_period" => 19200,
            "epoch_period" => 600,
            "max_accumulate_gas" => 10000000,
            "max_is_authorized_gas" => 50000000,
            "max_refine_gas" => 50000000000,
            "block_gas_limit" => 25000000000,
            "recent_block_count" => 8192,
            "max_work_items" => 4,
            "max_dependencies" => 8,
            "max_tickets_per_block" => 16,
            "max_lookup_anchor_age" => 14400,
            "tickets_attempts_number" => 2,
            "auth_window" => 80,
            "slot_period_sec" => 6,
            "auth_queue_len" => 80,
            "rotation_period" => 10,
            "max_extrinsics" => 16,
            "availability_timeout" => 80,
            "val_count" => 1023,
            "max_authorizer_code_size" => 65536,
            "max_input" => 12582912,
            "max_service_code_size" => 4194304,
            "basic_piece_len" => 342,
            "max_imports" => 2048,
            "segment_piece_count" => 12,
            "max_report_elective_data" => 4096,
            "transfer_memo_size" => 128,
            "max_exports" => 3072,
            "epoch_tail_start" => 540
        )
    )
end

# ===== RPC Server =====

mutable struct RPCServer
    host::String
    port::UInt16
    handlers::Dict{String, Function}
    subscriptions::SubscriptionManager
    chain_state::ChainState
    server::Union{Sockets.TCPServer, Nothing}
    clients::Dict{UInt64, Any}
    running::Bool
    next_client_id::UInt64
    # Track finalized block subscriptions: sub_id => client_id
    finalized_block_subs::Dict{Int64, UInt64}
    # Track best block subscriptions: sub_id => client_id
    best_block_subs::Dict{Int64, UInt64}
    # Track service request subscriptions: sub_id => (client_id, service_id, hash, len)
    service_request_subs::Dict{Int64, Tuple{UInt64, UInt32, Vector{UInt8}, Int}}
    # Track service value subscriptions: sub_id => (client_id, service_id, key, finalized)
    service_value_subs::Dict{Int64, Tuple{UInt64, UInt32, Vector{UInt8}, Bool}}
end

function RPCServer(; host::String="::", port::UInt16=UInt16(19800), chain_state::ChainState=MockChainState())
    server = RPCServer(
        host, port,
        Dict{String, Function}(),
        SubscriptionManager(),
        chain_state,
        nothing,
        Dict{UInt64, Any}(),
        false,
        1,
        Dict{Int64, UInt64}(),  # finalized_block_subs
        Dict{Int64, UInt64}(),  # best_block_subs
        Dict{Int64, Tuple{UInt64, UInt32, Vector{UInt8}, Int}}(),  # service_request_subs
        Dict{Int64, Tuple{UInt64, UInt32, Vector{UInt8}, Bool}}()  # service_value_subs
    )
    register_default_handlers!(server)
    return server
end

function register_handler!(server::RPCServer, method::String, handler::Function)
    server.handlers[method] = handler
end

# ===== Default RPC Handlers =====

function register_default_handlers!(server::RPCServer)
    # Chain info
    register_handler!(server, "parameters", (s, p) -> rpc_parameters(s, p))
    register_handler!(server, "bestBlock", (s, p) -> rpc_best_block(s, p))
    register_handler!(server, "finalizedBlock", (s, p) -> rpc_finalized_block(s, p))
    register_handler!(server, "parent", (s, p) -> rpc_parent(s, p))
    register_handler!(server, "stateRoot", (s, p) -> rpc_state_root(s, p))
    register_handler!(server, "beefyRoot", (s, p) -> rpc_beefy_root(s, p))
    register_handler!(server, "statistics", (s, p) -> rpc_statistics(s, p))

    # Service queries
    register_handler!(server, "serviceData", (s, p) -> rpc_service_data(s, p))
    register_handler!(server, "serviceValue", (s, p) -> rpc_service_value(s, p))
    register_handler!(server, "servicePreimage", (s, p) -> rpc_service_preimage(s, p))
    register_handler!(server, "serviceRequest", (s, p) -> rpc_service_request(s, p))
    register_handler!(server, "listServices", (s, p) -> rpc_list_services(s, p))

    # Work packages
    register_handler!(server, "workReport", (s, p) -> rpc_work_report(s, p))
    register_handler!(server, "submitWorkPackage", (s, p) -> rpc_submit_work_package(s, p))
    register_handler!(server, "submitWorkPackageBundle", (s, p) -> rpc_submit_work_package_bundle(s, p))
    register_handler!(server, "workPackageStatus", (s, p) -> rpc_work_package_status(s, p))

    # DA layer
    register_handler!(server, "fetchWorkPackageSegments", (s, p) -> rpc_fetch_wp_segments(s, p))
    register_handler!(server, "fetchSegments", (s, p) -> rpc_fetch_segments(s, p))

    # Preimages
    register_handler!(server, "submitPreimage", (s, p) -> rpc_submit_preimage(s, p))

    # Sync state
    register_handler!(server, "syncState", (s, p) -> rpc_sync_state(s, p))

    # Subscriptions
    register_handler!(server, "subscribeBestBlock", (s, p) -> rpc_subscribe_best_block(s, p))
    register_handler!(server, "unsubscribeBestBlock", (s, p) -> rpc_unsubscribe(s, p))
    register_handler!(server, "subscribeFinalizedBlock", (s, p) -> rpc_subscribe_finalized_block(s, p))
    register_handler!(server, "unsubscribeFinalizedBlock", (s, p) -> rpc_unsubscribe(s, p))
    register_handler!(server, "subscribeStatistics", (s, p) -> rpc_subscribe_statistics(s, p))
    register_handler!(server, "unsubscribeStatistics", (s, p) -> rpc_unsubscribe(s, p))
    register_handler!(server, "subscribeServiceData", (s, p) -> rpc_subscribe_service_data(s, p))
    register_handler!(server, "unsubscribeServiceData", (s, p) -> rpc_unsubscribe(s, p))
    register_handler!(server, "subscribeServiceValue", (s, p) -> rpc_subscribe_service_value(s, p))
    register_handler!(server, "unsubscribeServiceValue", (s, p) -> rpc_unsubscribe(s, p))
    register_handler!(server, "subscribeWorkPackageStatus", (s, p) -> rpc_subscribe_wp_status(s, p))
    register_handler!(server, "unsubscribeWorkPackageStatus", (s, p) -> rpc_unsubscribe(s, p))
    register_handler!(server, "subscribeSyncStatus", (s, p) -> rpc_subscribe_sync_status(s, p))
    register_handler!(server, "unsubscribeSyncStatus", (s, p) -> rpc_unsubscribe(s, p))
    register_handler!(server, "subscribeServiceRequest", (s, p) -> rpc_subscribe_service_request(s, p))
    register_handler!(server, "unsubscribeServiceRequest", (s, p) -> rpc_unsubscribe(s, p))
end

# ===== RPC Method Implementations =====

function rpc_parameters(server::RPCServer, params::Vector{Any})
    return server.chain_state.parameters
end

function rpc_best_block(server::RPCServer, params::Vector{Any})
    return block_descriptor_to_json(server.chain_state.best_block)
end

function rpc_finalized_block(server::RPCServer, params::Vector{Any})
    return block_descriptor_to_json(server.chain_state.finalized_block)
end

function rpc_parent(server::RPCServer, params::Vector{Any})
    length(params) < 1 && throw(RPCError(ERR_INVALID_PARAMS, "Missing header_hash parameter", nothing))
    header_hash = base64decode(params[1])

    # Look up block in chain state
    if haskey(server.chain_state.blocks, header_hash)
        block_info = server.chain_state.blocks[header_hash]
        parent_hash = get(block_info, "parent_hash", nothing)
        parent_slot = get(block_info, "parent_slot", nothing)

        if parent_hash !== nothing && parent_slot !== nothing
            return block_descriptor_to_json(BlockDescriptor(parent_hash, UInt64(parent_slot)))
        end
    end

    # For genesis block (slot 0), there's no parent - return null
    # Check if this is the genesis block
    if header_hash == server.chain_state.finalized_block.header_hash &&
       server.chain_state.finalized_block.slot == 0
        return nothing  # Genesis has no parent
    end

    throw(RPCError(ERR_BLOCK_UNAVAILABLE, "Block not found", base64encode(header_hash)))
end

function rpc_state_root(server::RPCServer, params::Vector{Any})
    length(params) < 1 && throw(RPCError(ERR_INVALID_PARAMS, "Missing header_hash parameter", nothing))
    # TODO: Implement state root lookup
    return base64encode(zeros(UInt8, 32))
end

function rpc_beefy_root(server::RPCServer, params::Vector{Any})
    length(params) < 1 && throw(RPCError(ERR_INVALID_PARAMS, "Missing header_hash parameter", nothing))
    # TODO: Implement BEEFY root lookup
    return base64encode(zeros(UInt8, 32))
end

function rpc_statistics(server::RPCServer, params::Vector{Any})
    length(params) < 1 && throw(RPCError(ERR_INVALID_PARAMS, "Missing header_hash parameter", nothing))
    # TODO: Implement statistics lookup
    return base64encode(UInt8[])
end

function rpc_service_data(server::RPCServer, params::Vector{Any})
    length(params) < 2 && throw(RPCError(ERR_INVALID_PARAMS, "Missing parameters", nothing))
    service_id = UInt32(params[2])
    if haskey(server.chain_state.services, service_id)
        return base64encode(JSON.json(server.chain_state.services[service_id]))
    end
    return nothing
end

function rpc_service_value(server::RPCServer, params::Vector{Any})
    length(params) < 3 && throw(RPCError(ERR_INVALID_PARAMS, "Missing parameters", nothing))
    # TODO: Implement service value lookup
    return nothing
end

function rpc_service_preimage(server::RPCServer, params::Vector{Any})
    length(params) < 3 && throw(RPCError(ERR_INVALID_PARAMS, "Missing parameters", nothing))
    # TODO: Implement preimage lookup
    return nothing
end

function rpc_service_request(server::RPCServer, params::Vector{Any})
    length(params) < 4 && throw(RPCError(ERR_INVALID_PARAMS, "Missing parameters", nothing))
    # TODO: Implement request lookup
    return nothing
end

function rpc_list_services(server::RPCServer, params::Vector{Any})
    return collect(keys(server.chain_state.services))
end

function rpc_work_report(server::RPCServer, params::Vector{Any})
    length(params) < 1 && throw(RPCError(ERR_INVALID_PARAMS, "Missing hash parameter", nothing))
    # TODO: Implement work report lookup
    throw(RPCError(ERR_WORK_REPORT_UNAVAILABLE, "Work report not found", params[1]))
end

function rpc_submit_work_package(server::RPCServer, params::Vector{Any})
    length(params) < 3 && throw(RPCError(ERR_INVALID_PARAMS, "Missing parameters", nothing))
    # TODO: Implement work package submission
    return nothing
end

function rpc_submit_work_package_bundle(server::RPCServer, params::Vector{Any})
    length(params) < 2 && throw(RPCError(ERR_INVALID_PARAMS, "Missing parameters", nothing))
    # TODO: Implement bundle submission
    return nothing
end

function rpc_work_package_status(server::RPCServer, params::Vector{Any})
    length(params) < 3 && throw(RPCError(ERR_INVALID_PARAMS, "Missing parameters", nothing))
    # Return "Unknown" for work packages we haven't seen
    # serde enum format: single-key map with null value for unit variant
    return Dict{String, Any}("Unknown" => nothing)
end

function rpc_fetch_wp_segments(server::RPCServer, params::Vector{Any})
    length(params) < 2 && throw(RPCError(ERR_INVALID_PARAMS, "Missing parameters", nothing))
    # TODO: Implement DA segment fetching
    throw(RPCError(ERR_DA_SEGMENT_UNAVAILABLE, "Segments not available", nothing))
end

function rpc_fetch_segments(server::RPCServer, params::Vector{Any})
    length(params) < 2 && throw(RPCError(ERR_INVALID_PARAMS, "Missing parameters", nothing))
    # TODO: Implement DA segment fetching
    throw(RPCError(ERR_DA_SEGMENT_UNAVAILABLE, "Segments not available", nothing))
end

function rpc_submit_preimage(server::RPCServer, params::Vector{Any})
    # Format: [service_id, data_base64]
    length(params) < 2 && throw(RPCError(ERR_INVALID_PARAMS, "Missing parameters for submitPreimage", nothing))

    service_id = UInt32(params[1])
    data = base64decode(params[2])
    data_len = length(data)

    println("submitPreimage: service=$(service_id), len=$(data_len)")

    # Store in submitted_preimages for the testnet to process
    push!(server.chain_state.submitted_preimages, (service_id, data))
    println("  Queued $(data_len) bytes for service $(service_id)")

    # Return true to indicate success (matches polkajam behavior)
    return true
end

function rpc_sync_state(server::RPCServer, params::Vector{Any})
    return Dict{String, Any}(
        "num_peers" => 0,
        "status" => "Completed"
    )
end

# Subscription handlers (return subscription ID)
function rpc_subscribe_best_block(server::RPCServer, params::Vector{Any})
    # Generate a subscription ID
    sub_id = rand(Int64) & 0x7FFFFFFFFFFFFFFF  # Positive int64
    # Mark that this subscription needs a notification to be sent
    return (sub_id, :best_block_notification)
end

function rpc_subscribe_finalized_block(server::RPCServer, params::Vector{Any})
    # Generate a subscription ID
    sub_id = rand(Int64) & 0x7FFFFFFFFFFFFFFF  # Positive int64
    # Mark that this subscription needs a notification to be sent
    return (sub_id, :finalized_block_notification)
end

function rpc_subscribe_statistics(server::RPCServer, params::Vector{Any})
    return 1
end

function rpc_subscribe_service_data(server::RPCServer, params::Vector{Any})
    return 1
end

function rpc_subscribe_service_value(server::RPCServer, params::Vector{Any})
    # jamt calls this to monitor when service storage values change
    # Format: [service_id, key (base64), finalized]
    if length(params) < 3
        throw(RPCError(ERR_INVALID_PARAMS, "Missing parameters for subscribeServiceValue", nothing))
    end
    service_id = UInt32(params[1])
    key = base64decode(params[2])
    finalized = Bool(params[3])

    # Generate subscription ID
    sub_id = rand(Int64) & 0x7FFFFFFFFFFFFFFF  # Positive int64

    println("subscribeServiceValue: service=$(service_id), key=$(bytes2hex(key[1:min(8, length(key))]))..., finalized=$(finalized)")

    # Return (sub_id, notification_type, service_id, key, finalized) for storage
    return (sub_id, :service_value_notification, service_id, key, finalized)
end

function rpc_subscribe_wp_status(server::RPCServer, params::Vector{Any})
    return 1
end

function rpc_subscribe_sync_status(server::RPCServer, params::Vector{Any})
    # Generate a subscription ID (use a large random number like polkajam does)
    sub_id = rand(Int64) & 0x7FFFFFFFFFFFFFFF  # Positive int64
    # Mark that this subscription needs a notification to be sent
    # We'll handle the notification in handle_websocket_message
    return (sub_id, :sync_status_notification)
end

function rpc_subscribe_service_request(server::RPCServer, params::Vector{Any})
    # jamt calls this to monitor when service request data is available
    # Format: [service_id, hash (base64), len, finalized]
    if length(params) < 3
        throw(RPCError(ERR_INVALID_PARAMS, "Missing parameters for subscribeServiceRequest", nothing))
    end
    service_id = UInt32(params[1])
    preimage_hash = base64decode(params[2])
    preimage_len = Int(params[3])

    # Generate subscription ID
    sub_id = rand(Int64) & 0x7FFFFFFFFFFFFFFF  # Positive int64

    # Return (sub_id, notification_type, service_id, hash, len) for storage
    return (sub_id, :service_request_notification, service_id, preimage_hash, preimage_len)
end

function rpc_unsubscribe(server::RPCServer, params::Vector{Any})
    length(params) < 1 && throw(RPCError(ERR_INVALID_PARAMS, "Missing subscription ID", nothing))
    sub_id = params[1]

    # Remove from all subscription dicts
    delete!(server.finalized_block_subs, sub_id)
    delete!(server.best_block_subs, sub_id)
    delete!(server.service_request_subs, sub_id)
    delete!(server.service_value_subs, sub_id)

    return true
end

# ===== Request Processing =====

function process_request(server::RPCServer, request, client_id::UInt64)::Dict{String, Any}
    # Convert JSON.Object to Dict if needed
    req = request isa Dict ? request : Dict{String, Any}(request)
    id = get(req, "id", nothing)
    method = get(req, "method", nothing)
    params = get(req, "params", Any[])

    # DEBUG: Log all incoming requests
    @info "RPC REQUEST" method=method id=id params_count=length(params isa Vector ? params : [])

    # Validate request
    if isnothing(method)
        return make_error_response(id, ERR_INVALID_REQUEST, "Missing method")
    end

    if !isa(params, Vector)
        return make_error_response(id, ERR_INVALID_PARAMS, "Params must be an array")
    end

    # Find and execute handler
    if !haskey(server.handlers, method)
        return make_error_response(id, ERR_METHOD_NOT_FOUND, "Method not found: $method")
    end

    try
        result = server.handlers[method](server, params)
        response = make_success_response(id, result)
        # DEBUG: Log response for tracking
        @info "RPC RESPONSE" method=method id=id result_type=typeof(result) result_json=JSON.json(response)
        return response
    catch e
        if isa(e, RPCError)
            return make_error_response(id, e.code, e.message, e.data)
        else
            return make_error_response(id, ERR_INTERNAL, string(e))
        end
    end
end

function make_success_response(id, result)::Dict{String, Any}
    response = Dict{String, Any}(
        "jsonrpc" => "2.0",
        "result" => result
    )
    !isnothing(id) && (response["id"] = id)
    return response
end

function make_error_response(id, code::Int, message::String, data=nothing)::Dict{String, Any}
    error_obj = Dict{String, Any}(
        "code" => code,
        "message" => message
    )
    !isnothing(data) && (error_obj["data"] = data)

    response = Dict{String, Any}(
        "jsonrpc" => "2.0",
        "error" => error_obj
    )
    !isnothing(id) && (response["id"] = id)
    return response
end

# ===== WebSocket Handling =====

function handle_websocket_message(server::RPCServer, data::Vector{UInt8}, client_id::UInt64)
    try
        request = JSON.parse(String(data))

        # Handle batch requests
        if isa(request, AbstractVector)
            responses = [process_request(server, req, client_id) for req in request]
            return Vector{UInt8}[Vector{UInt8}(JSON.json(responses))]
        else
            response = process_request(server, request, client_id)

            # Check if result needs a follow-up notification (before creating frames)
            frames = Vector{UInt8}[]  # Use properly typed vector
            if haskey(response, "result") && isa(response["result"], Tuple) && length(response["result"]) >= 2
                result_tuple = response["result"]
                sub_id = result_tuple[1]
                notification_type = result_tuple[2]
                # Fix the response to only contain the subscription ID BEFORE serializing
                response["result"] = sub_id
                push!(frames, Vector{UInt8}(JSON.json(response)))

                # Add notification frame based on type
                if notification_type == :sync_status_notification
                    # Format matches polkajam: {"jsonrpc":"2.0","method":"subscribeSyncStatus","params":{"subscription":ID,"result":"Completed"}}
                    notification = Dict{String, Any}(
                        "jsonrpc" => "2.0",
                        "method" => "subscribeSyncStatus",
                        "params" => Dict{String, Any}(
                            "subscription" => sub_id,
                            "result" => "Completed"
                        )
                    )
                    push!(frames, Vector{UInt8}(JSON.json(notification)))
                elseif notification_type == :finalized_block_notification
                    # Store the subscription for future updates
                    server.finalized_block_subs[sub_id] = client_id
                    # Send finalized block notification with the current finalized block
                    finalized = server.chain_state.finalized_block
                    notification = Dict{String, Any}(
                        "jsonrpc" => "2.0",
                        "method" => "subscribeFinalizedBlock",
                        "params" => Dict{String, Any}(
                            "subscription" => sub_id,
                            "result" => block_descriptor_to_json(finalized)
                        )
                    )
                    push!(frames, Vector{UInt8}(JSON.json(notification)))
                elseif notification_type == :best_block_notification
                    # Store the subscription for future updates
                    server.best_block_subs[sub_id] = client_id
                    # Send best block notification with the current best block
                    best = server.chain_state.best_block
                    notification = Dict{String, Any}(
                        "jsonrpc" => "2.0",
                        "method" => "subscribeBestBlock",
                        "params" => Dict{String, Any}(
                            "subscription" => sub_id,
                            "result" => block_descriptor_to_json(best)
                        )
                    )
                    push!(frames, Vector{UInt8}(JSON.json(notification)))
                elseif notification_type == :service_request_notification
                    # jamt subscribes to service request availability
                    # Extract subscription parameters from extended tuple
                    if length(result_tuple) >= 5
                        service_id = result_tuple[3]
                        preimage_hash = result_tuple[4]
                        preimage_len = result_tuple[5]
                        server.service_request_subs[sub_id] = (client_id, service_id, preimage_hash, preimage_len)
                        println("Registered service request subscription: sub_id=$(sub_id), service=$(service_id), hash=$(bytes2hex(preimage_hash[1:min(8, length(preimage_hash))]))..., len=$(preimage_len)")
                    end
                    # Don't send immediate notification - wait for preimage availability
                elseif notification_type == :service_value_notification
                    # jamt subscribes to service value changes (e.g. new service created)
                    # Extract subscription parameters from extended tuple
                    if length(result_tuple) >= 5
                        service_id = result_tuple[3]
                        key = result_tuple[4]
                        finalized = result_tuple[5]
                        server.service_value_subs[sub_id] = (client_id, service_id, key, finalized)
                        println("Registered service value subscription: sub_id=$(sub_id), service=$(service_id), key=$(bytes2hex(key[1:min(8, length(key))]))..., finalized=$(finalized)")

                        # JIP-2 requires sending an immediate notification with the current value
                        # For a new subscription, the value is null (no service created yet)
                        block = finalized ? server.chain_state.finalized_block : server.chain_state.best_block
                        initial_notification = Dict{String, Any}(
                            "jsonrpc" => "2.0",
                            "method" => "subscribeServiceValue",
                            "params" => Dict{String, Any}(
                                "subscription" => sub_id,
                                "result" => Dict{String, Any}(
                                    "header_hash" => base64encode(block.header_hash),
                                    "slot" => block.slot,
                                    "value" => nothing  # null - no value exists yet
                                )
                            )
                        )
                        push!(frames, Vector{UInt8}(JSON.json(initial_notification)))
                        println("Sent initial subscribeServiceValue notification with value=null")
                    end
                end
            else
                # Non-tuple result, just serialize as-is
                push!(frames, Vector{UInt8}(JSON.json(response)))
            end

            return frames
        end
    catch e
        # Handle JSON parse errors (ArgumentError in newer JSON.jl)
        if isa(e, ArgumentError) || contains(string(typeof(e)), "Parser")
            return Vector{UInt8}[Vector{UInt8}(JSON.json(make_error_response(nothing, ERR_PARSE, "Parse error")))]
        end
        return Vector{UInt8}[Vector{UInt8}(JSON.json(make_error_response(nothing, ERR_INTERNAL, string(e))))]
    end
end

# Simple HTTP/WebSocket server (basic implementation)
function start!(server::RPCServer)
    server.running = true
    # Bind to IPv6 (:: binds to all interfaces, supports both v4 and v6 on dual-stack)
    server.server = listen(IPv6(server.host), server.port)

    println("RPC server started on $(server.host):$(server.port)")

    @async while server.running
        try
            client = accept(server.server)
            client_id = server.next_client_id
            server.next_client_id += 1
            server.clients[client_id] = client

            @async handle_client(server, client, client_id)
        catch e
            server.running || break
            println("RPC accept error: $e")
        end
    end
end

function handle_client(server::RPCServer, client, client_id::UInt64)
    try
        # Read HTTP request
        request_line = readline(client)
        headers = Dict{String, String}()

        while true
            line = readline(client)
            isempty(line) && break
            if contains(line, ":")
                key, value = split(line, ":", limit=2)
                headers[strip(key)] = strip(value)
            end
        end

        # Check for WebSocket upgrade
        if get(headers, "Upgrade", "") == "websocket"
            handle_websocket_upgrade(server, client, client_id, headers)
        else
            # Handle as plain HTTP JSON-RPC
            handle_http_request(server, client, client_id, headers)
        end
    catch e
        println("Client error: $e")
    finally
        delete!(server.clients, client_id)
        close(client)
    end
end

function handle_websocket_upgrade(server::RPCServer, client, client_id::UInt64, headers::Dict{String, String})
    ws_key = get(headers, "Sec-WebSocket-Key", "")
    if isempty(ws_key)
        write(client, "HTTP/1.1 400 Bad Request\r\n\r\n")
        return
    end

    # Calculate accept key
    magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    accept_key = base64encode(sha1(ws_key * magic))

    # Send upgrade response
    response = """HTTP/1.1 101 Switching Protocols\r
Upgrade: websocket\r
Connection: Upgrade\r
Sec-WebSocket-Accept: $accept_key\r
\r
"""
    write(client, response)

    # WebSocket message loop
    while server.running && isopen(client)
        try
            frame = read_websocket_frame(client)
            isnothing(frame) && break

            responses = handle_websocket_message(server, frame, client_id)
            # Send all response frames (supports subscription notifications)
            for response in responses
                write_websocket_frame(client, response)
            end
        catch e
            isa(e, EOFError) && break
            println("WebSocket error: $e")
            break
        end
    end
end

function read_websocket_frame(io)::Union{Vector{UInt8}, Nothing}
    header = read(io, 2)
    length(header) < 2 && return nothing

    fin = (header[1] & 0x80) != 0
    opcode = header[1] & 0x0f

    # Close frame
    opcode == 0x08 && return nothing

    masked = (header[2] & 0x80) != 0
    payload_len = header[2] & 0x7f

    if payload_len == 126
        len_bytes = read(io, 2)
        payload_len = UInt64(len_bytes[1]) << 8 | len_bytes[2]
    elseif payload_len == 127
        len_bytes = read(io, 8)
        payload_len = 0
        for b in len_bytes
            payload_len = payload_len << 8 | b
        end
    end

    mask_key = masked ? read(io, 4) : UInt8[]
    payload = read(io, payload_len)

    # Unmask if needed
    if masked
        for i in 1:length(payload)
            payload[i] = payload[i] ⊻ mask_key[((i-1) % 4) + 1]
        end
    end

    return payload
end

function write_websocket_frame(io, data::Vector{UInt8})
    # Text frame, FIN bit set
    header = UInt8[0x81]

    len = length(data)
    if len < 126
        push!(header, UInt8(len))
    elseif len < 65536
        push!(header, 126)
        push!(header, UInt8((len >> 8) & 0xff))
        push!(header, UInt8(len & 0xff))
    else
        push!(header, 127)
        for i in 7:-1:0
            push!(header, UInt8((len >> (8*i)) & 0xff))
        end
    end

    write(io, header)
    write(io, data)
    flush(io)
end

function handle_http_request(server::RPCServer, client, client_id::UInt64, headers::Dict{String, String})
    # Read body
    content_length = parse(Int, get(headers, "Content-Length", "0"))
    body = content_length > 0 ? read(client, content_length) : UInt8[]

    if isempty(body)
        write(client, "HTTP/1.1 400 Bad Request\r\n\r\n")
        return
    end

    response_body = handle_websocket_message(server, body, client_id)

    response = """HTTP/1.1 200 OK\r
Content-Type: application/json\r
Content-Length: $(length(response_body))\r
Access-Control-Allow-Origin: *\r
\r
"""
    write(client, response)
    write(client, response_body)
end

function stop!(server::RPCServer)
    server.running = false
    if !isnothing(server.server)
        close(server.server)
        server.server = nothing
    end
    for (_, client) in server.clients
        try; close(client); catch; end
    end
    empty!(server.clients)
    println("RPC server stopped")
end

# ===== Notification Broadcasting =====

function broadcast_notification(server::RPCServer, method::String, params::Dict{String, Any})
    notification = Dict{String, Any}(
        "jsonrpc" => "2.0",
        "method" => method,
        "params" => params
    )
    data = Vector{UInt8}(JSON.json(notification))

    for (_, client) in server.clients
        try
            write_websocket_frame(client, data)
        catch
            # Client disconnected
        end
    end
end

function notify_block_update(server::RPCServer, method::String, block::BlockDescriptor)
    # Only handle finalized block notifications for now
    if method == "subscribeFinalizedBlock"
        block_json = block_descriptor_to_json(block)
        for (sub_id, client_id) in server.finalized_block_subs
            if haskey(server.clients, client_id)
                notification = Dict{String, Any}(
                    "jsonrpc" => "2.0",
                    "method" => method,
                    "params" => Dict{String, Any}(
                        "subscription" => sub_id,
                        "result" => block_json
                    )
                )
                try
                    write_websocket_frame(server.clients[client_id], Vector{UInt8}(JSON.json(notification)))
                catch
                    # Client disconnected, remove subscription
                    delete!(server.finalized_block_subs, sub_id)
                end
            else
                # Client gone, remove subscription
                delete!(server.finalized_block_subs, sub_id)
            end
        end
    elseif method == "subscribeBestBlock"
        # Only notify clients that subscribed to best block updates
        block_json = block_descriptor_to_json(block)
        for (sub_id, client_id) in server.best_block_subs
            if haskey(server.clients, client_id)
                notification = Dict{String, Any}(
                    "jsonrpc" => "2.0",
                    "method" => method,
                    "params" => Dict{String, Any}(
                        "subscription" => sub_id,
                        "result" => block_json
                    )
                )
                try
                    write_websocket_frame(server.clients[client_id], Vector{UInt8}(JSON.json(notification)))
                catch
                    # Client disconnected, remove subscription
                    delete!(server.best_block_subs, sub_id)
                end
            else
                # Client gone, remove subscription
                delete!(server.best_block_subs, sub_id)
            end
        end
    end
end

"""
    notify_service_request(server, service_id, preimage_hash, preimage_len, slot_provided)

Notify subscribers that a preimage is now available for the given service/hash/len.
According to JIP-2, chain subscription notifications use Chain Subscription Update format:
{header_hash: Hash, slot: Number, value: Array of Numbers}
"""
function notify_service_request(server::RPCServer, service_id::UInt32, preimage_hash::Vector{UInt8}, preimage_len::Int, slot_provided::UInt64)
    subs_to_remove = Int64[]

    # Get current best block info for Chain Subscription Update format
    best_block = server.chain_state.best_block

    for (sub_id, (client_id, sub_service_id, sub_hash, sub_len)) in server.service_request_subs
        # Check if this subscription matches
        if sub_service_id == service_id && sub_hash == preimage_hash && sub_len == preimage_len
            if haskey(server.clients, client_id)
                # JIP-2: Chain Subscription Update format with header_hash, slot, value
                notification = Dict{String, Any}(
                    "jsonrpc" => "2.0",
                    "method" => "subscribeServiceRequest",
                    "params" => Dict{String, Any}(
                        "subscription" => sub_id,
                        "result" => Dict{String, Any}(
                            "header_hash" => base64encode(best_block.header_hash),
                            "slot" => best_block.slot,
                            "value" => [slot_provided]  # Array with slot when provided
                        )
                    )
                )
                try
                    write_websocket_frame(server.clients[client_id], Vector{UInt8}(JSON.json(notification)))
                    println("Sent service request notification to sub $(sub_id): preimage available at slot $(slot_provided)")
                catch e
                    # Client disconnected
                    push!(subs_to_remove, sub_id)
                end
            else
                push!(subs_to_remove, sub_id)
            end
        end
    end

    # Clean up dead subscriptions
    for sub_id in subs_to_remove
        delete!(server.service_request_subs, sub_id)
    end
end

"""
    notify_service_value(server, service_id, key, new_value)

Notify subscribers that a service storage value has changed.
According to JIP-2, chain subscription notifications use Chain Subscription Update format:
{header_hash: Hash, slot: Number, value: Array (the new value)}
"""
function notify_service_value(server::RPCServer, service_id::UInt32, key::Vector{UInt8}, new_value::Vector{UInt8}; is_finalized::Bool=false, block::Union{BlockDescriptor, Nothing}=nothing)
    subs_to_remove = Int64[]

    # Use provided block, or derive from is_finalized flag
    if block === nothing
        block = is_finalized ? server.chain_state.finalized_block : server.chain_state.best_block
    end

    for (sub_id, (client_id, sub_service_id, sub_key, sub_finalized)) in server.service_value_subs
        # Check if this subscription matches AND finalized flag matches
        if sub_service_id == service_id && sub_key == key && sub_finalized == is_finalized
            if haskey(server.clients, client_id)
                # JIP-2: subscribeServiceValue notification with header_hash, slot, value
                # Note: value is BASE64-encoded bytes (jamt expects this format for serviceValue)
                notification = Dict{String, Any}(
                    "jsonrpc" => "2.0",
                    "method" => "subscribeServiceValue",
                    "params" => Dict{String, Any}(
                        "subscription" => sub_id,
                        "result" => Dict{String, Any}(
                            "header_hash" => base64encode(block.header_hash),
                            "slot" => block.slot,
                            "value" => base64encode(new_value)  # BASE64-encoded bytes
                        )
                    )
                )
                try
                    write_websocket_frame(server.clients[client_id], Vector{UInt8}(JSON.json(notification)))
                    println("Sent service value notification (finalized=$(is_finalized)) to sub $(sub_id): service=$(service_id), key=$(bytes2hex(key[1:min(8, length(key))]))...")
                catch e
                    # Client disconnected
                    push!(subs_to_remove, sub_id)
                end
            else
                push!(subs_to_remove, sub_id)
            end
        end
    end

    # Clean up dead subscriptions
    for sub_id in subs_to_remove
        delete!(server.service_value_subs, sub_id)
    end
end

end # module RPC
