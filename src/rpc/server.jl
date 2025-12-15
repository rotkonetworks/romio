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
        1
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
    # TODO: Implement block lookup
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
    # TODO: Implement status lookup
    return Dict{String, Any}("Failed" => "Not implemented")
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
    length(params) < 2 && throw(RPCError(ERR_INVALID_PARAMS, "Missing parameters", nothing))
    # TODO: Implement preimage submission
    return nothing
end

function rpc_sync_state(server::RPCServer, params::Vector{Any})
    return Dict{String, Any}(
        "num_peers" => 0,
        "status" => "Completed"
    )
end

# Subscription handlers (return subscription ID)
function rpc_subscribe_best_block(server::RPCServer, params::Vector{Any})
    # TODO: Create actual subscription
    return 1
end

function rpc_subscribe_finalized_block(server::RPCServer, params::Vector{Any})
    return 1
end

function rpc_subscribe_statistics(server::RPCServer, params::Vector{Any})
    return 1
end

function rpc_subscribe_service_data(server::RPCServer, params::Vector{Any})
    return 1
end

function rpc_subscribe_service_value(server::RPCServer, params::Vector{Any})
    return 1
end

function rpc_subscribe_wp_status(server::RPCServer, params::Vector{Any})
    return 1
end

function rpc_subscribe_sync_status(server::RPCServer, params::Vector{Any})
    return 1
end

function rpc_unsubscribe(server::RPCServer, params::Vector{Any})
    length(params) < 1 && throw(RPCError(ERR_INVALID_PARAMS, "Missing subscription ID", nothing))
    # TODO: Remove subscription
    return true
end

# ===== Request Processing =====

function process_request(server::RPCServer, request, client_id::UInt64)::Dict{String, Any}
    # Convert JSON.Object to Dict if needed
    req = request isa Dict ? request : Dict{String, Any}(request)
    id = get(req, "id", nothing)
    method = get(req, "method", nothing)
    params = get(req, "params", Any[])

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
        return make_success_response(id, result)
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

function handle_websocket_message(server::RPCServer, data::Vector{UInt8}, client_id::UInt64)::Vector{UInt8}
    try
        request = JSON.parse(String(data))

        # Handle batch requests
        if isa(request, AbstractVector)
            responses = [process_request(server, req, client_id) for req in request]
            return Vector{UInt8}(JSON.json(responses))
        else
            response = process_request(server, request, client_id)
            return Vector{UInt8}(JSON.json(response))
        end
    catch e
        # Handle JSON parse errors (ArgumentError in newer JSON.jl)
        if isa(e, ArgumentError) || contains(string(typeof(e)), "Parser")
            return Vector{UInt8}(JSON.json(make_error_response(nothing, ERR_PARSE, "Parse error")))
        end
        return Vector{UInt8}(JSON.json(make_error_response(nothing, ERR_INTERNAL, string(e))))
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

            response = handle_websocket_message(server, frame, client_id)
            write_websocket_frame(client, response)
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
    params = Dict{String, Any}(
        "subscription" => 1,  # TODO: Track actual subscription IDs
        "result" => block_descriptor_to_json(block)
    )
    broadcast_notification(server, method, params)
end

end # module RPC
