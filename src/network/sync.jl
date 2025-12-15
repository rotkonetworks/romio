# Block Sync Protocol for JAMNP-S
#
# Implements block synchronization using the pure Julia QUIC implementation
# from JAMNPSConnection for TLS 1.3 connections with Ed25519 certificates.
# - Block request (0x80): Request blocks by hash or height range
# - Block announcement (0x00): Receive new block notifications
# - State request (0x81): Request state data

module BlockSync

using Sockets
using ..JAMNPS

# Import JAMNPSConnection module (loaded by main before this)
import Main: JAMNPSConnection

export SyncClient, connect_to_peer!, request_blocks, start_sync_loop!, parse_bootnode

# Bootnode address format: peer_id@host:port
struct BootnodeAddr
    peer_id::String
    host::String
    port::UInt16
end

function parse_bootnode(addr::String)::BootnodeAddr
    m = match(r"^([a-z2-7]{53})@(.+):(\d+)$", addr)
    isnothing(m) && error("Invalid bootnode format: $addr (expected: peer_id@host:port)")
    return BootnodeAddr(m.captures[1], m.captures[2], parse(UInt16, m.captures[3]))
end

# Block request message format (JAMNP-S 0x80)
struct BlockRequest
    direction::UInt8      # 0 = ascending, 1 = descending
    max_blocks::UInt32
    start_hash::Union{Vector{UInt8}, Nothing}
    start_slot::Union{UInt32, Nothing}
end

function encode_block_request(req::BlockRequest)::Vector{UInt8}
    buf = UInt8[]
    push!(buf, req.direction)
    append!(buf, reinterpret(UInt8, [htol(req.max_blocks)]))

    if req.start_hash !== nothing
        push!(buf, 0x01)  # hash type
        append!(buf, req.start_hash)
    elseif req.start_slot !== nothing
        push!(buf, 0x00)  # slot type
        append!(buf, reinterpret(UInt8, [htol(req.start_slot)]))
    end

    return buf
end

# Block response - simplified header structure
struct BlockHeader
    slot::UInt32
    parent_hash::Vector{UInt8}
    state_root::Vector{UInt8}
    extrinsic_hash::Vector{UInt8}
    header_hash::Vector{UInt8}  # computed
end

# Peer connection using pure Julia JAMNPSConnection
mutable struct PeerConnection
    conn::JAMNPSConnection.JAMNPSConn
    bootnode::BootnodeAddr
    stream_buffers::Dict{UInt64, Vector{UInt8}}  # stream_id -> buffer
end

# Sync client using pure Julia QUIC connections
mutable struct SyncClient
    genesis_hash::Vector{UInt8}
    identity::JAMNPS.JAMNPSIdentity
    config::JAMNPSConnection.JAMNPSConfig
    peers::Dict{String, BootnodeAddr}  # peer_id -> addr
    connections::Dict{String, PeerConnection}  # peer_id -> connection
    best_slot::UInt32
    finalized_slot::UInt32
    on_block::Union{Function, Nothing}
    running::Bool
end

function SyncClient(identity::JAMNPS.JAMNPSIdentity, genesis_hash::Vector{UInt8})
    # Create JAMNPSConfig for our identity
    config = JAMNPSConnection.JAMNPSConfig(genesis_hash, identity)

    SyncClient(
        genesis_hash,
        identity,
        config,
        Dict{String, BootnodeAddr}(),
        Dict{String, PeerConnection}(),
        UInt32(0),
        UInt32(0),
        nothing,
        false
    )
end

function add_bootnode!(client::SyncClient, bootnode::String)
    addr = parse_bootnode(bootnode)
    client.peers[addr.peer_id] = addr
end

"""
    connect_to_peer!(client, peer_id) -> Bool

Initiate QUIC connection to peer using pure Julia JAMNP-S implementation.
"""
function connect_to_peer!(client::SyncClient, peer_id::String)::Bool
    !haskey(client.peers, peer_id) && return false
    addr = client.peers[peer_id]

    try
        @info "Connecting to peer $peer_id at $(addr.host):$(addr.port) via Julia QUIC"

        # Use JAMNPSConnection.connect() which handles:
        # - UDP socket creation
        # - X25519 key generation
        # - TLS 1.3 ClientHello with Ed25519
        # - Initial packet encryption
        conn = JAMNPSConnection.connect(client.config, addr.host, addr.port)

        # Create peer connection wrapper
        peer_conn = PeerConnection(
            conn,
            addr,
            Dict{UInt64, Vector{UInt8}}()
        )

        client.connections[peer_id] = peer_conn

        # Start dedicated receive task for this connection
        start_receive_task!(client, peer_id)

        @info "Julia QUIC connection initiated to $peer_id (state: $(JAMNPSConnection.state(conn)))"
        return true
    catch e
        @warn "Failed to connect to $peer_id" exception=(e, catch_backtrace())
        return false
    end
end

"""
    poll_connection!(client, peer_id) -> Bool

Poll a connection for incoming data and process it.
Returns true if still connected.
"""
function poll_connection!(client::SyncClient, peer_id::String)::Bool
    !haskey(client.connections, peer_id) && return false

    peer_conn = client.connections[peer_id]
    conn = peer_conn.conn

    # Check if connection is closed
    if JAMNPSConnection.state(conn) == JAMNPSConnection.JAMNPS_CLOSED
        return false
    end

    try
        # Non-blocking receive
        # Julia's recvfrom is blocking, so we use select-style polling
        # or just try to receive with a small timeout
        if isreadable(JAMNPSConnection.socket(conn))
            # Julia's recvfrom returns (InetAddr, data) - address first!
            result = recvfrom(JAMNPSConnection.socket(conn))
            from_addr = result[1]
            data = result[2]::Vector{UInt8}
            if !isempty(data)
                # Process the packet through JAMNPSConnection
                JAMNPSConnection.process_packet!(conn, data)

                # Check if we transitioned to CONNECTED
                if JAMNPSConnection.state(conn) == JAMNPSConnection.JAMNPS_CONNECTED
                    @info "Connection to $peer_id established!"
                    # Start block sync
                    request_block_announcement!(client, peer_id)
                end
            end
        end
    catch e
        if !isa(e, Base.IOError)
            @debug "Poll error for $peer_id" exception=e
        end
    end

    return true
end

"""
    request_blocks(client, peer_id, start_slot, max_blocks) -> Bool

Request blocks from peer starting at given slot.
"""
function request_blocks(client::SyncClient, peer_id::String;
                        start_slot::UInt32=UInt32(0),
                        max_blocks::UInt32=UInt32(64))::Bool
    !haskey(client.connections, peer_id) && return false
    peer_conn = client.connections[peer_id]
    conn = peer_conn.conn

    if JAMNPSConnection.state(conn) != JAMNPSConnection.JAMNPS_CONNECTED
        @debug "Connection to $peer_id not established yet (state: $(JAMNPSConnection.state(conn)))"
        return false
    end

    try
        # Open CE stream for block request
        stream_id = JAMNPSConnection.open_ce_stream!(conn, JAMNPS.StreamKind.BLOCK_REQUEST)

        # Build request
        req = BlockRequest(0x00, max_blocks, nothing, start_slot)
        data = encode_block_request(req)

        # Send on stream
        JAMNPSConnection.send_stream_data!(conn, stream_id, data, true)

        @info "Requested blocks from $peer_id starting at slot $start_slot"
        return true
    catch e
        @warn "Failed to request blocks from $peer_id: $e"
        return false
    end
end

"""
    start_receive_task!(client, peer_id)

Start a dedicated receive task for a peer connection.
This task blocks on recvfrom and processes incoming packets.
"""
function start_receive_task!(client::SyncClient, peer_id::String)
    !haskey(client.connections, peer_id) && return

    peer_conn = client.connections[peer_id]
    conn = peer_conn.conn

    @async begin
        println("SYNC: Starting receive task for $peer_id (v3-explicit-indexing)")
        while client.running && haskey(client.connections, peer_id)
            try
                if !Base.isopen(JAMNPSConnection.socket(conn))
                    println("SYNC: Socket closed for $peer_id")
                    break
                end

                # Blocking recvfrom - will wait for data
                # Julia's recvfrom returns (InetAddr, data) - address first!
                recv_result = recvfrom(JAMNPSConnection.socket(conn))
                from_addr = recv_result[1]
                data = recv_result[2]::Vector{UInt8}

                if !isempty(data)
                    println("SYNC: RECV $(length(data)) bytes from $from_addr (state: $(JAMNPSConnection.state(conn)))")
                    flush(stdout)

                    JAMNPSConnection.process_packet!(conn, data)

                    println("SYNC: After process_packet!, state: $(JAMNPSConnection.state(conn))")
                    flush(stdout)

                    # Check state transition
                    if JAMNPSConnection.state(conn) == JAMNPSConnection.JAMNPS_CONNECTED
                        println("SYNC: Connected to $peer_id!")
                        request_block_announcement!(client, peer_id)
                    end
                end
            catch e
                if isa(e, EOFError) || isa(e, Base.IOError)
                    println("SYNC: Socket error for $peer_id: $e")
                    break
                elseif isa(e, InterruptException)
                    break
                else
                    println("SYNC: Recv error for $peer_id: $e")
                    @debug "Recv exception" exception=(e, catch_backtrace())
                end
            end
        end
        println("SYNC: Receive task ended for $peer_id")

        # Mark connection as closed
        if haskey(client.connections, peer_id)
            try
                JAMNPSConnection.close!(conn)
            catch; end
            delete!(client.connections, peer_id)
        end
    end
end

"""
    receive_loop(client)

Background loop to monitor connection health.
Actual receiving is done by per-connection tasks started by start_receive_task!
"""
function receive_loop(client::SyncClient)
    println("SYNC: Starting receive loop (monitoring only)")
    while client.running
        try
            # Check connection health
            for (peer_id, peer_conn) in collect(client.connections)
                conn = peer_conn.conn
                if JAMNPSConnection.state(conn) == JAMNPSConnection.JAMNPS_CLOSED
                    println("SYNC: Connection to $peer_id closed")
                    delete!(client.connections, peer_id)
                end
            end

            sleep(1.0)  # Health check every second
        catch e
            isa(e, InterruptException) && break
            @debug "Receive loop error: $e"
        end
    end
    println("SYNC: Receive loop ended")
end

function request_block_announcement!(client::SyncClient, peer_id::String)::Bool
    !haskey(client.connections, peer_id) && return false
    peer_conn = client.connections[peer_id]
    conn = peer_conn.conn

    if JAMNPSConnection.state(conn) != JAMNPSConnection.JAMNPS_CONNECTED
        return false
    end

    try
        # Open UP stream for block announcements
        stream_id = JAMNPSConnection.open_up_stream!(conn, JAMNPS.StreamKind.BLOCK_ANNOUNCEMENT)

        # Build handshake message
        handshake = JAMNPS.BlockAnnouncementHandshake(
            zeros(UInt8, 32),  # genesis as finalized
            client.finalized_slot,
            []  # no leaves
        )

        # Send handshake
        data = JAMNPS.encode_handshake(handshake)
        JAMNPSConnection.send_stream_data!(conn, stream_id, data, false)

        @info "Opened block announcement stream with $peer_id"
        return true
    catch e
        @warn "Failed to open block announcement stream: $e"
    end

    return false
end

function process_stream_data!(client::SyncClient, peer_id::String, stream_id::UInt64,
                              data::Vector{UInt8}, fin::Bool)
    length(data) < 1 && return

    !haskey(client.connections, peer_id) && return
    peer_conn = client.connections[peer_id]

    if !haskey(peer_conn.stream_buffers, stream_id)
        peer_conn.stream_buffers[stream_id] = UInt8[]
    end

    append!(peer_conn.stream_buffers[stream_id], data)

    # Parse if we have enough data
    stream_buf = peer_conn.stream_buffers[stream_id]
    length(stream_buf) < 5 && return

    # First byte is stream kind
    stream_kind = stream_buf[1]

    if stream_kind == JAMNPS.StreamKind.BLOCK_ANNOUNCEMENT
        handle_block_announcement!(client, stream_buf[2:end])
    elseif stream_kind == JAMNPS.StreamKind.BLOCK_REQUEST
        handle_block_response!(client, stream_buf[2:end])
    end

    # Clear buffer if done
    if fin
        delete!(peer_conn.stream_buffers, stream_id)
    end
end

function handle_block_announcement!(client::SyncClient, payload::Vector{UInt8})
    length(payload) < 68 && return  # header_hash (32) + finalized_hash (32) + slot (4)

    header_hash = payload[1:32]
    finalized_hash = payload[33:64]
    finalized_slot = ltoh(reinterpret(UInt32, payload[65:68])[1])

    if finalized_slot > client.finalized_slot
        client.finalized_slot = finalized_slot
        @info "New finalized block: slot=$finalized_slot"
    end

    # Trigger sync if we're behind
    if client.best_slot < finalized_slot && !isempty(client.connections)
        peer_id = first(keys(client.connections))
        request_blocks(client, peer_id; start_slot=client.best_slot + 1)
    end
end

function handle_block_response!(client::SyncClient, payload::Vector{UInt8})
    length(payload) < 4 && return
    num_blocks = ltoh(reinterpret(UInt32, payload[1:4])[1])

    @info "Received $num_blocks blocks"

    offset = 5
    for i in 1:num_blocks
        offset + 32 > length(payload) && break

        if offset + 36 <= length(payload)
            slot = ltoh(reinterpret(UInt32, payload[offset:offset+3])[1])
            hash = payload[offset+4:offset+35]

            if slot > client.best_slot
                client.best_slot = slot

                if client.on_block !== nothing
                    try
                        client.on_block(slot, hash)
                    catch e
                        @warn "Block callback error: $e"
                    end
                end
            end

            offset += 36
        end
    end
end

"""
    start_sync_loop!(client; on_block=nothing)

Start the sync client's background receive loop.
"""
function start_sync_loop!(client::SyncClient; on_block::Union{Function, Nothing}=nothing)
    client.on_block = on_block
    client.running = true

    # Connect to all bootnodes
    for peer_id in keys(client.peers)
        connect_to_peer!(client, peer_id)
    end

    # Start receive loop in background
    @async receive_loop(client)

    return client
end

function stop_sync!(client::SyncClient)
    client.running = false
    for (_, peer_conn) in client.connections
        try
            JAMNPSConnection.close!(peer_conn.conn)
        catch; end
    end
    empty!(client.connections)
end

end # module BlockSync
