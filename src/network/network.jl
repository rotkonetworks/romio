# JAM Network Module - JAMNP-S implementation using Quic.jl
module Network

using Quic
using Quic.JAMNPS
using Quic.Ed25519
using Quic.X509
using Quic.Crypto
using Sockets

export NetworkConfig, NetworkNode, Peer
export start_network!, stop_network!, connect_peer!, broadcast_block!, broadcast_work_package!

# Network configuration
struct NetworkConfig
    genesis_hash::Vector{UInt8}    # 32 bytes - identifies the chain
    identity::JAMNPS.JAMNPSIdentity
    listen_addr::String
    listen_port::UInt16
    bootstrap_peers::Vector{String}
    max_peers::UInt16
    is_builder::Bool              # Builder vs Validator role
end

function NetworkConfig(;
    genesis_hash::Vector{UInt8},
    seed::Union{Vector{UInt8}, Nothing} = nothing,
    listen_addr::String = "0.0.0.0",
    listen_port::UInt16 = UInt16(30333),
    bootstrap_peers::Vector{String} = String[],
    max_peers::UInt16 = UInt16(50),
    is_builder::Bool = false
)
    identity = if seed !== nothing
        JAMNPS.generate_identity(seed)
    else
        JAMNPS.generate_identity()
    end

    NetworkConfig(
        genesis_hash,
        identity,
        listen_addr,
        listen_port,
        bootstrap_peers,
        max_peers,
        is_builder
    )
end

# Connected peer
mutable struct Peer
    alt_name::String
    public_key::Vector{UInt8}
    addr::IPAddr
    port::UInt16
    is_builder::Bool
    connected_at::Float64
    last_seen::Float64

    # Stream IDs for UP streams
    block_announce_stream::Union{UInt64, Nothing}
    statement_distribution_stream::Union{UInt64, Nothing}

    # Statistics
    blocks_received::UInt64
    blocks_sent::UInt64
    bytes_received::UInt64
    bytes_sent::UInt64
end

# JAMNP-S Stream kinds (from graypaper)
const STREAM_BLOCK_ANNOUNCE = 0x00        # UP-0: Block announcements
const STREAM_STATEMENT_DIST = 0x01        # UP-1: Statement distribution
const STREAM_AUDIT_ANNOUNCE = 0x02        # UP-2: Audit announcements
const STREAM_SEGMENT_REQUEST = 0x80       # CE-128: Segment requests
const STREAM_AUDIT_SHARD = 0x81          # CE-129: Audit shards
const STREAM_WORK_PACKAGE_SUBMIT = 0x82  # CE-130: Work package submission
const STREAM_WORK_PACKAGE_SHARE = 0x83   # CE-131: Work package sharing

# Network node
mutable struct NetworkNode
    config::NetworkConfig
    socket::Union{UDPSocket, Nothing}
    peers::Dict{String, Peer}  # keyed by alt_name
    running::Bool

    # ALPN for this chain
    alpn::String

    # Callbacks
    on_block_announce::Union{Function, Nothing}
    on_work_package::Union{Function, Nothing}
    on_statement::Union{Function, Nothing}

    # Statistics
    total_connections::UInt64
    total_bytes_in::UInt64
    total_bytes_out::UInt64
end

function NetworkNode(config::NetworkConfig)
    alpn = JAMNPS.make_alpn(config.genesis_hash)

    NetworkNode(
        config,
        nothing,
        Dict{String, Peer}(),
        false,
        alpn,
        nothing,
        nothing,
        nothing,
        0, 0, 0
    )
end

# Start the network node
function start_network!(node::NetworkNode)
    if node.running
        return
    end

    # Bind UDP socket
    node.socket = UDPSocket()
    bind(node.socket, IPv4(node.config.listen_addr), node.config.listen_port)

    node.running = true

    alt_name = JAMNPS.derive_alt_name(node.config.identity.keypair.public_key)

    println("JAM Network started")
    println("  ALPN: $(node.alpn)")
    println("  Alt-name: $(alt_name)")
    println("  Listen: $(node.config.listen_addr):$(node.config.listen_port)")
    println("  Role: $(node.config.is_builder ? "Builder" : "Validator")")

    # Connect to bootstrap peers
    for peer_addr in node.config.bootstrap_peers
        @async try
            connect_peer!(node, peer_addr)
        catch e
            println("Failed to connect to bootstrap peer $peer_addr: $e")
        end
    end

    # Start listener task
    @async listen_loop(node)
end

# Stop the network node
function stop_network!(node::NetworkNode)
    node.running = false

    if node.socket !== nothing
        close(node.socket)
        node.socket = nothing
    end

    # Disconnect all peers
    for (_, peer) in node.peers
        # Send CONNECTION_CLOSE
    end
    empty!(node.peers)

    println("JAM Network stopped")
end

# Connect to a peer
function connect_peer!(node::NetworkNode, addr_str::String)
    # Parse address (format: "host:port" or "altname@host:port")
    parts = split(addr_str, "@")

    host_port = parts[end]
    hp_parts = split(host_port, ":")
    host = String(hp_parts[1])
    port = parse(UInt16, hp_parts[2])

    peer_addr = getaddrinfo(host)

    # Determine who should initiate based on JAMNP-S rules
    my_key = node.config.identity.keypair.public_key

    # For now, always initiate (we don't know peer key yet)
    println("Connecting to peer at $host:$port...")

    # In real implementation, would use JAMNPS connection
    # For now, create peer entry
    peer = Peer(
        "",  # alt_name unknown until handshake
        UInt8[],
        peer_addr,
        port,
        false,
        time(),
        time(),
        nothing,
        nothing,
        0, 0, 0, 0
    )

    node.total_connections += 1

    return peer
end

# Listen for incoming connections
function listen_loop(node::NetworkNode)
    while node.running && node.socket !== nothing
        try
            # Receive UDP packet
            data, addr = recvfrom(node.socket)

            node.total_bytes_in += length(data)

            # Process QUIC packet
            @async process_incoming_packet(node, data, addr)

        catch e
            if node.running
                println("Network receive error: $e")
            end
        end
    end
end

# Process incoming packet
function process_incoming_packet(node::NetworkNode, data::Vector{UInt8}, addr)
    # In full implementation, would:
    # 1. Parse QUIC packet header
    # 2. Find/create connection state
    # 3. Decrypt and process frames
    # 4. Handle JAMNP-S protocol messages

    # For now, just log
    # println("Received $(length(data)) bytes from $addr")
end

# Broadcast block announcement to all peers
function broadcast_block!(node::NetworkNode, block_hash::Vector{UInt8}, header_data::Vector{UInt8})
    if !node.running
        return 0
    end

    # JAMNP-S block announcement format
    # UP-0 stream: length-prefixed header
    msg = create_jamnps_message(STREAM_BLOCK_ANNOUNCE, header_data)

    sent_count = 0
    for (_, peer) in node.peers
        if peer.block_announce_stream !== nothing
            # Send on UP stream
            send_to_peer(node, peer, msg)
            peer.blocks_sent += 1
            sent_count += 1
        end
    end

    return sent_count
end

# Broadcast work package
function broadcast_work_package!(node::NetworkNode, core_id::UInt8, package_data::Vector{UInt8})
    if !node.running
        return 0
    end

    # JAMNP-S work package share format
    msg = create_jamnps_message(STREAM_WORK_PACKAGE_SHARE, vcat([core_id], package_data))

    sent_count = 0
    for (_, peer) in node.peers
        if peer.is_builder
            send_to_peer(node, peer, msg)
            sent_count += 1
        end
    end

    return sent_count
end

# Create JAMNP-S message with length prefix
function create_jamnps_message(stream_kind::UInt8, payload::Vector{UInt8})
    # Simple length-prefixed format
    len = length(payload)
    msg = UInt8[]
    push!(msg, stream_kind)

    # Variable-length encoding for size
    if len < 128
        push!(msg, UInt8(len))
    elseif len < 16384
        push!(msg, UInt8(0x80 | ((len >> 8) & 0x3f)))
        push!(msg, UInt8(len & 0xff))
    else
        push!(msg, UInt8(0xc0 | ((len >> 24) & 0x3f)))
        push!(msg, UInt8((len >> 16) & 0xff))
        push!(msg, UInt8((len >> 8) & 0xff))
        push!(msg, UInt8(len & 0xff))
    end

    append!(msg, payload)
    return msg
end

# Send data to peer
function send_to_peer(node::NetworkNode, peer::Peer, data::Vector{UInt8})
    if node.socket === nothing
        return false
    end

    try
        send(node.socket, peer.addr, peer.port, data)
        peer.bytes_sent += length(data)
        node.total_bytes_out += length(data)
        peer.last_seen = time()
        return true
    catch e
        println("Failed to send to peer $(peer.alt_name): $e")
        return false
    end
end

# Get network statistics
function get_network_stats(node::NetworkNode)
    return Dict{String, Any}(
        "running" => node.running,
        "peer_count" => length(node.peers),
        "total_connections" => node.total_connections,
        "bytes_in" => node.total_bytes_in,
        "bytes_out" => node.total_bytes_out,
        "alpn" => node.alpn,
        "alt_name" => JAMNPS.derive_alt_name(node.config.identity.keypair.public_key)
    )
end

# Get peer list
function get_peers(node::NetworkNode)
    peers = []
    for (alt_name, peer) in node.peers
        push!(peers, Dict{String, Any}(
            "alt_name" => alt_name,
            "addr" => string(peer.addr),
            "port" => peer.port,
            "is_builder" => peer.is_builder,
            "connected_at" => peer.connected_at,
            "last_seen" => peer.last_seen,
            "blocks_received" => peer.blocks_received,
            "blocks_sent" => peer.blocks_sent
        ))
    end
    return peers
end

end # module Network
