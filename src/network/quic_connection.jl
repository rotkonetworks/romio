module JAMNPSConnection

#= JAMNP-S Connection Management

High-level API for establishing and managing JAMNP-S connections
between JAM validators. This module is a thin wrapper around the
Quic.QuicClient library, adding only JAMNP-S specific functionality:
- JAMNP-S ALPN protocol identifier
- UP (Unique Persistent) and CE (Common Ephemeral) stream management
- JAM validator identity management
=#

using Quic
using Quic: QuicConnection, QuicConfig, ConnectionState
using Quic: DISCONNECTED, CONNECTING, HANDSHAKING, CONNECTED, CLOSED
using Quic.Ed25519
using Sockets

# Import library functions with qualified access to avoid name conflicts
import Quic: connect! as quic_connect!, open_stream! as quic_open_stream!
import Quic.QuicClient: process_packet! as quic_process_packet!, send_stream_data! as quic_send_stream_data!

# Import JAMNPS from parent module (must be included first)
import Main.JAMNPS

# Re-export connection states for convenience
const JAMNPS_DISCONNECTED = DISCONNECTED
const JAMNPS_CONNECTING = CONNECTING
const JAMNPS_HANDSHAKING = HANDSHAKING
const JAMNPS_CONNECTED = CONNECTED
const JAMNPS_CLOSED = CLOSED

# JAMNP-S specific configuration
struct JAMNPSConfig
    genesis_hash::Vector{UInt8}      # 32-byte genesis hash
    identity::JAMNPS.JAMNPSIdentity  # Our Ed25519 identity
    is_builder::Bool                  # Builder node vs validator
    idle_timeout_ms::UInt64          # Idle timeout in milliseconds
    max_streams::UInt64              # Maximum concurrent streams
end

function JAMNPSConfig(genesis_hash::Vector{UInt8}, identity::JAMNPS.JAMNPSIdentity;
                      is_builder::Bool=false, idle_timeout_ms::UInt64=UInt64(30000),
                      max_streams::UInt64=UInt64(100))
    JAMNPSConfig(genesis_hash, identity, is_builder, idle_timeout_ms, max_streams)
end

# JAMNP-S Connection - wraps QuicConnection with JAMNP-S specific state
mutable struct JAMNPSConn
    config::JAMNPSConfig
    quic::QuicConnection             # Underlying QUIC connection from library

    # Peer identity (discovered during handshake)
    peer_pubkey::Union{Vector{UInt8}, Nothing}
    peer_alt_name::Union{String, Nothing}

    # JAMNP-S Streams
    up_streams::Dict{UInt8, UInt64}  # stream kind -> stream ID
    ce_streams::Vector{Tuple{UInt64, UInt8}}  # (stream_id, kind)

    # Timing
    connected_at::Union{UInt64, Nothing}
end

#= High-Level API =#

"""
    connect(config::JAMNPSConfig, host::String, port::UInt16) -> JAMNPSConn

Establish a JAMNP-S connection to a remote peer.
"""
function connect(config::JAMNPSConfig, host::String, port::UInt16)
    socket = UDPSocket()

    # Resolve the host address first to determine address family
    addr = getaddrinfo(host)

    # Bind to matching address family
    if addr isa IPv4
        bind(socket, IPv4("0.0.0.0"), 0)
    else
        bind(socket, IPv6("::"), 0)
    end

    # Create ALPN for JAMNP-S
    alpn = JAMNPS.make_alpn(config.genesis_hash; builder=config.is_builder)

    # Create QuicConfig from JAMNPSConfig
    quic_config = QuicConfig(
        alpn;
        server_name=nothing,
        idle_timeout_ms=config.idle_timeout_ms,
        max_streams=config.max_streams,
        ed25519_keypair=config.identity.keypair,
        certificate=config.identity.certificate
    )

    # Create underlying QUIC connection
    quic_conn = QuicConnection(quic_config, socket, true)

    # Set up callback for connection established
    quic_conn.on_connected = function(conn)
        println("JAMNP-S: Connection established!")
    end

    # Create JAMNP-S wrapper
    conn = JAMNPSConn(
        config,
        quic_conn,
        nothing,  # peer_pubkey
        nothing,  # peer_alt_name
        Dict{UInt8, UInt64}(),  # up_streams
        Tuple{UInt64, UInt8}[], # ce_streams
        nothing   # connected_at
    )

    # Initiate connection
    quic_connect!(quic_conn, host, port)

    println("JAMNP-S: Connecting to $host:$port with ALPN: $alpn")
    return conn
end

"""
    listen(config::JAMNPSConfig, host::String, port::UInt16) -> UDPSocket

Create a listening socket for JAMNP-S connections.
"""
function listen(config::JAMNPSConfig, host::String, port::UInt16)
    socket = UDPSocket()
    bind(socket, parse(IPAddr, host), port)
    return socket
end

"""
    accept(config::JAMNPSConfig, socket::UDPSocket, data::Vector{UInt8},
           remote_addr::Sockets.InetAddr) -> JAMNPSConn

Accept an incoming JAMNP-S connection.
"""
function accept(config::JAMNPSConfig, socket::UDPSocket, data::Vector{UInt8},
                remote_addr::Sockets.InetAddr)
    alpn = JAMNPS.make_alpn(config.genesis_hash; builder=config.is_builder)

    quic_config = QuicConfig(
        alpn;
        server_name=nothing,
        idle_timeout_ms=config.idle_timeout_ms,
        max_streams=config.max_streams,
        ed25519_keypair=config.identity.keypair,
        certificate=config.identity.certificate
    )

    quic_conn = QuicConnection(quic_config, socket, false)
    quic_conn.remote_addr = remote_addr

    conn = JAMNPSConn(
        config,
        quic_conn,
        nothing,
        nothing,
        Dict{UInt8, UInt64}(),
        Tuple{UInt64, UInt8}[],
        nothing
    )

    # Process the initial packet
    process_packet!(conn, data)

    return conn
end

#= Packet Processing =#

"""
    process_packet!(conn::JAMNPSConn, data::Vector{UInt8})

Process a received QUIC datagram.
"""
function process_packet!(conn::JAMNPSConn, data::Vector{UInt8})
    # Delegate to library
    quic_process_packet!(conn.quic, data)

    # Check if connection is now established
    if conn.quic.state == CONNECTED && conn.connected_at === nothing
        conn.connected_at = time_ns()

        # Extract peer identity from certificate
        if conn.quic.peer_pubkey !== nothing
            conn.peer_pubkey = conn.quic.peer_pubkey
            conn.peer_alt_name = JAMNPS.derive_alt_name(conn.peer_pubkey)
            println("JAMNP-S: Peer identity: $(conn.peer_alt_name)")
        end
    end
end

#= Stream API for JAMNP-S Protocols =#

"""
    open_up_stream!(conn::JAMNPSConn, kind::UInt8) -> UInt64

Open a Unique Persistent (UP) stream for the given protocol kind.
UP streams persist for the lifetime of the connection.
"""
function open_up_stream!(conn::JAMNPSConn, kind::UInt8)
    if conn.quic.state != CONNECTED
        error("Connection not established")
    end

    # Check if this UP stream already exists
    if haskey(conn.up_streams, kind)
        return conn.up_streams[kind]
    end

    # Open new bidirectional stream via library
    stream_id = quic_open_stream!(conn.quic, true)
    conn.up_streams[kind] = stream_id

    # Send stream kind as first byte
    quic_send_stream_data!(conn.quic, stream_id, [kind], false)

    println("JAMNP-S: Opened UP stream $kind -> stream_id $stream_id")
    return stream_id
end

"""
    open_ce_stream!(conn::JAMNPSConn, kind::UInt8) -> UInt64

Open a Common Ephemeral (CE) stream for a single request/response.
CE streams are closed after the exchange completes.
"""
function open_ce_stream!(conn::JAMNPSConn, kind::UInt8)
    if conn.quic.state != CONNECTED
        error("Connection not established")
    end

    # Open new bidirectional stream via library
    stream_id = quic_open_stream!(conn.quic, true)
    push!(conn.ce_streams, (stream_id, kind))

    # Send stream kind as first byte
    quic_send_stream_data!(conn.quic, stream_id, [kind], false)

    println("JAMNP-S: Opened CE stream $kind -> stream_id $stream_id")
    return stream_id
end

"""
    send_stream_data!(conn::JAMNPSConn, stream_id::UInt64, data::Vector{UInt8}, fin::Bool)

Send data on a stream.
"""
function send_stream_data!(conn::JAMNPSConn, stream_id::UInt64, data::Vector{UInt8}, fin::Bool)
    quic_send_stream_data!(conn.quic, stream_id, data, fin)
end

"""
    send_message!(conn::JAMNPSConn, stream_id::UInt64, content::Vector{UInt8})

Send a length-prefixed message on a stream (JAMNP-S message format).
"""
function send_message!(conn::JAMNPSConn, stream_id::UInt64, content::Vector{UInt8})
    msg = JAMNPS.encode_message(content)
    send_stream_data!(conn, stream_id, msg, false)
end

"""
    state(conn::JAMNPSConn) -> ConnectionState

Get the current connection state.
"""
function state(conn::JAMNPSConn)
    return conn.quic.state
end

"""
    is_connected(conn::JAMNPSConn) -> Bool

Check if the connection is established.
"""
function is_connected(conn::JAMNPSConn)
    return conn.quic.state == CONNECTED
end

"""
    socket(conn::JAMNPSConn) -> UDPSocket

Get the underlying UDP socket.
"""
function socket(conn::JAMNPSConn)
    return conn.quic.socket
end

"""
    close!(conn::JAMNPSConn)

Close the JAMNP-S connection gracefully.
"""
function close!(conn::JAMNPSConn)
    Quic.QuicClient.close!(conn.quic)
end

# Exports
export JAMNPSConfig, JAMNPSConn
export JAMNPS_DISCONNECTED, JAMNPS_CONNECTING, JAMNPS_HANDSHAKING, JAMNPS_CONNECTED, JAMNPS_CLOSED
export connect, listen, accept, close!
export open_up_stream!, open_ce_stream!, send_stream_data!, send_message!
export process_packet!, state, is_connected, socket

end # module JAMNPSConnection
