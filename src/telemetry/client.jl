# JIP-3: Telemetry Client Implementation
# Sends telemetry events to JAM Tart (Testing, Analytics and Research Telemetry)

module Telemetry

using Sockets
using Dates

export TelemetryClient, connect!, disconnect!, emit!
export NodeInfo, StatusEvent, BestBlockChanged, FinalizedBlockChanged, SyncStatusChanged
export ConnectionRefused, ConnectingIn, ConnectedIn, ConnectingOut, ConnectedOut, Disconnected

# ===== JAM Common Era =====
const JAM_EPOCH_START = 1735732800  # 2025-01-01 12:00:00 UTC

function jam_timestamp()::UInt64
    # Microseconds since JAM Common Era
    UInt64(floor((time() - JAM_EPOCH_START) * 1_000_000))
end

# ===== JAM Serialization Helpers =====

function encode_u8(v::UInt8)::Vector{UInt8}
    [v]
end

function encode_u16(v::UInt16)::Vector{UInt8}
    reinterpret(UInt8, [htol(v)])
end

function encode_u32(v::UInt32)::Vector{UInt8}
    reinterpret(UInt8, [htol(v)])
end

function encode_u64(v::UInt64)::Vector{UInt8}
    reinterpret(UInt8, [htol(v)])
end

function encode_bool(v::Bool)::Vector{UInt8}
    [v ? 0x01 : 0x00]
end

# Variable-length natural number encoding (GP serialization)
function encode_varlen(n::Integer)::Vector{UInt8}
    n == 0 && return UInt8[0x00]
    bytes = UInt8[]
    while n > 0
        push!(bytes, UInt8(n & 0x7f))
        n >>= 7
    end
    # Set continuation bits
    for i in 1:length(bytes)-1
        bytes[i] |= 0x80
    end
    return bytes
end

function encode_len_prefixed(data::Vector{UInt8})::Vector{UInt8}
    vcat(encode_varlen(length(data)), data)
end

function encode_string(s::String, max_len::Int)::Vector{UInt8}
    bytes = Vector{UInt8}(s)
    length(bytes) > max_len && (bytes = bytes[1:max_len])
    encode_len_prefixed(bytes)
end

function encode_hash(h::Vector{UInt8})::Vector{UInt8}
    @assert length(h) == 32 "Hash must be 32 bytes"
    copy(h)
end

function encode_peer_id(id::Vector{UInt8})::Vector{UInt8}
    @assert length(id) == 32 "Peer ID must be 32 bytes"
    copy(id)
end

function encode_peer_address(ipv6::Vector{UInt8}, port::UInt16)::Vector{UInt8}
    @assert length(ipv6) == 16 "IPv6 address must be 16 bytes"
    vcat(ipv6, encode_u16(port))
end

# Convert IPv6 address to 16 bytes
function ipv6_to_bytes(addr::IPv6)::Vector{UInt8}
    reinterpret(UInt8, [hton(addr.host)])
end

# Localhost IPv6 (::1)
function localhost_ipv6()::Vector{UInt8}
    bytes = zeros(UInt8, 16)
    bytes[16] = 0x01
    return bytes
end

# ===== Event Discriminators =====
const EVT_DROPPED = 0x00

# Status events (10-13)
const EVT_STATUS = 0x0a
const EVT_BEST_BLOCK_CHANGED = 0x0b
const EVT_FINALIZED_BLOCK_CHANGED = 0x0c
const EVT_SYNC_STATUS_CHANGED = 0x0d

# Networking events (20-28)
const EVT_CONNECTION_REFUSED = 0x14
const EVT_CONNECTING_IN = 0x15
const EVT_CONNECT_IN_FAILED = 0x16
const EVT_CONNECTED_IN = 0x17
const EVT_CONNECTING_OUT = 0x18
const EVT_CONNECT_OUT_FAILED = 0x19
const EVT_CONNECTED_OUT = 0x1a
const EVT_DISCONNECTED = 0x1b
const EVT_PEER_MISBEHAVED = 0x1c

# Block authoring/importing events (40-47)
const EVT_AUTHORING = 0x28
const EVT_AUTHORING_FAILED = 0x29
const EVT_AUTHORED = 0x2a
const EVT_IMPORTING = 0x2b
const EVT_BLOCK_VERIFICATION_FAILED = 0x2c
const EVT_BLOCK_VERIFIED = 0x2d
const EVT_BLOCK_EXECUTION_FAILED = 0x2e
const EVT_BLOCK_EXECUTED = 0x2f

# Block distribution events (60-68)
const EVT_BLOCK_ANNOUNCEMENT_STREAM_OPENED = 0x3c
const EVT_BLOCK_ANNOUNCEMENT_STREAM_CLOSED = 0x3d
const EVT_BLOCK_ANNOUNCED = 0x3e
const EVT_SENDING_BLOCK_REQUEST = 0x3f
const EVT_RECEIVING_BLOCK_REQUEST = 0x40
const EVT_BLOCK_REQUEST_FAILED = 0x41
const EVT_BLOCK_REQUEST_SENT = 0x42
const EVT_BLOCK_REQUEST_RECEIVED = 0x43
const EVT_BLOCK_TRANSFERRED = 0x44

# ===== Types =====

struct BlockOutline
    size_bytes::UInt32
    header_hash::Vector{UInt8}
    num_tickets::UInt32
    num_preimages::UInt32
    preimages_size::UInt32
    num_guarantees::UInt32
    num_assurances::UInt32
    num_dispute_verdicts::UInt32
end

function encode_block_outline(b::BlockOutline)::Vector{UInt8}
    vcat(
        encode_u32(b.size_bytes),
        encode_hash(b.header_hash),
        encode_u32(b.num_tickets),
        encode_u32(b.num_preimages),
        encode_u32(b.preimages_size),
        encode_u32(b.num_guarantees),
        encode_u32(b.num_assurances),
        encode_u32(b.num_dispute_verdicts)
    )
end

# Connection side
const CONN_LOCAL = 0x00
const CONN_REMOTE = 0x01

# ===== Node Information =====

struct NodeInfo
    protocol_version::UInt8
    jam_parameters::Vector{UInt8}
    genesis_hash::Vector{UInt8}
    peer_id::Vector{UInt8}
    peer_address_ipv6::Vector{UInt8}
    peer_address_port::UInt16
    node_flags::UInt32
    impl_name::String
    impl_version::String
    gp_version::String
    note::String
end

function NodeInfo(;
    jam_parameters::Vector{UInt8}=UInt8[],
    genesis_hash::Vector{UInt8}=zeros(UInt8, 32),
    peer_id::Vector{UInt8}=zeros(UInt8, 32),
    peer_address_ipv6::Vector{UInt8}=zeros(UInt8, 16),
    peer_address_port::UInt16=UInt16(0),
    node_flags::UInt32=UInt32(0),
    impl_name::String="JAMit",
    impl_version::String="0.1.0",
    gp_version::String="0.7.1",
    note::String=""
)
    NodeInfo(
        0x00,  # Protocol version
        jam_parameters,
        genesis_hash,
        peer_id,
        peer_address_ipv6,
        peer_address_port,
        node_flags,
        impl_name,
        impl_version,
        gp_version,
        note
    )
end

function encode(info::NodeInfo)::Vector{UInt8}
    vcat(
        encode_u8(info.protocol_version),
        encode_len_prefixed(info.jam_parameters),
        encode_hash(info.genesis_hash),
        encode_peer_id(info.peer_id),
        encode_peer_address(info.peer_address_ipv6, info.peer_address_port),
        encode_u32(info.node_flags),
        encode_string(info.impl_name, 32),
        encode_string(info.impl_version, 32),
        encode_string(info.gp_version, 16),
        encode_string(info.note, 512)
    )
end

# ===== Event Types =====

abstract type TelemetryEvent end

# Status event (10)
struct StatusEvent <: TelemetryEvent
    total_peers::UInt32
    validator_peers::UInt32
    peers_with_announcements::UInt32
    guarantees_by_core::Vector{UInt8}
    shards_count::UInt32
    shards_size::UInt64
    preimages_count::UInt32
    preimages_size::UInt32
end

function encode(e::StatusEvent)::Vector{UInt8}
    vcat(
        encode_u32(e.total_peers),
        encode_u32(e.validator_peers),
        encode_u32(e.peers_with_announcements),
        e.guarantees_by_core,
        encode_u32(e.shards_count),
        encode_u64(e.shards_size),
        encode_u32(e.preimages_count),
        encode_u32(e.preimages_size)
    )
end
discriminator(::StatusEvent) = EVT_STATUS

# Best block changed (11)
struct BestBlockChanged <: TelemetryEvent
    slot::UInt32
    header_hash::Vector{UInt8}
end

function encode(e::BestBlockChanged)::Vector{UInt8}
    vcat(encode_u32(e.slot), encode_hash(e.header_hash))
end
discriminator(::BestBlockChanged) = EVT_BEST_BLOCK_CHANGED

# Finalized block changed (12)
struct FinalizedBlockChanged <: TelemetryEvent
    slot::UInt32
    header_hash::Vector{UInt8}
end

function encode(e::FinalizedBlockChanged)::Vector{UInt8}
    vcat(encode_u32(e.slot), encode_hash(e.header_hash))
end
discriminator(::FinalizedBlockChanged) = EVT_FINALIZED_BLOCK_CHANGED

# Sync status changed (13)
struct SyncStatusChanged <: TelemetryEvent
    is_synced::Bool
end

function encode(e::SyncStatusChanged)::Vector{UInt8}
    encode_bool(e.is_synced)
end
discriminator(::SyncStatusChanged) = EVT_SYNC_STATUS_CHANGED

# Connection refused (20)
struct ConnectionRefused <: TelemetryEvent
    peer_address_ipv6::Vector{UInt8}
    peer_address_port::UInt16
end

function encode(e::ConnectionRefused)::Vector{UInt8}
    encode_peer_address(e.peer_address_ipv6, e.peer_address_port)
end
discriminator(::ConnectionRefused) = EVT_CONNECTION_REFUSED

# Connecting in (21)
struct ConnectingIn <: TelemetryEvent
    peer_address_ipv6::Vector{UInt8}
    peer_address_port::UInt16
end

function encode(e::ConnectingIn)::Vector{UInt8}
    encode_peer_address(e.peer_address_ipv6, e.peer_address_port)
end
discriminator(::ConnectingIn) = EVT_CONNECTING_IN

# Connected in (23)
struct ConnectedIn <: TelemetryEvent
    event_id::UInt64
    peer_id::Vector{UInt8}
end

function encode(e::ConnectedIn)::Vector{UInt8}
    vcat(encode_u64(e.event_id), encode_peer_id(e.peer_id))
end
discriminator(::ConnectedIn) = EVT_CONNECTED_IN

# Connecting out (24)
struct ConnectingOut <: TelemetryEvent
    peer_id::Vector{UInt8}
    peer_address_ipv6::Vector{UInt8}
    peer_address_port::UInt16
end

function encode(e::ConnectingOut)::Vector{UInt8}
    vcat(
        encode_peer_id(e.peer_id),
        encode_peer_address(e.peer_address_ipv6, e.peer_address_port)
    )
end
discriminator(::ConnectingOut) = EVT_CONNECTING_OUT

# Connected out (26)
struct ConnectedOut <: TelemetryEvent
    event_id::UInt64
end

function encode(e::ConnectedOut)::Vector{UInt8}
    encode_u64(e.event_id)
end
discriminator(::ConnectedOut) = EVT_CONNECTED_OUT

# Disconnected (27)
struct Disconnected <: TelemetryEvent
    peer_id::Vector{UInt8}
    terminator::Union{UInt8, Nothing}
    reason::String
end

function encode(e::Disconnected)::Vector{UInt8}
    terminator_bytes = isnothing(e.terminator) ? [0x00] : vcat([0x01], [e.terminator])
    vcat(
        encode_peer_id(e.peer_id),
        terminator_bytes,
        encode_string(e.reason, 128)
    )
end
discriminator(::Disconnected) = EVT_DISCONNECTED

# Block announced (62)
struct BlockAnnounced <: TelemetryEvent
    peer_id::Vector{UInt8}
    connection_side::UInt8
    slot::UInt32
    header_hash::Vector{UInt8}
end

function encode(e::BlockAnnounced)::Vector{UInt8}
    vcat(
        encode_peer_id(e.peer_id),
        [e.connection_side],
        encode_u32(e.slot),
        encode_hash(e.header_hash)
    )
end
discriminator(::BlockAnnounced) = EVT_BLOCK_ANNOUNCED

# Authoring (40)
struct Authoring <: TelemetryEvent
    slot::UInt32
    parent_hash::Vector{UInt8}
end

function encode(e::Authoring)::Vector{UInt8}
    vcat(encode_u32(e.slot), encode_hash(e.parent_hash))
end
discriminator(::Authoring) = EVT_AUTHORING

# Authored (42)
struct Authored <: TelemetryEvent
    event_id::UInt64
    block_outline::BlockOutline
end

function encode(e::Authored)::Vector{UInt8}
    vcat(encode_u64(e.event_id), encode_block_outline(e.block_outline))
end
discriminator(::Authored) = EVT_AUTHORED

# ===== Telemetry Client =====

mutable struct TelemetryClient
    host::String
    port::UInt16
    socket::Union{TCPSocket, Nothing}
    connected::Bool
    node_info::NodeInfo
    next_event_id::UInt64
    buffer::Vector{UInt8}
    lock::ReentrantLock
    status_interval::Float64
    last_status_time::Float64
end

function TelemetryClient(host::String, port::UInt16; node_info::NodeInfo=NodeInfo())
    TelemetryClient(
        host, port, nothing, false, node_info,
        0, UInt8[], ReentrantLock(), 2.0, 0.0
    )
end

function connect!(client::TelemetryClient)::Bool
    try
        client.socket = connect(client.host, client.port)
        client.connected = true
        client.next_event_id = 0

        # Send node info as first message
        send_message!(client, encode(client.node_info))

        println("Telemetry connected to $(client.host):$(client.port)")
        return true
    catch e
        println("Telemetry connection failed: $e")
        client.connected = false
        return false
    end
end

function disconnect!(client::TelemetryClient)
    if client.connected && !isnothing(client.socket)
        try
            close(client.socket)
        catch
        end
    end
    client.connected = false
    client.socket = nothing
    println("Telemetry disconnected")
end

function send_message!(client::TelemetryClient, data::Vector{UInt8})
    !client.connected && return false

    lock(client.lock) do
        try
            # Length prefix (4 bytes LE) + data
            len_bytes = reinterpret(UInt8, [htol(UInt32(length(data)))])
            write(client.socket, len_bytes)
            write(client.socket, data)
            flush(client.socket)
            return true
        catch e
            println("Telemetry send error: $e")
            client.connected = false
            return false
        end
    end
end

function emit!(client::TelemetryClient, event::TelemetryEvent)::UInt64
    !client.connected && return 0

    event_id = client.next_event_id

    # Encode: timestamp + discriminator + event data
    message = vcat(
        encode_u64(jam_timestamp()),
        [discriminator(event)],
        encode(event)
    )

    if send_message!(client, message)
        client.next_event_id += 1
    end

    return event_id
end

# Emit status event periodically
function emit_status!(client::TelemetryClient;
    total_peers::UInt32=UInt32(0),
    validator_peers::UInt32=UInt32(0),
    peers_with_announcements::UInt32=UInt32(0),
    guarantees_by_core::Vector{UInt8}=zeros(UInt8, 341),
    shards_count::UInt32=UInt32(0),
    shards_size::UInt64=UInt64(0),
    preimages_count::UInt32=UInt32(0),
    preimages_size::UInt32=UInt32(0)
)
    now = time()
    if now - client.last_status_time >= client.status_interval
        emit!(client, StatusEvent(
            total_peers, validator_peers, peers_with_announcements,
            guarantees_by_core, shards_count, shards_size,
            preimages_count, preimages_size
        ))
        client.last_status_time = now
    end
end

# Helper to create telemetry client from CLI args
function from_cli(telemetry_arg::String; node_info::NodeInfo=NodeInfo())::Union{TelemetryClient, Nothing}
    isempty(telemetry_arg) && return nothing

    parts = split(telemetry_arg, ":")
    length(parts) != 2 && return nothing

    host = String(parts[1])
    port = tryparse(UInt16, parts[2])
    isnothing(port) && return nothing

    return TelemetryClient(host, port; node_info=node_info)
end

end # module Telemetry
