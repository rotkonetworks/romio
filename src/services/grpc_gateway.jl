# gRPC Gateway for JAM Services
#
# This module provides gRPC endpoints for clients to interact with
# Tendermint SDK apps running on JAM. It replaces the TendermintProxyService
# with JAM-native equivalents while keeping app-specific services unchanged.
#
# Architecture:
#
#   ┌──────────────────────────────────────────────────────────────────┐
#   │                         Clients                                   │
#   │  (pcli, wallets, IBC relayers, block explorers)                  │
#   └───────────────────────────┬──────────────────────────────────────┘
#                               │ gRPC
#                               ▼
#   ┌──────────────────────────────────────────────────────────────────┐
#   │                     gRPC Gateway                                  │
#   │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐   │
#   │  │ JAMProxyService │  │ ViewService     │  │ ComponentServices│  │
#   │  │ (replaces       │  │ (unchanged)     │  │ (DEX, Stake,etc)│  │
#   │  │  TendermintProxy│  │                 │  │ (unchanged)      │  │
#   │  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘   │
#   └───────────┼────────────────────┼────────────────────┼────────────┘
#               │                    │                    │
#               ▼                    ▼                    ▼
#   ┌──────────────────────────────────────────────────────────────────┐
#   │                     App State (cnidarium)                        │
#   └──────────────────────────────────────────────────────────────────┘
#               │
#               ▼ State sync
#   ┌──────────────────────────────────────────────────────────────────┐
#   │                         JAM Chain                                 │
#   │              (consensus, DA, block production)                    │
#   └──────────────────────────────────────────────────────────────────┘
#
# The key insight is that most gRPC services just read from app state.
# Only TendermintProxyService needs JAM-specific implementation because
# it deals with consensus/block data.

module GRPCGateway

export JAMProxyService, GRPCServer
export get_status, broadcast_tx_async, broadcast_tx_sync, get_tx, abci_query, get_block_by_height

# ============================================================================
# JAM Proxy Service (replaces TendermintProxyService)
# ============================================================================

# Status response - JAM equivalent of Tendermint's GetStatusResponse
struct JAMStatus
    # Node info
    node_id::Vector{UInt8}
    listen_addr::String
    network::String  # chain_id
    version::String

    # Sync info
    latest_block_hash::Vector{UInt8}
    latest_app_hash::Vector{UInt8}
    latest_block_height::Int64
    latest_block_time::Int64
    catching_up::Bool

    # Validator info (if this node is a validator)
    validator_address::Union{Vector{UInt8}, Nothing}
    voting_power::Int64
end

# Transaction broadcast result
struct BroadcastResult
    code::UInt32
    data::Vector{UInt8}
    log::String
    hash::Vector{UInt8}
end

# Block info
struct BlockInfo
    height::Int64
    hash::Vector{UInt8}
    time::Int64
    proposer::Vector{UInt8}
    txs::Vector{Vector{UInt8}}
    app_hash::Vector{UInt8}
end

# ABCI Query result
struct ABCIQueryResult
    code::UInt32
    log::String
    info::String
    index::Int64
    key::Vector{UInt8}
    value::Vector{UInt8}
    height::Int64
end

# ============================================================================
# JAM Proxy Service Implementation
# ============================================================================

mutable struct JAMProxyService
    # Connection to JAM node
    jam_endpoint::String

    # Local state cache
    latest_height::Int64
    latest_block_hash::Vector{UInt8}
    latest_app_hash::Vector{UInt8}

    # Pending transactions (mempool)
    pending_txs::Vector{Vector{UInt8}}

    # Chain info
    chain_id::String
    node_id::Vector{UInt8}
end

function JAMProxyService(chain_id::String; jam_endpoint::String="localhost:9944")
    JAMProxyService(
        jam_endpoint,
        0,
        zeros(UInt8, 32),
        zeros(UInt8, 32),
        Vector{UInt8}[],
        chain_id,
        rand(UInt8, 20)  # Random node ID for demo
    )
end

# GetStatus - returns current chain status
function get_status(service::JAMProxyService)::JAMStatus
    JAMStatus(
        service.node_id,
        "tcp://0.0.0.0:26657",  # Tendermint-compatible address
        service.chain_id,
        "0.1.0",
        service.latest_block_hash,
        service.latest_app_hash,
        service.latest_height,
        trunc(Int64, time()),
        false,  # catching_up
        nothing,
        0
    )
end

# BroadcastTxAsync - submit transaction without waiting for result
function broadcast_tx_async(service::JAMProxyService, tx::Vector{UInt8})::BroadcastResult
    # Add to pending pool
    push!(service.pending_txs, tx)

    # In JAM: would submit to work package builder
    # For now, return immediately with tx hash
    tx_hash = sha256(tx)

    BroadcastResult(0, UInt8[], "added to mempool", tx_hash)
end

# BroadcastTxSync - submit and wait for CheckTx result
function broadcast_tx_sync(service::JAMProxyService, tx::Vector{UInt8})::BroadcastResult
    # Validate transaction (CheckTx equivalent)
    # In JAM: would call refine() to validate

    valid = length(tx) > 0  # Simplified validation
    if !valid
        return BroadcastResult(1, UInt8[], "invalid transaction", UInt8[])
    end

    push!(service.pending_txs, tx)
    tx_hash = sha256(tx)

    BroadcastResult(0, UInt8[], "check tx passed", tx_hash)
end

# GetTx - fetch transaction by hash
function get_tx(service::JAMProxyService, hash::Vector{UInt8})::Union{Vector{UInt8}, Nothing}
    # In JAM: would query from DA layer or block storage
    # For now, check pending pool

    for tx in service.pending_txs
        if sha256(tx) == hash
            return tx
        end
    end

    return nothing
end

# ABCIQuery - query app state
function abci_query(service::JAMProxyService, path::String, data::Vector{UInt8}, height::Int64)::ABCIQueryResult
    # This passes through to the app's query handler
    # The app (e.g., Penumbra) handles the actual query

    # Common paths:
    # /store/... - raw key-value queries
    # /app/... - app-specific queries
    # /p2p/... - peer info

    # For JAM: query would go to service state storage
    ABCIQueryResult(
        0,
        "",
        "",
        0,
        Vector{UInt8}(path),
        UInt8[],  # Would be actual query result
        service.latest_height
    )
end

# GetBlockByHeight - fetch block at specific height
function get_block_by_height(service::JAMProxyService, height::Int64)::Union{BlockInfo, Nothing}
    # In JAM: query from block storage / DA layer

    if height > service.latest_height || height < 1
        return nothing
    end

    # Would fetch actual block data
    BlockInfo(
        height,
        sha256(Vector{UInt8}(string(height))),
        trunc(Int64, time()) - (service.latest_height - height) * 6,
        zeros(UInt8, 20),
        Vector{UInt8}[],
        sha256(Vector{UInt8}("app-$height"))
    )
end

# ============================================================================
# gRPC Server
#
# In production, this would use a proper gRPC library.
# For now, we define the interface.
# ============================================================================

mutable struct GRPCServer
    proxy::JAMProxyService
    host::String
    port::Int
    running::Bool

    # Service registry - maps service name to handler
    services::Dict{String, Any}
end

function GRPCServer(proxy::JAMProxyService; host::String="0.0.0.0", port::Int=8080)
    services = Dict{String, Any}(
        "penumbra.util.tendermint_proxy.v1.TendermintProxyService" => proxy
    )
    GRPCServer(proxy, host, port, false, services)
end

function register_service!(server::GRPCServer, name::String, handler::Any)
    server.services[name] = handler
end

function start!(server::GRPCServer)
    server.running = true
    println("gRPC server starting on $(server.host):$(server.port)")

    # In production:
    # - Use HTTP/2 (or HTTP/3 via Quic.jl!) for gRPC transport
    # - Parse protobuf requests
    # - Route to appropriate service handlers
    # - Return protobuf responses

    return true
end

function stop!(server::GRPCServer)
    server.running = false
    println("gRPC server stopped")
end

# ============================================================================
# Integration with Quic.jl for gRPC over HTTP/3
# ============================================================================

# gRPC can run over HTTP/3 (QUIC) for better performance.
# This would use Quic.jl's HTTP/3 support:
#
# using Quic
#
# function start_grpc_quic!(server::GRPCServer)
#     # Create HTTP/3 server
#     h3_server = Quic.HTTP3.Server(server.host, server.port)
#
#     # Handle gRPC requests over HTTP/3
#     # gRPC uses:
#     #   - POST method
#     #   - Path: /package.Service/Method
#     #   - Content-Type: application/grpc
#     #   - Body: length-prefixed protobuf
#
#     # Route to handlers based on path
# end

# ============================================================================
# Demo
# ============================================================================

using SHA

function demo()
    println("="^60)
    println("gRPC Gateway for JAM Services")
    println("="^60)

    # Create proxy service
    proxy = JAMProxyService("penumbra-jam-1")

    # Simulate some state
    proxy.latest_height = 100
    proxy.latest_block_hash = sha256(Vector{UInt8}("block-100"))
    proxy.latest_app_hash = sha256(Vector{UInt8}("app-100"))

    println("\n--- GetStatus ---")
    status = get_status(proxy)
    println("  Chain: $(status.network)")
    println("  Height: $(status.latest_block_height)")
    println("  Block hash: $(bytes2hex(status.latest_block_hash)[1:16])...")

    println("\n--- BroadcastTxAsync ---")
    tx1 = Vector{UInt8}("test-transaction-1")
    result1 = broadcast_tx_async(proxy, tx1)
    println("  Code: $(result1.code)")
    println("  Hash: $(bytes2hex(result1.hash)[1:16])...")
    println("  Pending txs: $(length(proxy.pending_txs))")

    println("\n--- BroadcastTxSync ---")
    tx2 = Vector{UInt8}("test-transaction-2")
    result2 = broadcast_tx_sync(proxy, tx2)
    println("  Code: $(result2.code)")
    println("  Log: $(result2.log)")

    println("\n--- GetTx ---")
    found_tx = get_tx(proxy, result1.hash)
    println("  Found: $(found_tx !== nothing)")
    if found_tx !== nothing
        println("  TX: $(String(found_tx))")
    end

    println("\n--- ABCIQuery ---")
    query_result = abci_query(proxy, "/store/shielded_pool/note_commitment_tree", UInt8[], 0)
    println("  Code: $(query_result.code)")
    println("  Height: $(query_result.height)")

    println("\n--- GetBlockByHeight ---")
    block = get_block_by_height(proxy, 50)
    if block !== nothing
        println("  Height: $(block.height)")
        println("  Hash: $(bytes2hex(block.hash)[1:16])...")
    end

    println("\n" * "="^60)
    println("gRPC Services for Penumbra on JAM")
    println("="^60)
    println("""
    Services that need JAM-specific implementation:
    ├── TendermintProxyService (→ JAMProxyService)
    │   ├── GetStatus          → JAM chain status
    │   ├── BroadcastTxAsync   → Submit to work package builder
    │   ├── BroadcastTxSync    → Submit + validate (refine)
    │   ├── GetTx              → Query from DA/storage
    │   ├── ABCIQuery          → Query service state
    │   └── GetBlockByHeight   → Query from block storage

    Services that stay unchanged (query app state):
    ├── ViewService            → Wallet queries
    ├── ShieldedPoolQueryService
    ├── DexQueryService
    ├── StakeQueryService
    ├── GovernanceQueryService
    └── ... (all component query services)

    Transport options:
    ├── gRPC over HTTP/2 (standard)
    └── gRPC over HTTP/3 (Quic.jl) ← faster!
    """)
end

end # module
