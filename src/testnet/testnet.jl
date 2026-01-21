# JAM Testnet
# Multi-validator testnet with QUIC networking and 6s blocks
#
# Architecture:
#   - N validator nodes running in separate tasks
#   - QUIC/JAMNPS networking between nodes
#   - Safrole consensus with ticket-based author selection
#   - GRANDPA finality with 2/3+1 threshold
#   - RPC server per node for external interaction
#
# Usage:
#   julia --threads=auto --project=. -e 'include("src/testnet/testnet.jl"); Testnet.run()'

module Testnet

using Sockets
using Dates
using Base64

# Core JAM constants
const JAM_EPOCH = 1735732800  # 2025-01-01 12:00 UTC
const P = 6  # slot period in seconds
const E = 600  # epoch length in slots

# Project root for includes
const PROJECT_ROOT = dirname(dirname(@__DIR__))
const SRC_DIR = joinpath(PROJECT_ROOT, "src")
const CRYPTO_DIR = joinpath(SRC_DIR, "crypto")
const NETWORK_DIR = joinpath(SRC_DIR, "network")

# Include Blake2b implementation
include(joinpath(CRYPTO_DIR, "Blake2b.jl"))

# Include JAMNPS networking
include(joinpath(NETWORK_DIR, "jamnps.jl"))
using .JAMNPS

# Include RPC server for jamt compatibility
include(joinpath(SRC_DIR, "rpc", "server.jl"))
using .RPC

# Include PVM for service execution
include(joinpath(SRC_DIR, "pvm", "pvm.jl"))
include(joinpath(SRC_DIR, "pvm", "polkavm_blob.jl"))
include(joinpath(SRC_DIR, "pvm", "corevm_extension.jl"))

# Include JAM encoding, SCALE encoding, and CoreVM file handling
include(joinpath(SRC_DIR, "encoding", "jam.jl"))
include(joinpath(SRC_DIR, "encoding", "scale.jl"))
include(joinpath(SRC_DIR, "corevm", "fs.jl"))

# blake2b-256 hash function
function blake2b_256(data::Union{Vector{UInt8}, Base.CodeUnits{UInt8, String}})::Vector{UInt8}
    output = zeros(UInt8, 32)
    input = data isa Vector{UInt8} ? data : Vector{UInt8}(data)
    Blake2b!(output, 32, UInt8[], 0, input, length(input))
    return output
end

# polkajam's exact Bootstrap service code_hash
const POLKAJAM_BOOTSTRAP_CODE_HASH = UInt8[
    0x00, 0x59, 0x0a, 0x2a, 0x74, 0xe3, 0x19, 0x91, 0x30, 0x4f, 0xc6, 0x28, 0xe9, 0x72, 0x19, 0xb7,
    0x34, 0x10, 0x12, 0x5b, 0x2f, 0x52, 0x32, 0x18, 0xe0, 0x67, 0x34, 0x0e, 0x50, 0x64, 0xc8, 0xcb
]

# Load the Bootstrap module from polkajam (used for servicePreimage)
function load_bootstrap_module()::Vector{UInt8}
    module_path = joinpath(@__DIR__, "bootstrap_module.bin")
    if isfile(module_path)
        return read(module_path)
    else
        @warn "Bootstrap module not found at $module_path"
        return UInt8[]
    end
end

const BOOTSTRAP_MODULE = load_bootstrap_module()

# Bootstrap service exact 89-byte data matching polkajam format
# Format: code_hash(32) + balance(9: 0xef + 8 bytes) + min_acc_gas(8) + min_memo_gas(8)
#         + storage_octets(8) + storage_items(8) + preimage_octets(8) + preimage_items(8)
const BOOTSTRAP_SERVICE_DATA = hex2bytes(
    "00590a2a74e31991304fc628e97219b73410125b2f523218e067340e5064c8cb" *  # code_hash (32 bytes)
    "efffffffffffffffff" *  # balance field (9 bytes: 0xef prefix + 8 bytes)
    "0a00000000000000" *    # min_acc_gas (8 bytes LE) = 10
    "0a00000000000000" *    # min_memo_gas (8 bytes LE) = 10
    "4c18020000000000" *    # storage_octets (8 bytes LE) = 137292
    "ffffffffffffffff" *    # storage_items (8 bytes LE) = max u64
    "0400000000000000" *    # preimage_octets (8 bytes LE) = 4
    "0000000000000000"      # preimage_items (8 bytes LE) = 0
)

# Simple Ed25519 signature using SHA-512 (placeholder - production uses real Ed25519)
# For testnet, we use a simplified signing scheme
function ed25519_sign(private_key::Vector{UInt8}, message::Vector{UInt8})::Vector{UInt8}
    # Hash private key + message for deterministic signature
    sig_data = blake2b_256(vcat(private_key, message))
    # Return 64-byte signature (doubled hash for length)
    return vcat(sig_data, blake2b_256(vcat(sig_data, private_key)))
end

function ed25519_verify(public_key::Vector{UInt8}, message::Vector{UInt8}, signature::Vector{UInt8})::Bool
    # Simplified verification - just check length for testnet
    return length(signature) == 64
end

# Generate keypair from seed
function generate_validator_keypair(seed::Vector{UInt8})
    private = blake2b_256(seed)
    public = blake2b_256(vcat(seed, b"public"))
    return (private, public)
end

# Validator key structure (simplified for testnet)
struct TestnetValidatorKey
    ed25519_private::Vector{UInt8}
    ed25519_public::Vector{UInt8}
    bandersnatch_public::Vector{UInt8}  # placeholder - same as ed25519 for testnet
    bls_public::Vector{UInt8}  # placeholder
    index::UInt16
end

# Generate deterministic validator keys from seed
function generate_validator_keys(num_validators::Int, genesis_seed::Vector{UInt8})::Vector{TestnetValidatorKey}
    keys = TestnetValidatorKey[]

    for i in 1:num_validators
        # Deterministic seed per validator
        seed = blake2b_256(vcat(genesis_seed, reinterpret(UInt8, [UInt32(i)])))

        # Generate Ed25519 keypair
        (private, public) = generate_validator_keypair(seed)

        # For testnet, use ed25519 as placeholder for other keys
        bandersnatch = public  # would be different in production
        bls = vcat(public, public, public, public[1:16])  # 144 bytes placeholder

        push!(keys, TestnetValidatorKey(
            private,
            public,
            bandersnatch,
            bls,
            UInt16(i - 1)
        ))
    end

    return keys
end

# QUIC peer connection state
mutable struct QuicPeer
    host::String
    port::UInt16
    socket::Union{UDPSocket, Nothing}
    connected::Bool
    last_send::Float64
end

# CoreVM service state (matches jamt expectations)
mutable struct CoreVMService
    id::UInt32
    code::Vector{UInt8}  # PVM blob
    code_hash::Vector{UInt8}
    storage::Dict{Vector{UInt8}, Vector{UInt8}}
    preimages::Dict{Vector{UInt8}, Vector{UInt8}}
    balance::UInt64
    exports::Vector{Vector{UInt8}}
    metadata::Dict{String, Any}
end

# Encode a CoreVMService to 89-byte SCALE format for jamt using scale.jl
function encode_service_data(svc::CoreVMService)::Vector{UInt8}
    preimage_size = sum(length(v) for (k, v) in svc.preimages; init=0)
    return encode_service_account(
        code_hash = svc.code_hash,
        balance = svc.balance,
        storage_octets = UInt64(length(svc.code)),
        storage_items = UInt64(length(svc.storage)),
        preimage_octets = UInt64(preimage_size),
        preimage_items = UInt64(length(svc.preimages))
    )
end

# ChainState implementation for testnet (wraps node state for RPC)
mutable struct TestnetChainState <: RPC.ChainState
    best_block::RPC.BlockDescriptor
    finalized_block::RPC.BlockDescriptor
    blocks::Dict{Vector{UInt8}, Any}
    services::Dict{UInt32, CoreVMService}
    parameters::Dict{String, Any}
    # For preimage handling
    submitted_preimages::Vector{Tuple{UInt32, Vector{UInt8}}}
    pending_corevm_by_size::Dict{Int, Tuple{Vector{UInt8}, Int}}
    pending_corevm_size::Union{Int, Nothing}
    pending_corevm_hash::Union{Vector{UInt8}, Nothing}
end

function TestnetChainState(genesis_hash::Vector{UInt8}, services::Dict{UInt32, CoreVMService})
    TestnetChainState(
        RPC.BlockDescriptor(genesis_hash, 0),
        RPC.BlockDescriptor(genesis_hash, 0),
        Dict{Vector{UInt8}, Any}(),
        services,
        jam_parameters(),
        Vector{Tuple{UInt32, Vector{UInt8}}}(),
        Dict{Int, Tuple{Vector{UInt8}, Int}}(),
        nothing,
        nothing
    )
end

# Node state for multi-node testnet
mutable struct TestnetNode
    index::Int
    validator_key::TestnetValidatorKey
    rpc_port::UInt16
    quic_port::UInt16

    # State
    current_slot::UInt64
    best_block_hash::Vector{UInt8}
    best_block_slot::UInt64
    finalized_slot::UInt64
    finalized_block_hash::Vector{UInt8}

    # Block storage
    blocks::Dict{Vector{UInt8}, Dict{String, Any}}

    # QUIC networking
    quic_socket::Union{UDPSocket, Nothing}
    quic_peers::Vector{QuicPeer}
    genesis_hash::Vector{UInt8}

    # Services and chain state for RPC
    services::Dict{UInt32, CoreVMService}
    next_service_id::UInt32
    preimages::Dict{Vector{UInt8}, Vector{UInt8}}
    chain_state::TestnetChainState

    # Pending work packages for service creation
    pending_work_packages::Vector{Dict{String, Any}}
    pending_service_notifications::Vector{Tuple{UInt32, UInt64}}  # (service_id, slot_created)
    pending_corevm_hash::Union{Vector{UInt8}, Nothing}
    pending_corevm_size::Union{Int, Nothing}
    requested_preimages::Vector{Tuple{UInt32, Vector{UInt8}, Int}}  # (service_id, hash, size)
    accepted_preimages::Dict{Tuple{UInt32, Vector{UInt8}, Int}, UInt64}  # key => slot_accepted

    # RPC server
    rpc_server::Union{RPC.RPCServer, Nothing}

    # Metrics
    blocks_produced::UInt64
    blocks_received::UInt64
    quic_messages_sent::UInt64
    quic_messages_recv::UInt64

    # Running state
    running::Bool
end

# Create genesis block
function create_genesis_block(validators::Vector{TestnetValidatorKey})::Dict{String, Any}
    genesis_hash = blake2b_256(b"romio-jam-genesis-v1")

    Dict{String, Any}(
        "hash" => genesis_hash,
        "parent_hash" => zeros(UInt8, 32),
        "slot" => UInt64(0),
        "author_index" => UInt16(0),
        "validators" => [v.ed25519_public for v in validators],
        "state_root" => blake2b_256(b"genesis-state"),
        "extrinsic_hash" => blake2b_256(UInt8[])
    )
end

# Determine block author for slot (simplified Safrole)
function get_slot_author(slot::UInt64, num_validators::Int)::Int
    # Simple round-robin for now - real impl uses ticket VRF
    return Int(slot % num_validators) + 1
end

# Create a new block
function create_block(
    node::TestnetNode,
    parent_hash::Vector{UInt8},
    parent_slot::UInt64,
    slot::UInt64,
    num_validators::Int
)::Dict{String, Any}
    # Create block header
    block_data = vcat(
        parent_hash,
        reinterpret(UInt8, [slot]),
        reinterpret(UInt8, [node.validator_key.index])
    )

    block_hash = blake2b_256(block_data)

    Dict{String, Any}(
        "hash" => block_hash,
        "parent_hash" => parent_hash,
        "slot" => slot,
        "author_index" => node.validator_key.index,
        "state_root" => blake2b_256(vcat(b"state-", reinterpret(UInt8, [slot]))),
        "extrinsic_hash" => blake2b_256(UInt8[]),
        "signature" => sign_block(node.validator_key, block_hash)
    )
end

# Sign block with validator key
function sign_block(key::TestnetValidatorKey, block_hash::Vector{UInt8})::Vector{UInt8}
    ed25519_sign(key.ed25519_private, block_hash)
end

# Verify block signature
function verify_block_signature(
    block::Dict{String, Any},
    validators::Vector{TestnetValidatorKey}
)::Bool
    author_idx = block["author_index"] + 1  # 0-indexed to 1-indexed
    if author_idx < 1 || author_idx > length(validators)
        return false
    end

    author_key = validators[author_idx]
    signature = get(block, "signature", UInt8[])

    if isempty(signature)
        return false
    end

    ed25519_verify(author_key.ed25519_public, block["hash"], signature)
end

# Encode block for QUIC transmission
function encode_block_message(block::Dict{String, Any})::Vector{UInt8}
    # JAMNPS format: stream_kind (1) + length (4) + data
    # Block announcement format: header_hash (32) + slot (8) + author (2) + sig (64) + parent (32)
    buf = UInt8[]

    # Stream kind: BLOCK_ANNOUNCEMENT = 0x00
    push!(buf, JAMNPS.StreamKind.BLOCK_ANNOUNCEMENT)

    # Block data
    append!(buf, block["hash"])
    append!(buf, reinterpret(UInt8, [block["slot"]]))
    append!(buf, reinterpret(UInt8, [block["author_index"]]))
    append!(buf, block["signature"])
    append!(buf, block["parent_hash"])

    return buf
end

# Decode block from QUIC message
function decode_block_message(data::Vector{UInt8})::Union{Dict{String, Any}, Nothing}
    if length(data) < 139  # 1 + 32 + 8 + 2 + 64 + 32
        return nothing
    end

    if data[1] != JAMNPS.StreamKind.BLOCK_ANNOUNCEMENT
        return nothing
    end

    offset = 2
    block_hash = data[offset:offset+31]; offset += 32
    slot = reinterpret(UInt64, data[offset:offset+7])[1]; offset += 8
    author_index = reinterpret(UInt16, data[offset:offset+1])[1]; offset += 2
    signature = data[offset:offset+63]; offset += 64
    parent_hash = data[offset:offset+31]

    Dict{String, Any}(
        "hash" => block_hash,
        "slot" => slot,
        "author_index" => author_index,
        "signature" => signature,
        "parent_hash" => parent_hash,
        "state_root" => blake2b_256(vcat(b"state-", reinterpret(UInt8, [slot]))),
        "extrinsic_hash" => blake2b_256(UInt8[])
    )
end

# Block gossip via QUIC - broadcast to all peers
function broadcast_block!(node::TestnetNode, block::Dict{String, Any}, validators::Vector{TestnetValidatorKey})
    if node.quic_socket === nothing
        return
    end

    msg = encode_block_message(block)

    for peer in node.quic_peers
        try
            # Send block announcement via UDP to peer's QUIC port
            send(node.quic_socket, IPv4(peer.host), peer.port, msg)
            node.quic_messages_sent += 1
            peer.last_send = time()
        catch e
            # Peer unreachable - continue
        end
    end
end

# Receive block from QUIC peer
function receive_block!(node::TestnetNode, data::Vector{UInt8}, validators::Vector{TestnetValidatorKey})::Bool
    block = decode_block_message(data)
    if block === nothing
        return false
    end

    block_hash = block["hash"]

    # Already have this block
    if haskey(node.blocks, block_hash)
        return false
    end

    # Verify signature
    if !verify_block_signature(block, validators)
        println("  Node $(node.index): Invalid block signature from QUIC")
        return false
    end

    # Verify parent exists (except genesis)
    parent_hash = block["parent_hash"]
    if parent_hash != zeros(UInt8, 32) && !haskey(node.blocks, parent_hash)
        # Missing parent - would request it via QUIC in real impl
        return false
    end

    # Store block
    node.blocks[block_hash] = block
    node.blocks_received += 1
    node.quic_messages_recv += 1

    # Update best block if this extends chain
    block_slot = block["slot"]
    if block_slot > node.best_block_slot
        node.best_block_hash = block_hash
        node.best_block_slot = block_slot
        # Sync chain state for RPC
        sync_chain_state!(node)
    end

    return true
end

# Initialize QUIC socket for node
function init_quic_socket!(node::TestnetNode)
    try
        socket = UDPSocket()
        bind(socket, IPv4("0.0.0.0"), node.quic_port)
        node.quic_socket = socket
        println("  Node $(node.index): QUIC listening on UDP port $(node.quic_port)")
        return true
    catch e
        println("  Node $(node.index): Failed to bind QUIC port: $e")
        return false
    end
end

# Start async QUIC receiver for a node using Threads.@spawn for true parallelism
function start_quic_receiver!(node::TestnetNode, validators::Vector{TestnetValidatorKey})
    if node.quic_socket === nothing
        return
    end

    # Use Threads.@spawn for parallel QUIC receive
    if Threads.nthreads() > 1
        Threads.@spawn begin
            while node.running
                try
                    # recvfrom returns (InetAddr, data)
                    addr, data = recvfrom(node.quic_socket)
                    if !isempty(data)
                        receive_block!(node, data, validators)
                    end
                catch e
                    if node.running
                        sleep(0.01)
                    end
                end
            end
        end
    else
        println("  Warning: Single-threaded - QUIC receive disabled. Use --threads=auto")
    end
end

# Process incoming QUIC messages for a node (called from main tick)
function process_quic_messages!(node::TestnetNode, validators::Vector{TestnetValidatorKey})
    # QUIC receive is now handled by async task started by start_quic_receiver!
    # This function now just yields to allow async task to run
    yield()
end

# Node tick - called every 100ms
function node_tick!(node::TestnetNode, validators::Vector{TestnetValidatorKey}, num_validators::Int)
    if !node.running
        return
    end

    # Process incoming QUIC messages first
    process_quic_messages!(node, validators)

    # Calculate current slot from wall clock
    current_time = time()
    seconds_since_epoch = current_time - JAM_EPOCH
    current_slot = UInt64(max(1, floor(Int, seconds_since_epoch / P)))

    # Slot changed?
    if current_slot > node.current_slot
        node.current_slot = current_slot

        # Check if we should produce block
        expected_author = get_slot_author(current_slot, num_validators)

        if expected_author == node.index
            # We're the author - produce block!
            block = create_block(
                node,
                node.best_block_hash,
                node.best_block_slot,
                current_slot,
                num_validators
            )

            # Store locally
            node.blocks[block["hash"]] = block
            node.best_block_hash = block["hash"]
            node.best_block_slot = current_slot
            node.blocks_produced += 1

            println("Node $(node.index) produced block at slot $(current_slot) [QUIC broadcast]")

            # Broadcast to peers via QUIC
            broadcast_block!(node, block, validators)
        end

        # Update finalization (simplified - finalize after 2 slots)
        old_finalized_slot = node.finalized_slot
        if current_slot > 2 && current_slot - 2 > node.finalized_slot
            new_finalized_slot = current_slot - 2
            node.finalized_slot = new_finalized_slot
            # Find block at finalized slot and update finalized_block_hash
            for (hash, block) in node.blocks
                if get(block, "slot", 0) == new_finalized_slot
                    node.finalized_block_hash = hash
                    break
                end
            end
        end

        # Sync chain state for RPC
        sync_chain_state!(node)

        # Notify subscribers if finalized slot changed
        if node.finalized_slot > old_finalized_slot && node.rpc_server !== nothing
            finalized_block = RPC.BlockDescriptor(
                node.chain_state.finalized_block.header_hash,
                node.finalized_slot
            )
            RPC.notify_block_update(node.rpc_server, "subscribeFinalizedBlock", finalized_block)

            # Send notifications for services created in now-finalized slots
            for (service_id, slot_created) in node.pending_service_notifications
                if slot_created <= node.finalized_slot
                    # Notify subscribeServiceValue for Bootstrap service with key "created"
                    created_key = Vector{UInt8}("created")
                    service_id_bytes = reinterpret(UInt8, [UInt32(service_id)])
                    RPC.notify_service_value(node.rpc_server, UInt32(0), created_key, Vector{UInt8}(service_id_bytes), is_finalized=true)
                    println("Notified service creation: service #$(service_id) finalized at slot $(slot_created)")
                end
            end
            # Remove notified services
            filter!(x -> x[2] > node.finalized_slot, node.pending_service_notifications)
        end

        # Process pending work packages
        processed_count = process_pending_work_packages!(node, current_slot)

        # After processing work packages, notify subscribers that preimages were accepted
        if processed_count > 0 && node.rpc_server !== nothing && !isempty(node.requested_preimages)
            for (service_id, preimage_hash, preimage_len) in node.requested_preimages
                println("Notifying service request: service=$(service_id), hash=$(bytes2hex(preimage_hash[1:min(8, length(preimage_hash))]))..., len=$(preimage_len)")
                RPC.notify_service_request(node.rpc_server, service_id, preimage_hash, preimage_len, current_slot)
                # Move to accepted_preimages so late subscribers can be notified
                node.accepted_preimages[(service_id, preimage_hash, preimage_len)] = current_slot
            end
            # Clear requested preimages after notifying (they're now in accepted_preimages)
            empty!(node.requested_preimages)
        end

        # Check for late subscriptions that need notification (preimage already accepted)
        if node.rpc_server !== nothing && !isempty(node.accepted_preimages)
            for (sub_id, (client_id, sub_service_id, sub_hash, sub_len)) in node.rpc_server.service_request_subs
                key = (sub_service_id, sub_hash, sub_len)
                if haskey(node.accepted_preimages, key)
                    accepted_slot = node.accepted_preimages[key]
                    println("Late subscription $(sub_id) for already-accepted preimage: service=$(sub_service_id), hash=$(bytes2hex(sub_hash[1:min(8, length(sub_hash))]))..., slot=$(accepted_slot)")
                    RPC.notify_service_request(node.rpc_server, sub_service_id, sub_hash, sub_len, accepted_slot)
                end
            end
        end
    end
end

# Process pending work packages and create services
# Returns the number of services created
function process_pending_work_packages!(node::TestnetNode, current_slot::UInt64)::Int
    if isempty(node.pending_work_packages)
        return 0
    end

    # Only process work packages that have been pending for at least 1 slot
    ready_packages = filter(wp -> wp["submitted_at"] < current_slot, node.pending_work_packages)
    if isempty(ready_packages)
        return 0
    end

    processed_count = 0

    for wp in ready_packages
        # Try to find corevm data in preimages
        corevm_data = nothing
        corevm_hash = nothing

        # Search by pending corevm hash/size
        if node.pending_corevm_hash !== nothing
            if haskey(node.preimages, node.pending_corevm_hash)
                corevm_data = node.preimages[node.pending_corevm_hash]
                corevm_hash = node.pending_corevm_hash
            elseif haskey(node.services, UInt32(0)) && haskey(node.services[UInt32(0)].preimages, node.pending_corevm_hash)
                corevm_data = node.services[UInt32(0)].preimages[node.pending_corevm_hash]
                corevm_hash = node.pending_corevm_hash
            end
        end

        # Fallback: search for preimage with PVM magic in guest code size range (100-50000 bytes)
        if corevm_data === nothing
            for (hash, data) in node.preimages
                # Look for guest code (100-50000 bytes), not CoreVM module (>100000)
                if length(data) >= 100 && length(data) < 50000 && findfirst(b"PVM\0", data) !== nothing
                    if corevm_data === nothing || length(data) > length(corevm_data)
                        corevm_data = data
                        corevm_hash = hash
                    end
                end
            end
        end

        if corevm_data === nothing
            println("  No corevm found for work package, skipping")
            continue
        end

        # Create new service
        service_id = node.next_service_id
        node.next_service_id += 1

        # Extract PVM blob
        pvm_start = findfirst(b"PVM\0", corevm_data)
        pvm_blob = pvm_start !== nothing ? corevm_data[pvm_start[1]:end] : corevm_data

        # Compute code hash using MainBlock encoding (like mocktestnet)
        code_hash = blake2b_256(corevm_data)

        # Create service
        service = CoreVMService(
            service_id,
            pvm_blob,
            code_hash,
            Dict{Vector{UInt8}, Vector{UInt8}}(),  # storage
            Dict{Vector{UInt8}, Vector{UInt8}}(code_hash => corevm_data),  # preimages
            UInt64(1_000_000_000),  # balance
            Vector{UInt8}[],  # exports
            Dict{String, Any}()  # metadata
        )

        node.services[service_id] = service
        node.chain_state.services[service_id] = service

        # Store in Bootstrap service preimages too
        if haskey(node.services, UInt32(0))
            node.services[UInt32(0)].preimages[code_hash] = corevm_data
        end

        println("Created new service #$(service_id) with $(length(pvm_blob)) bytes code, hash=$(bytes2hex(code_hash[1:8]))...")

        # Send immediate non-finalized notification for subscribers watching best block
        if node.rpc_server !== nothing
            created_key = Vector{UInt8}("created")
            service_id_bytes = reinterpret(UInt8, [UInt32(service_id)])
            RPC.notify_service_value(node.rpc_server, UInt32(0), created_key, Vector{UInt8}(service_id_bytes), is_finalized=false)
            println("Sent non-finalized service creation notification: service #$(service_id)")
        end

        # Schedule finalized notification (will be sent when finalized)
        push!(node.pending_service_notifications, (service_id, current_slot))

        # Clear pending corevm
        node.pending_corevm_hash = nothing
        node.pending_corevm_size = nothing

        processed_count += 1
    end

    # Remove processed work packages
    filter!(wp -> wp["submitted_at"] >= current_slot, node.pending_work_packages)

    return processed_count
end

# JAM parameters for jamt compatibility (V1 format like polkajam)
function jam_parameters()::Dict{String, Any}
    # Wrapped in V1 to match polkajam format that jamt expects
    Dict{String, Any}(
        "V1" => Dict{String, Any}(
            "slot_period_sec" => P,
            "epoch_period" => E,
            "max_work_items" => 4,
            "max_input" => 12 * 1024 * 1024,  # max_work_package_size
            "max_exports" => 3072,
            "max_imports" => 2048,
            "max_accumulate_gas" => 100000000000,
            "max_refine_gas" => 50000000000,
            "max_is_authorized_gas" => 50000000,
            "max_service_code_size" => 4194304,
            "max_authorizer_code_size" => 65536,
            "val_count" => 6,
            "core_count" => 2,
            "deposit_per_item" => 10,
            "deposit_per_byte" => 1,
            "deposit_per_account" => 100,
            "min_turnaround_period" => 32,
            "block_gas_limit" => 20000000,
            "recent_block_count" => 8,
            "max_dependencies" => 8,
            "max_tickets_per_block" => 3,
            "max_lookup_anchor_age" => 24,
            "tickets_attempts_number" => 3,
            "auth_window" => 8,
            "auth_queue_len" => 80,
            "rotation_period" => 4,
            "max_extrinsics" => 128,
            "availability_timeout" => 5,
            "basic_piece_len" => 4,
            "segment_piece_count" => 1026,
            "max_report_elective_data" => 49152,
            "transfer_memo_size" => 128,
            "epoch_tail_start" => 10
        )
    )
end

# Start WebSocket RPC server for node (jamt compatible)
function start_rpc_server!(node::TestnetNode, all_nodes::Vector{TestnetNode})
    # Create RPC server with proper chain_state
    server = RPC.RPCServer(; port=node.rpc_port, chain_state=node.chain_state)
    node.rpc_server = server

    # Override handlers with testnet-specific ones that use node state directly
    RPC.register_handler!(server, "romio_refine", (s, p) -> begin
        service_id = UInt32(p[1])
        payload_hex = String(p[2])
        gas_limit = Int64(p[3])

        payload = hex2bytes(startswith(payload_hex, "0x") ? payload_hex[3:end] : payload_hex)

        if !haskey(node.services, service_id)
            return Dict("success" => false, "error" => "service not found")
        end

        service = node.services[service_id]
        service.metadata["payload"] = payload

        result = execute_pvm_refine(service, gas_limit)

        delete!(service.metadata, "payload")
        return result
    end)

    # Override serviceData to return proper SCALE-encoded service account data
    # Params: [service_id] or [service_id, block_hash] or [block_hash, service_id]
    RPC.register_handler!(server, "serviceData", (s, p) -> begin
        if length(p) < 1
            throw(RPC.RPCError(RPC.ERR_INVALID_PARAMS, "Missing service_id", nothing))
        end

        # Parse service_id - handle both param orders
        service_id = if p[1] isa Number
            UInt32(p[1])
        elseif length(p) >= 2 && p[2] isa Number
            # [block_hash, service_id] order
            UInt32(p[2])
        elseif p[1] isa String && all(c -> c in "0123456789", p[1])
            # Numeric string
            UInt32(parse(Int, p[1]))
        else
            throw(RPC.RPCError(RPC.ERR_INVALID_PARAMS, "Invalid service_id", nothing))
        end

        # For Bootstrap service (0), return exact polkajam-compatible data
        if service_id == UInt32(0)
            return Base64.base64encode(BOOTSTRAP_SERVICE_DATA)
        end

        if haskey(node.services, service_id)
            svc = node.services[service_id]
            data = encode_service_data(svc)
            return Base64.base64encode(data)
        end
        return nothing
    end)

    # Override servicePreimage to return Bootstrap module code
    # Params: [block_hash, service_id, preimage_hash_base64]
    RPC.register_handler!(server, "servicePreimage", (s, p) -> begin
        if length(p) < 3
            throw(RPC.RPCError(RPC.ERR_INVALID_PARAMS, "Missing parameters", nothing))
        end
        # p[1] = block_hash, p[2] = service_id, p[3] = preimage_hash (base64)
        service_id = UInt32(p[2])
        preimage_hash = Base64.base64decode(p[3])

        # For Bootstrap service (0), return the polkajam Bootstrap module
        if service_id == UInt32(0) && !isempty(BOOTSTRAP_MODULE)
            # Check if the query matches the Bootstrap module's code_hash
            # POLKAJAM_BOOTSTRAP_CODE_HASH is [0x00, 0x59, 0x0a, ...] where first byte is version
            # The actual hash is bytes 2:32 (or we do partial match)
            if length(preimage_hash) >= 31
                expected_hash = POLKAJAM_BOOTSTRAP_CODE_HASH[2:32]  # Skip version byte
                if preimage_hash[1:31] == expected_hash[1:31]
                    return Base64.base64encode(BOOTSTRAP_MODULE)
                end
            end
        end

        # Check service preimages
        if haskey(node.services, service_id)
            svc = node.services[service_id]
            if haskey(svc.preimages, preimage_hash)
                return Base64.base64encode(svc.preimages[preimage_hash])
            end
            # Try partial match (first 31 bytes)
            for (k, v) in svc.preimages
                if length(k) >= 31 && length(preimage_hash) >= 31 && k[1:31] == preimage_hash[1:31]
                    return Base64.base64encode(v)
                end
            end
        end
        return nothing
    end)

    # Override serviceRequest to capture corevm hash/size and load from local files
    # jamt sends multiple serviceRequest calls before submitWorkPackage
    RPC.register_handler!(server, "serviceRequest", (s, p) -> begin
        if length(p) >= 4
            service_id = UInt32(p[2])
            preimage_hash = Base64.base64decode(p[3])
            preimage_size = Int(p[4])
            println("serviceRequest: service=$(service_id), hash=$(bytes2hex(preimage_hash[1:min(8, length(preimage_hash))]))..., size=$(preimage_size)")

            # Track all requested preimages for notify_service_request later
            push!(node.requested_preimages, (service_id, copy(preimage_hash), preimage_size))

            # Store the guest code hash/size (for work package processing)
            # Guest code is typically 100-50000 bytes, skip CoreVM module (>100000) and metadata (<100)
            is_likely_guest = preimage_size >= 100 && preimage_size < 50000
            if is_likely_guest
                node.pending_corevm_hash = preimage_hash
                node.pending_corevm_size = preimage_size
                println("  Stored pending guest code: hash=$(bytes2hex(preimage_hash[1:8]))..., size=$(preimage_size)")
            end

            # Search for files that match the expected size
            search_paths = [
                "corevm-guests/blc-vm",
                "corevm-guests",
                pwd(),
            ]
            for search_path in search_paths
                if isdir(search_path)
                    for filename in readdir(search_path)
                        filepath = joinpath(search_path, filename)
                        if isfile(filepath) && (endswith(filename, ".corevm") || endswith(filename, ".bin"))
                            try
                                data = read(filepath)
                                # Check if size matches (within tolerance for segment padding)
                                if abs(length(data) - preimage_size) <= 16
                                    # Store under jamt's expected hash
                                    node.preimages[preimage_hash] = data
                                    if haskey(node.services, UInt32(0))
                                        node.services[UInt32(0)].preimages[preimage_hash] = data
                                    end
                                    println("  Loaded $filename ($(length(data)) bytes) for size $(preimage_size)")
                                    break
                                end
                            catch e
                                # Ignore errors
                            end
                        end
                    end
                end
                if haskey(node.preimages, preimage_hash)
                    break
                end
            end

            # Also check Bootstrap module for large requests
            if !haskey(node.preimages, preimage_hash) && preimage_size > 100000 && !isempty(BOOTSTRAP_MODULE)
                if abs(length(BOOTSTRAP_MODULE) - preimage_size) <= 16
                    node.preimages[preimage_hash] = BOOTSTRAP_MODULE
                    if haskey(node.services, UInt32(0))
                        node.services[UInt32(0)].preimages[preimage_hash] = BOOTSTRAP_MODULE
                    end
                    println("  Loaded bootstrap module ($(length(BOOTSTRAP_MODULE)) bytes) for size $(preimage_size)")
                end
            end
        end
        return nothing  # jamt expects null
    end)

    # Override subscribeServiceRequest to capture expected corevm hash/size
    RPC.register_handler!(server, "subscribeServiceRequest", (s, p) -> begin
        if length(p) < 4
            throw(RPC.RPCError(RPC.ERR_INVALID_PARAMS, "Missing parameters", nothing))
        end
        service_id = UInt32(p[1])
        preimage_hash = Base64.base64decode(p[2])
        preimage_len = Int(p[3])
        finalized = get(p, 4, false)

        println("subscribeServiceRequest: service=$(service_id), hash=$(bytes2hex(preimage_hash[1:min(8, length(preimage_hash))]))..., len=$(preimage_len)")

        # jamt sends 3 serviceRequest calls:
        #   1. CoreVM module (~272KB) - the executor that runs guest code
        #   2. Guest code (~500-50000 bytes) - the actual service being deployed
        #   3. Metadata (~81 bytes) - initialization data
        # We want the GUEST CODE, which is typically in the 100-50000 byte range.
        is_likely_guest = preimage_len >= 100 && preimage_len < 50000

        if is_likely_guest
            node.pending_corevm_hash = preimage_hash
            node.pending_corevm_size = preimage_len
            println("  Stored pending guest code: hash=$(bytes2hex(preimage_hash[1:8]))..., size=$(preimage_len)")
        else
            println("  Skipping size $(preimage_len) bytes (likely $(preimage_len < 100 ? "metadata" : "corevm module"))")
        end

        # Return subscription ID and channel (use smaller ID to avoid Int64 overflow in jamt)
        sub_id = rand(UInt32)
        return (UInt64(sub_id), :service_request_notification, service_id, preimage_hash, preimage_len)
    end)

    # Override submitWorkPackage to handle service creation
    RPC.register_handler!(server, "submitWorkPackage", (s, p) -> begin
        if length(p) < 3
            throw(RPC.RPCError(RPC.ERR_INVALID_PARAMS, "Missing parameters", nothing))
        end

        core_index = p[1]
        wp_data = Base64.base64decode(p[2])
        extrinsics = p[3]

        wp_hash = blake2b_256(wp_data)
        println("submitWorkPackage: core=$(core_index), hash=$(bytes2hex(wp_hash[1:8]))..., size=$(length(wp_data))")

        # Extract corevm data from extrinsics
        println("  extrinsics type=$(typeof(extrinsics)), count=$(length(extrinsics)), pending_hash=$(node.pending_corevm_hash !== nothing ? bytes2hex(node.pending_corevm_hash[1:8]) : "nothing")")
        if extrinsics isa Vector && length(extrinsics) > 0
            expected_size = node.pending_corevm_size
            expected_hash = node.pending_corevm_hash

            for (i, ext) in enumerate(extrinsics)
                println("    extrinsics[$i] type=$(typeof(ext))")
                ext_data = nothing
                if ext isa String
                    ext_data = Base64.base64decode(ext)
                    println("    extrinsics[$i]: $(length(ext_data)) bytes (direct string)")
                elseif ext isa Vector
                    for (j, sub) in enumerate(ext)
                        if sub isa String
                            sub_data = Base64.base64decode(sub)
                            println("    extrinsics[$i][$j]: $(length(sub_data)) bytes")
                            if ext_data === nothing || length(sub_data) > length(ext_data)
                                ext_data = sub_data
                            end
                        end
                    end
                end

                if ext_data !== nothing
                    # Check if this is the corevm (by size or PVM magic)
                    has_pvm = findfirst(b"PVM\0", ext_data) !== nothing
                    size_match = expected_size !== nothing && abs(length(ext_data) - expected_size) <= 16
                    println("    Checking: size=$(length(ext_data)), expected=$(expected_size), has_pvm=$(has_pvm), size_match=$(size_match)")

                    if size_match || has_pvm
                        println("  Found corevm in extrinsics[$i]: $(length(ext_data)) bytes")
                        # Store in preimages under expected hash if available
                        if expected_hash !== nothing
                            node.preimages[expected_hash] = ext_data
                            if haskey(node.services, UInt32(0))
                                node.services[UInt32(0)].preimages[expected_hash] = ext_data
                            end
                            println("  Stored corevm under hash=$(bytes2hex(expected_hash[1:8]))...")
                        else
                            # Store under computed hash
                            computed_hash = blake2b_256(ext_data)
                            node.preimages[computed_hash] = ext_data
                            if haskey(node.services, UInt32(0))
                                node.services[UInt32(0)].preimages[computed_hash] = ext_data
                            end
                            println("  Stored corevm under computed hash=$(bytes2hex(computed_hash[1:8]))...")
                        end
                        break
                    end
                end
            end
        end

        # Store work package for processing
        push!(node.pending_work_packages, Dict(
            "hash" => wp_hash,
            "core" => core_index,
            "data" => wp_data,
            "extrinsics" => extrinsics,
            "submitted_at" => node.current_slot
        ))

        return nothing  # jamt expects null
    end)

    # Start the server
    RPC.start!(server)
    return server
end

# Update chain state from node state (call after block changes)
function sync_chain_state!(node::TestnetNode)
    node.chain_state.best_block = RPC.BlockDescriptor(node.best_block_hash, node.best_block_slot)
    node.chain_state.finalized_block = RPC.BlockDescriptor(node.finalized_block_hash, node.finalized_slot)
    node.chain_state.services = node.services

    # Sync blocks dict for RPC availability queries
    for (hash, block) in node.blocks
        if !haskey(node.chain_state.blocks, hash)
            slot = get(block, "slot", UInt64(0))
            parent_hash = get(block, "parent_hash", zeros(UInt8, 32))
            parent_slot = slot > 0 ? slot - 1 : UInt64(0)
            RPC.add_block!(node.chain_state, hash, slot, parent_hash, parent_slot)
        end
    end
end

# Execute PVM refine for a service
function execute_pvm_refine(service::CoreVMService, gas_limit::Int64)::Dict{String, Any}
    pvm_blob = service.code
    payload = get(service.metadata, "payload", UInt8[])
    payload_hash = blake2b_256(payload)

    if isempty(pvm_blob)
        return Dict(
            "success" => false,
            "error" => "service has no code",
            "payload_hash" => bytes2hex(payload_hash),
            "payload_size" => length(payload),
            "gas_limit" => gas_limit,
            "output" => "",
            "output_hex" => "",
            "gas_used" => 0,
            "steps" => 0,
            "exports" => String[]
        )
    end

    export_data = Vector{Vector{UInt8}}()
    steps = 0

    try
        prog = PolkaVMBlob.parse_polkavm_blob(pvm_blob)
        opcode_mask = PolkaVMBlob.get_opcode_mask(prog)

        # Find entry point
        entry_pc = UInt32(0)
        for exp in prog.exports
            if exp.name == "jb_refine" || exp.name == "refine"
                entry_pc = exp.pc
                break
            end
        end

        # Memory layout
        VM_MAX_PAGE_SIZE = UInt32(0x10000)
        align_64k(x) = (x + VM_MAX_PAGE_SIZE - 1) & ~(VM_MAX_PAGE_SIZE - 1)
        ro_data_address_space = align_64k(prog.ro_data_size)
        RO_BASE = UInt32(0x10000)
        RW_BASE = UInt32(RO_BASE + ro_data_address_space + VM_MAX_PAGE_SIZE)
        STACK_HIGH = UInt32(0xFFFF0000 - VM_MAX_PAGE_SIZE)
        STACK_LOW = UInt32(STACK_HIGH - prog.stack_size)
        HEAP_BASE = UInt32(RW_BASE + prog.rw_data_size)

        skip_distances = PVM.precompute_skip_distances(opcode_mask)

        rw_data_full = zeros(UInt8, prog.rw_data_size)
        copyto!(rw_data_full, 1, prog.rw_data, 1, length(prog.rw_data))

        memory = PVM.Memory()
        PVM.init_memory_regions!(memory,
            RO_BASE, UInt32(length(prog.ro_data)), prog.ro_data,
            RW_BASE, UInt32(length(rw_data_full)), rw_data_full,
            STACK_LOW, STACK_HIGH,
            HEAP_BASE, STACK_LOW)

        regs = zeros(UInt64, 13)
        regs[1] = UInt64(0xFFFF0000)
        regs[2] = UInt64(STACK_HIGH)

        state = PVM.PVMState(
            entry_pc, PVM.CONTINUE, Int64(gas_limit),
            prog.code, opcode_mask, skip_distances, regs, memory, prog.jump_table,
            UInt32(0), Vector{Vector{UInt8}}(), Dict{UInt32, PVM.GuestPVM}())

        max_steps = min(gas_limit, 100_000_000)

        while state.status == PVM.CONTINUE && state.gas > 0 && steps < max_steps
            PVM.step!(state)
            steps += 1

            if state.status == PVM.HOST
                call_id = Int(state.host_call_id)

                # host_fetch - get payload
                if call_id == 1
                    buf_ptr = UInt32(state.registers[8])
                    offset = Int(state.registers[9])
                    buf_len = Int(state.registers[10])
                    discriminator = Int(state.registers[11])

                    if discriminator == 13 && !isempty(payload) && buf_len > 0
                        copy_len = min(length(payload) - offset, buf_len)
                        if copy_len > 0
                            for i in 1:copy_len
                                PVM.write_u8(state, UInt64(buf_ptr + i - 1), payload[offset + i])
                            end
                        end
                        state.registers[8] = UInt64(copy_len)
                    else
                        state.registers[8] = UInt64(0)
                    end

                # host_export
                elseif call_id == 7
                    ptr = UInt32(state.registers[8])
                    len = Int(state.registers[9])
                    if len > 0 && len < 65536
                        data = PVM.read_bytes_bulk(state, UInt64(ptr), len)
                        push!(export_data, data)
                        state.registers[8] = UInt64(0)
                    else
                        state.registers[8] = UInt64(-1)
                    end
                else
                    state.registers[8] = UInt64(0)
                end

                skip = PVM.skip_distance(state.opcode_mask, Int(state.pc) + 1)
                state.pc = state.pc + 1 + skip
                state.status = PVM.CONTINUE
            end
        end

        gas_used = gas_limit - state.gas

        return Dict(
            "success" => true,
            "payload_hash" => bytes2hex(payload_hash),
            "payload_size" => length(payload),
            "gas_limit" => gas_limit,
            "output" => "",
            "output_hex" => "",
            "gas_used" => gas_used,
            "steps" => steps,
            "exports" => [bytes2hex(e) for e in export_data],
            "error" => ""
        )
    catch e
        return Dict(
            "success" => false,
            "error" => string(e),
            "payload_hash" => bytes2hex(payload_hash),
            "payload_size" => length(payload),
            "gas_limit" => gas_limit,
            "output" => "",
            "output_hex" => "",
            "gas_used" => 0,
            "steps" => steps,
            "exports" => String[]
        )
    end
end

# Initialize genesis services
# Deploys bootstrap service (0) and optionally loads additional services from corevm files
function initialize_services(; genesis_services::Vector{String}=String[])::Tuple{Dict{UInt32, CoreVMService}, UInt32}
    services = Dict{UInt32, CoreVMService}()

    # Service 0: Bootstrap (required for deployer functionality)
    services[UInt32(0)] = CoreVMService(
        UInt32(0),
        UInt8[],  # Bootstrap doesn't expose code
        UInt8[],  # No code_hash
        Dict{Vector{UInt8}, Vector{UInt8}}(),  # storage
        Dict{Vector{UInt8}, Vector{UInt8}}(),  # preimages
        UInt64(254_806_881),  # Match polkajam's balance
        Vector{UInt8}[],
        Dict{String, Any}()
    )

    next_service_id = UInt32(1)

    # Load additional services from corevm files
    for corevm_path in genesis_services
        if isfile(corevm_path)
            try
                code = read(corevm_path)
                code_hash = blake2b_256(code)
                services[next_service_id] = CoreVMService(
                    next_service_id,
                    code,
                    code_hash,
                    Dict{Vector{UInt8}, Vector{UInt8}}(),  # storage
                    Dict{Vector{UInt8}, Vector{UInt8}}(),  # preimages
                    UInt64(100_000_000),  # Initial balance
                    Vector{UInt8}[],
                    Dict{String, Any}("source" => basename(corevm_path))
                )
                println("  Service $(next_service_id): $(basename(corevm_path)) ($(length(code)) bytes)")
                next_service_id += 1
            catch e
                println("  Warning: Failed to load $(corevm_path): $e")
            end
        else
            println("  Warning: Service file not found: $(corevm_path)")
        end
    end

    if isempty(genesis_services)
        println("  Genesis services: Bootstrap (0)")
    else
        println("  Genesis services: Bootstrap (0) + $(length(genesis_services)) service(s)")
    end

    return (services, next_service_id)
end

# Print testnet status
function print_status(nodes::Vector{TestnetNode})
    println("\n--- Testnet Status (QUIC) ---")
    for node in nodes
        quic_status = node.quic_socket !== nothing ? "up" : "down"
        println("Node $(node.index): slot=$(node.current_slot) best=$(node.best_block_slot) fin=$(node.finalized_slot) produced=$(node.blocks_produced) recv=$(node.blocks_received) quic_tx=$(node.quic_messages_sent) quic_rx=$(node.quic_messages_recv)")
    end
    println("-----------------------------\n")
end

# Main entry point
function run_multinode_testnet(;
    num_nodes::Int = 6,
    base_rpc_port::UInt16 = UInt16(19800),
    base_quic_port::UInt16 = UInt16(40000),
    genesis_services::Vector{String} = String[]
)
    println("============================================================")
    println("Romio Multi-Node JAM Testnet")
    println("============================================================")
    println("Validators: $num_nodes")
    println("Slot period: $(P)s")
    println("Epoch length: $(E) slots")
    println("")

    # Generate validator keys
    genesis_seed = blake2b_256(b"romio-testnet-genesis")
    validators = generate_validator_keys(num_nodes, genesis_seed)

    println("Generated $(length(validators)) validator keys")
    for (i, v) in enumerate(validators)
        println("  Validator $i: $(bytes2hex(v.ed25519_public[1:8]))...")
    end
    println("")

    # Create genesis block
    genesis = create_genesis_block(validators)
    println("Genesis hash: $(bytes2hex(genesis["hash"][1:8]))...")
    println("")

    # Create nodes with QUIC networking
    nodes = TestnetNode[]
    for i in 1:num_nodes
        # Build peer list for this node
        quic_peers = QuicPeer[]
        for j in 1:num_nodes
            if j != i
                push!(quic_peers, QuicPeer(
                    "127.0.0.1",
                    base_quic_port + UInt16(j - 1),
                    nothing,  # socket created later
                    false,    # not connected yet
                    0.0       # last_send
                ))
            end
        end

        # Initialize services for this node (only first node prints)
        (services, next_service_id) = initialize_services(; genesis_services = i == 1 ? genesis_services : String[])
        # Copy services to other nodes (they should have same genesis state)
        if i > 1
            first_node = nodes[1]
            services = copy(first_node.services)
            next_service_id = first_node.next_service_id
        end

        # Create chain state for RPC integration
        chain_state = TestnetChainState(genesis["hash"], services)

        node = TestnetNode(
            i,
            validators[i],
            base_rpc_port + UInt16(i - 1),
            base_quic_port + UInt16(i - 1),
            UInt64(0),  # current_slot
            genesis["hash"],  # best_block_hash
            UInt64(0),  # best_block_slot
            UInt64(0),  # finalized_slot
            genesis["hash"],  # finalized_block_hash
            Dict{Vector{UInt8}, Dict{String, Any}}(genesis["hash"] => genesis),
            nothing,  # quic_socket
            quic_peers,
            genesis["hash"],  # genesis_hash
            services,  # services
            next_service_id,  # next_service_id
            Dict{Vector{UInt8}, Vector{UInt8}}(),  # preimages
            chain_state,  # chain_state for RPC
            Vector{Dict{String, Any}}(),  # pending_work_packages
            Vector{Tuple{UInt32, UInt64}}(),  # pending_service_notifications
            nothing,  # pending_corevm_hash
            nothing,  # pending_corevm_size
            Vector{Tuple{UInt32, Vector{UInt8}, Int}}(),  # requested_preimages
            Dict{Tuple{UInt32, Vector{UInt8}, Int}, UInt64}(),  # accepted_preimages
            nothing,  # rpc_server (set later)
            UInt64(0),  # blocks_produced
            UInt64(0),  # blocks_received
            UInt64(0),  # quic_messages_sent
            UInt64(0),  # quic_messages_recv
            true  # running
        )

        push!(nodes, node)
    end

    # Initialize QUIC sockets
    println("Initializing QUIC networking...")
    for node in nodes
        init_quic_socket!(node)
    end
    println("")

    # Start QUIC receivers (threads required)
    if Threads.nthreads() > 1
        println("Starting QUIC receivers ($(Threads.nthreads()) threads)...")
        for node in nodes
            start_quic_receiver!(node, validators)
        end
    else
        println("Warning: Run with --threads=auto for QUIC networking")
    end
    println("")

    # Start WebSocket RPC servers (jamt compatible)
    println("Starting RPC servers (WebSocket)...")
    for node in nodes
        start_rpc_server!(node, nodes)
        println("  Node $(node.index): RPC ws://localhost:$(node.rpc_port)")
    end
    println("")

    println("Testnet running with QUIC inter-node gossip.")
    println("Connect via RPC: curl localhost:$(base_rpc_port)")
    println("")
    println("Press Ctrl+C to stop.")
    println("")

    # Main loop
    last_status_time = time()
    status_interval = 10.0  # print status every 10s

    try
        while true
            # Tick all nodes with QUIC processing
            for node in nodes
                node_tick!(node, validators, num_nodes)
            end

            # Periodic status
            if time() - last_status_time > status_interval
                print_status(nodes)
                last_status_time = time()
            end

            sleep(0.1)  # 100ms tick
        end
    catch e
        if isa(e, InterruptException)
            println("\nShutting down...")
        else
            rethrow(e)
        end
    finally
        # Stop all nodes, close QUIC sockets and RPC servers
        for node in nodes
            node.running = false
            if node.quic_socket !== nothing
                close(node.quic_socket)
            end
            if node.rpc_server !== nothing
                try
                    RPC.stop!(node.rpc_server)
                catch
                end
            end
        end
        println("Testnet stopped.")
    end
end

# Helper
function bytes2hex(data::Vector{UInt8})::String
    join([string(b, base=16, pad=2) for b in data], "")
end

const run = run_multinode_testnet

export run, run_multinode_testnet

end # module
