# Julia JAM Testnet - Compatible with polkajam jamt/corevm tooling
#
# Usage:
#   julia --project=. -e 'include("src/testnet/testnet.jl"); JuliaJAMTestnet.run_testnet()'
#
# Then connect with:
#   jamt --rpc ws://localhost:19800 vm new ./doom.corevm 1000000000

module JuliaJAMTestnet

using JSON
using Base64
using StaticArrays

# Include Blake2b implementation for JAM-compatible hashing
const CRYPTO_DIR = joinpath(dirname(@__DIR__), "crypto")
include(joinpath(CRYPTO_DIR, "Blake2b.jl"))

# blake2b-256 hash function (JAM's primary hash)
function blake2b_256(data::Union{Vector{UInt8}, Base.CodeUnits{UInt8, String}})::Vector{UInt8}
    input = Vector{UInt8}(data)
    output = zeros(UInt8, 32)
    Blake2b!(output, 32, UInt8[], 0, input, length(input))
    return output
end

# Get the directory of this file for relative includes
const TESTNET_DIR = @__DIR__
const SRC_DIR = dirname(TESTNET_DIR)

# Include RPC server
include(joinpath(SRC_DIR, "rpc", "server.jl"))

using .RPC

# polkajam's exact Bootstrap service code_hash
const POLKAJAM_BOOTSTRAP_CODE_HASH = UInt8[
    0x00, 0x59, 0x0a, 0x2a, 0x74, 0xe3, 0x19, 0x91, 0x30, 0x4f, 0xc6, 0x28, 0xe9, 0x72, 0x19, 0xb7,
    0x34, 0x10, 0x12, 0x5b, 0x2f, 0x52, 0x32, 0x18, 0xe0, 0x67, 0x34, 0x0e, 0x50, 0x64, 0xc8, 0xcb
]

# Bootstrap metadata preimage key: jamt uses serviceData[2:33] (code_hash[2:32] + balance prefix)
# Since balance starts with 0xef (4-byte Natural encoding), key ends with 0xef
const BOOTSTRAP_METADATA_KEY = UInt8[
    0x59, 0x0a, 0x2a, 0x74, 0xe3, 0x19, 0x91, 0x30, 0x4f, 0xc6, 0x28, 0xe9, 0x72, 0x19, 0xb7,
    0x34, 0x10, 0x12, 0x5b, 0x2f, 0x52, 0x32, 0x18, 0xe0, 0x67, 0x34, 0x0e, 0x50, 0x64, 0xc8, 0xcb,
    0xef  # Must match serviceData[33] which is balance prefix byte (0xef for 4-byte Natural)
]

# Bootstrap service exact 89-byte data matching polkajam format
# Note: polkajam uses 0xef prefix for balance (4-byte Natural), not 0xff (9-byte Natural)
const BOOTSTRAP_SERVICE_DATA = hex2bytes(
    "00590a2a74e31991304fc628e97219b73410125b2f523218e067340e5064c8cb" *  # code_hash (32 bytes)
    "efffffffffffffffff" *  # balance field (9 bytes: 0xef prefix + 8 bytes) - matches polkajam exactly
    "0a00000000000000" *    # min_acc_gas (8 bytes LE) = 10
    "0a00000000000000" *    # min_memo_gas (8 bytes LE) = 10
    "4c18020000000000" *    # storage_octets (8 bytes LE) = 137292
    "ffffffffffffffff" *    # storage_items (8 bytes LE) = max u64
    "0400000000000000" *    # preimage_octets (8 bytes LE) = 4
    "0000000000000000"      # preimage_items (8 bytes LE) = 0
)

# Bootstrap service corevm module - loaded from polkajam's actual Bootstrap service
# This is the full 137KB Bootstrap module that jamt expects to find via servicePreimage
function load_bootstrap_module()::Vector{UInt8}
    module_path = joinpath(@__DIR__, "bootstrap_module.bin")
    if isfile(module_path)
        return read(module_path)
    else
        @warn "Bootstrap module not found at $module_path, using stub"
        # Fallback stub module with minimal metadata
        return UInt8[
            0x32, 0x00,  # metadata length = 50 bytes
            0x15, b"jam-bootstrap-service"...,  # name (21 bytes)
            0x06, b"0.1.27"...,  # version (6 bytes)
            0x0a, b"Apache-2.0"...,  # license (10 bytes)
            0x01, 0x25,  # author length prefix
        ]
    end
end

const BOOTSTRAP_MODULE = load_bootstrap_module()

# JAM codec helpers for variable-length Natural encoding
function encode_natural(x::Integer)::Vector{UInt8}
    if x == 0
        return [0x00]
    elseif x < 128
        return [UInt8(x)]
    elseif x < 16384
        return [UInt8(0x80 | (x >> 8)), UInt8(x & 0xff)]
    elseif x < 2097152
        return [UInt8(0xc0 | (x >> 16)), UInt8((x >> 8) & 0xff), UInt8(x & 0xff)]
    else
        # 9-byte encoding for large numbers
        result = Vector{UInt8}(undef, 9)
        result[1] = 0xff
        for i in 1:8
            result[i+1] = UInt8((x >> (8*(i-1))) & 0xff)
        end
        return result
    end
end

function encode_u32(x::UInt32)::Vector{UInt8}
    return [UInt8(x & 0xff), UInt8((x >> 8) & 0xff),
            UInt8((x >> 16) & 0xff), UInt8((x >> 24) & 0xff)]
end

function encode_u64(x::UInt64)::Vector{UInt8}
    return [UInt8(x & 0xff), UInt8((x >> 8) & 0xff),
            UInt8((x >> 16) & 0xff), UInt8((x >> 24) & 0xff),
            UInt8((x >> 32) & 0xff), UInt8((x >> 40) & 0xff),
            UInt8((x >> 48) & 0xff), UInt8((x >> 56) & 0xff)]
end

# CoreVM Service - wrapper that jamt expects
mutable struct CoreVMService
    service_id::UInt32
    code::Vector{UInt8}
    storage::Dict{Vector{UInt8}, Vector{UInt8}}
    preimages::Dict{Vector{UInt8}, Vector{UInt8}}
    balance::UInt64
    exports::Vector{Vector{UInt8}}  # Exported segments (frames, etc.)
end

# Segment storage for DA layer
mutable struct SegmentStore
    # segment_root => [segments]
    segments::Dict{Vector{UInt8}, Vector{Vector{UInt8}}}
    # work_package_hash => segment_root
    wp_to_root::Dict{Vector{UInt8}, Vector{UInt8}}
end

SegmentStore() = SegmentStore(
    Dict{Vector{UInt8}, Vector{Vector{UInt8}}}(),
    Dict{Vector{UInt8}, Vector{UInt8}}()
)

# Live chain state connected to validator
mutable struct LiveChainState <: RPC.ChainState
    # Block tracking
    best_block::RPC.BlockDescriptor
    finalized_block::RPC.BlockDescriptor
    blocks::Dict{Vector{UInt8}, Any}

    # Services
    services::Dict{UInt32, CoreVMService}
    next_service_id::UInt32

    # Protocol parameters
    parameters::Dict{String, Any}

    # DA layer
    segment_store::SegmentStore

    # Work packages
    pending_work_packages::Vector{Any}
    work_reports::Dict{Vector{UInt8}, Any}

    # Preimages
    preimages::Dict{Vector{UInt8}, Vector{UInt8}}

    # Slot tracking
    current_slot::UInt64
    slot_start_time::Float64

    # Requested preimages: (service_id, hash, len) => slot_requested
    # Used to track which preimages jamt is waiting for
    requested_preimages::Dict{Tuple{UInt32, Vector{UInt8}, Int}, UInt64}

    # Accepted preimages: (service_id, hash, len) => slot_accepted
    # Used to notify late subscribers that preimage is already available
    accepted_preimages::Dict{Tuple{UInt32, Vector{UInt8}, Int}, UInt64}

    # Submitted preimages: list of (service_id, data) tuples
    # jamt submits preimages via submitPreimage RPC, we store them here
    submitted_preimages::Vector{Tuple{UInt32, Vector{UInt8}}}

    # Pending finalized notifications: slot => [service_ids created at that slot]
    # When a slot becomes finalized, we send finalized service value notifications
    pending_finalized_notifications::Dict{UInt64, Vector{UInt32}}

    # Pending best-block notifications: slot => [(service_id, block_descriptor_when_created)]
    # Deferred to next slot so jamt has time to set up subscription handler
    pending_best_notifications::Dict{UInt64, Vector{Tuple{UInt32, RPC.BlockDescriptor}}}

    # Recently created services: (service_id_from, key) => (service_id_value, slot_created)
    # Used to send immediate notifications to late subscribers
    recent_service_values::Dict{Tuple{UInt32, Vector{UInt8}}, Tuple{UInt32, UInt64}}
end

function LiveChainState()
    genesis_hash = blake2b_256(b"julia-jam-genesis")

    # Create Bootstrap service (service ID 0) - required for jamt vm new
    # Store the Bootstrap module in preimages dict with the correct key
    bootstrap_preimages = Dict{Vector{UInt8}, Vector{UInt8}}()
    # Key is BOOTSTRAP_METADATA_KEY (code_hash[2:32] + balance_prefix 0xef)
    bootstrap_preimages[Vector{UInt8}(BOOTSTRAP_METADATA_KEY)] = BOOTSTRAP_MODULE

    services = Dict{UInt32, CoreVMService}()
    services[UInt32(0)] = CoreVMService(
        UInt32(0),
        UInt8[],  # Bootstrap doesn't expose its code via servicePreimage
        Dict{Vector{UInt8}, Vector{UInt8}}(),
        bootstrap_preimages,  # Contains Bootstrap module for jamt metadata lookup
        UInt64(254_806_881),  # Match polkajam's balance
        Vector{UInt8}[]
    )

    # Global preimages dict
    preimages = Dict{Vector{UInt8}, Vector{UInt8}}()

    LiveChainState(
        RPC.BlockDescriptor(genesis_hash, 0),
        RPC.BlockDescriptor(genesis_hash, 0),
        Dict{Vector{UInt8}, Any}(),
        services,
        UInt32(1),  # next service IDs start at 1
        jam_parameters(),
        SegmentStore(),
        Any[],
        Dict{Vector{UInt8}, Any}(),
        preimages,
        UInt64(0),
        time(),
        Dict{Tuple{UInt32, Vector{UInt8}, Int}, UInt64}(),  # requested_preimages
        Dict{Tuple{UInt32, Vector{UInt8}, Int}, UInt64}(),  # accepted_preimages
        Tuple{UInt32, Vector{UInt8}}[],  # submitted_preimages
        Dict{UInt64, Vector{UInt32}}(),  # pending_finalized_notifications
        Dict{UInt64, Vector{Tuple{UInt32, RPC.BlockDescriptor}}}(),  # pending_best_notifications
        Dict{Tuple{UInt32, Vector{UInt8}}, Tuple{UInt32, UInt64}}()  # recent_service_values
    )
end

function jam_parameters()::Dict{String, Any}
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

# Create a new CoreVM service from .corevm file
function create_corevm_service!(chain::LiveChainState, code::Vector{UInt8}, amount::UInt64)::UInt32
    service_id = chain.next_service_id
    chain.next_service_id += 1

    # Parse .corevm metadata header (skip to PVM blob)
    pvm_start = findfirst(b"PVM\0", code)
    pvm_blob = if pvm_start !== nothing
        code[pvm_start[1]:end]
    else
        code  # Assume raw PVM blob
    end

    code_hash = blake2b_256(pvm_blob)

    service = CoreVMService(
        service_id,
        pvm_blob,
        Dict{Vector{UInt8}, Vector{UInt8}}(),
        Dict{Vector{UInt8}, Vector{UInt8}}(code_hash => pvm_blob),
        amount,
        Vector{UInt8}[]
    )

    chain.services[service_id] = service
    println("Created CoreVM service #$(service_id) with $(length(pvm_blob)) bytes code")

    return service_id
end

# Store exported segments
function store_segments!(chain::LiveChainState, segment_root::Vector{UInt8}, segments::Vector{Vector{UInt8}})
    chain.segment_store.segments[segment_root] = segments
end

# Testnet RPC handlers (override defaults for live chain)
function setup_testnet_handlers!(server::RPC.RPCServer, chain::LiveChainState)
    # Override parameters to use live chain
    RPC.register_handler!(server, "parameters", (s, p) -> chain.parameters)

    # Override block handlers
    RPC.register_handler!(server, "bestBlock", (s, p) -> begin
        RPC.block_descriptor_to_json(chain.best_block)
    end)

    RPC.register_handler!(server, "finalizedBlock", (s, p) -> begin
        RPC.block_descriptor_to_json(chain.finalized_block)
    end)

    # Service handlers
    RPC.register_handler!(server, "listServices", (s, p) -> begin
        collect(keys(chain.services))
    end)

    RPC.register_handler!(server, "serviceData", (s, p) -> begin
        if length(p) < 2
            throw(RPC.RPCError(RPC.ERR_INVALID_PARAMS, "Missing service_id", nothing))
        end
        service_id = UInt32(p[2])

        # For Bootstrap service (0), return exact polkajam-compatible data
        if service_id == UInt32(0)
            return base64encode(BOOTSTRAP_SERVICE_DATA)
        end

        if haskey(chain.services, service_id)
            svc = chain.services[service_id]
            code_hash = if isempty(svc.code)
                zeros(UInt8, 32)
            else
                blake2b_256(svc.code)
            end

            # polkajam format: 89 bytes total
            data = vcat(
                code_hash,                            # code_hash: 32 bytes
                encode_natural(svc.balance),          # balance: Natural (9 bytes)
                encode_u64(UInt64(0)),                # min_acc_gas
                encode_u64(UInt64(0)),                # min_memo_gas
                encode_u64(UInt64(0)),                # storage_octets
                encode_u64(UInt64(0)),                # storage_items
                encode_u64(UInt64(0)),                # preimage_octets
                encode_u64(UInt64(0))                 # preimage_items
            )
            return base64encode(data)
        end
        return nothing
    end)

    # Service request - jamt uses this to request preimages
    # Format: [block_hash_b64, service_id, preimage_hash_b64, size]
    # This is a hint/request, not a data submission - jamt is telling us what it needs
    # We return null (like polkajam) - the actual preimages come through work package processing
    RPC.register_handler!(server, "serviceRequest", (s, p) -> begin
        if length(p) >= 4
            # p[1] = block_hash (String), p[2] = service_id (Int), p[3] = hash (String), p[4] = size (Int)
            service_id = UInt32(p[2])
            preimage_hash = base64decode(p[3])
            preimage_size = Int(p[4])
            println("serviceRequest: service=$(service_id), hash=$(bytes2hex(preimage_hash[1:min(8, length(preimage_hash))]))..., size=$(preimage_size)")

            # Track this request in chain state so we can notify when it becomes available
            chain.requested_preimages[(service_id, preimage_hash, preimage_size)] = chain.current_slot
        end
        return nothing
    end)

    # Service preimage lookup - jamt uses this to fetch Bootstrap code
    RPC.register_handler!(server, "servicePreimage", (s, p) -> begin
        if length(p) < 3
            throw(RPC.RPCError(RPC.ERR_INVALID_PARAMS, "Missing parameters", nothing))
        end
        # p[1] = block, p[2] = service_id, p[3] = preimage_hash (base64)
        service_id = UInt32(p[2])
        preimage_hash = base64decode(p[3])
        println("servicePreimage: service=$(service_id), hash=$(bytes2hex(preimage_hash)), b64=$(p[3])")

        if haskey(chain.services, service_id)
            svc = chain.services[service_id]
            println("  service $(service_id) found, preimages count: $(length(svc.preimages))")
            for (k, v) in svc.preimages
                println("    stored key: $(bytes2hex(k)) ($(length(v)) bytes)")
            end
            # Check service's preimages
            if haskey(svc.preimages, preimage_hash)
                println("  FOUND in service preimages!")
                return base64encode(svc.preimages[preimage_hash])
            end
        end

        # Check global preimages
        println("  checking global preimages ($(length(chain.preimages)) entries)...")
        if haskey(chain.preimages, preimage_hash)
            println("  FOUND in global preimages!")
            return base64encode(chain.preimages[preimage_hash])
        end

        println("  NOT FOUND")
        return nothing
    end)

    # Work package submission - this is what jamt vm new uses
    RPC.register_handler!(server, "submitWorkPackage", (s, p) -> begin
        if length(p) < 3
            throw(RPC.RPCError(RPC.ERR_INVALID_PARAMS, "Missing parameters", nothing))
        end

        # p[1] = core_index, p[2] = work_package (base64), p[3] = extrinsics (usually empty for jamt)
        core_index = p[1]
        wp_data = base64decode(p[2])
        extrinsics = p[3]

        # Store work package
        wp_hash = blake2b_256(wp_data)
        push!(chain.pending_work_packages, Dict(
            "hash" => wp_hash,
            "core" => core_index,
            "data" => wp_data,
            "extrinsics" => extrinsics,
            "submitted_at" => chain.current_slot
        ))

        println("Received work package for core $(core_index), hash=$(bytes2hex(wp_hash[1:8]))...")

        # jamt expects null response from submitWorkPackage
        # Service request notifications are sent in the main loop after processing
        return nothing
    end)

    # Preimage submission
    RPC.register_handler!(server, "submitPreimage", (s, p) -> begin
        if length(p) < 2
            throw(RPC.RPCError(RPC.ERR_INVALID_PARAMS, "Missing parameters", nothing))
        end

        service_id = UInt32(p[1])
        preimage = base64decode(p[2])
        preimage_hash = blake2b_256(preimage)
        preimage_len = length(preimage)

        # Store in chain preimages
        chain.preimages[preimage_hash] = preimage

        # If service exists, also store there
        if haskey(chain.services, service_id)
            chain.services[service_id].preimages[preimage_hash] = preimage
        end

        println("Stored preimage for service $(service_id), hash=$(bytes2hex(preimage_hash[1:8]))..., size=$(preimage_len)")

        # Notify subscribers that this preimage is now available
        RPC.notify_service_request(server, service_id, preimage_hash, preimage_len, chain.current_slot)

        return nothing
    end)

    # Fetch segments - critical for corevm-monitor
    RPC.register_handler!(server, "fetchSegments", (s, p) -> begin
        if length(p) < 2
            throw(RPC.RPCError(RPC.ERR_INVALID_PARAMS, "Missing parameters", nothing))
        end

        segment_root = base64decode(p[1])
        indices = p[2]  # Array of segment indices

        if haskey(chain.segment_store.segments, segment_root)
            segments = chain.segment_store.segments[segment_root]
            result = Vector{Union{String, Nothing}}()
            for idx in indices
                if idx >= 0 && idx < length(segments)
                    push!(result, base64encode(segments[idx + 1]))
                else
                    push!(result, nothing)
                end
            end
            return result
        end

        throw(RPC.RPCError(RPC.ERR_DA_SEGMENT_UNAVAILABLE, "Segments not available", base64encode(segment_root)))
    end)

    # Work package status
    RPC.register_handler!(server, "workPackageStatus", (s, p) -> begin
        if length(p) < 3
            throw(RPC.RPCError(RPC.ERR_INVALID_PARAMS, "Missing parameters", nothing))
        end

        # Check if we have a work report for this package
        wp_hash = base64decode(p[2])
        if haskey(chain.work_reports, wp_hash)
            report = chain.work_reports[wp_hash]
            return Dict{String, Any}("Reported" => Dict(
                "report_hash" => base64encode(report["hash"]),
                "reported_in" => report["slot"]
            ))
        end

        # Check if pending
        for wp in chain.pending_work_packages
            if wp["hash"] == wp_hash
                return Dict{String, Any}("Completed" => nothing)
            end
        end

        return Dict{String, Any}("Unknown" => nothing)
    end)

    # Sync status - jamt waits for this
    RPC.register_handler!(server, "syncState", (s, p) -> begin
        Dict{String, Any}(
            "num_peers" => 1,  # Pretend we have peers
            "status" => "Completed"
        )
    end)
end

# Process Bootstrap work package - creates a new service
function process_bootstrap_work_package!(chain::LiveChainState, wp::Dict)::Union{Dict, Nothing}
    # Extract work package data
    wp_data = wp["data"]
    wp_hash = wp["hash"]

    # Parse the work package - Bootstrap expects specific format
    # For now, assume the work package contains the .corevm file data
    # jamt sends: authorization, context, payload where payload has the service code

    # Try to find PVM blob in the work package
    pvm_start = findfirst(b"PVM\0", wp_data)
    if pvm_start === nothing
        println("  No PVM magic found in work package, treating as raw blob")
        # Could be a raw work package, try to extract anyway
        # Look for length-prefixed data typical of corevm format
        if length(wp_data) < 100
            println("  Work package too small, skipping")
            return nothing
        end
    end

    # Create new service with next available ID
    service_id = chain.next_service_id
    chain.next_service_id += 1

    # Extract the PVM blob (everything from PVM magic onwards)
    pvm_blob = if pvm_start !== nothing
        wp_data[pvm_start[1]:end]
    else
        wp_data  # Use raw data
    end

    code_hash = blake2b_256(pvm_blob)

    # Create the service
    service = CoreVMService(
        service_id,
        pvm_blob,
        Dict{Vector{UInt8}, Vector{UInt8}}(),
        Dict{Vector{UInt8}, Vector{UInt8}}(code_hash => pvm_blob),  # Store code as preimage
        UInt64(1_000_000_000),  # Initial balance from jamt request
        Vector{UInt8}[]
    )

    chain.services[service_id] = service
    println("  Created new service #$(service_id) with $(length(pvm_blob)) bytes code, hash=$(bytes2hex(code_hash[1:8]))...")

    # Return work result for inclusion in work report
    return Dict(
        "service_id" => service_id,
        "code_hash" => code_hash,
        "success" => true
    )
end

# Process pending work packages for a slot
function process_pending_work_packages!(chain::LiveChainState)::Vector{Dict}
    work_results = Dict[]

    if isempty(chain.pending_work_packages)
        return work_results
    end

    println("Processing $(length(chain.pending_work_packages)) pending work package(s)...")

    for wp in chain.pending_work_packages
        wp_hash = wp["hash"]
        core = wp["core"]

        println("  Work package on core $(core), hash=$(bytes2hex(wp_hash[1:8]))...")

        # For now, assume all work packages go to Bootstrap service
        # In a real implementation, we'd parse the work package header to determine the service
        result = process_bootstrap_work_package!(chain, wp)

        if result !== nothing
            push!(work_results, result)

            # Store work report
            report_hash = blake2b_256(vcat(wp_hash, reinterpret(UInt8, [chain.current_slot])))
            chain.work_reports[wp_hash] = Dict(
                "hash" => report_hash,
                "slot" => chain.current_slot,
                "result" => result
            )
        end
    end

    # Clear processed work packages
    empty!(chain.pending_work_packages)

    return work_results
end

# Slot ticker - advances chain state
# Returns (finalized_new_block, processed_work_package_count, created_service_ids)
function slot_tick!(chain::LiveChainState)::Tuple{Bool, Int, Vector{UInt32}}
    current_time = time()
    slot_duration = 6.0  # 6 seconds per slot
    finalized_new_block = false
    processed_count = 0
    created_service_ids = UInt32[]

    elapsed = current_time - chain.slot_start_time
    if elapsed >= slot_duration
        chain.current_slot += 1
        chain.slot_start_time = current_time

        # Process any pending work packages first
        work_results = process_pending_work_packages!(chain)
        processed_count = length(work_results)

        # Extract created service IDs from work results
        for wr in work_results
            if haskey(wr, "service_id") && get(wr, "success", false)
                push!(created_service_ids, UInt32(wr["service_id"]))
            end
        end

        # Create new block (include work results in block hash for uniqueness)
        work_data = isempty(work_results) ? UInt8[] : blake2b_256(Vector{UInt8}(string(work_results)))
        new_hash = blake2b_256(vcat(chain.best_block.header_hash, reinterpret(UInt8, [chain.current_slot]), work_data))

        # Store parent reference
        chain.blocks[new_hash] = Dict(
            "slot" => chain.current_slot,
            "parent_hash" => chain.best_block.header_hash,
            "parent_slot" => chain.best_block.slot,
            "work_results" => work_results
        )

        chain.best_block = RPC.BlockDescriptor(new_hash, chain.current_slot)

        # Finalize after 2 slots
        if chain.current_slot > 2
            finalized_slot = chain.current_slot - 2
            old_finalized = chain.finalized_block.slot
            # Find block at that slot
            for (hash, info) in chain.blocks
                if info["slot"] == finalized_slot
                    chain.finalized_block = RPC.BlockDescriptor(hash, finalized_slot)
                    if finalized_slot > old_finalized
                        finalized_new_block = true
                    end
                    break
                end
            end
        end

        println("Slot $(chain.current_slot) - best: $(bytes2hex(new_hash[1:8]))... (finalized: $(chain.finalized_block.slot))")
    end
    return (finalized_new_block, processed_count, created_service_ids)
end

# Main testnet entry point
function run_testnet(; port::UInt16 = UInt16(19800))
    println("="^60)
    println("Julia JAM Testnet")
    println("="^60)
    println("Compatible with polkajam jamt/corevm tooling")
    println("")

    # Create live chain state
    chain = LiveChainState()
    println("Genesis hash: $(bytes2hex(chain.best_block.header_hash[1:8]))...")

    # Create RPC server with live chain
    server = RPC.RPCServer(port=port, chain_state=chain)
    setup_testnet_handlers!(server, chain)

    println("\nStarting RPC server on port $(port)...")
    RPC.start!(server)

    println("\nTestnet running. Connect with:")
    println("  jamt --rpc ws://localhost:$(port) vm new ./doom.corevm 1000000000")
    println("\nPress Ctrl+C to stop.\n")

    # Track last broadcast slot to avoid duplicate notifications
    last_best_slot = chain.current_slot

    # "created" key for Bootstrap service value subscriptions (ASCII for "created")
    created_key = Vector{UInt8}("created")

    try
        while true
            (new_finalized, processed_count, created_service_ids) = slot_tick!(chain)

            # Broadcast best block notification when slot advances
            if chain.current_slot > last_best_slot
                RPC.notify_block_update(server, "subscribeBestBlock", chain.best_block)
                last_best_slot = chain.current_slot

                # Send pending best-block service value notifications (deferred from previous slot)
                # This ensures jamt has time to set up its subscription handler
                if haskey(chain.pending_best_notifications, chain.current_slot)
                    for (pending_service_id, block_when_created) in chain.pending_best_notifications[chain.current_slot]
                        service_id_bytes = reinterpret(UInt8, [UInt32(pending_service_id)])
                        println("Notifying subscribeServiceValue (best): service 0, key='created', value=$(pending_service_id) [deferred, created at slot $(block_when_created.slot)]")
                        RPC.notify_service_value(server, UInt32(0), created_key, Vector{UInt8}(service_id_bytes), block=block_when_created)
                    end
                    delete!(chain.pending_best_notifications, chain.current_slot)
                end

                # If work packages were processed this slot, notify service request subscribers
                # for all requested preimages (simulating Bootstrap accepting them)
                if processed_count > 0
                    for ((service_id, preimage_hash, preimage_len), requested_slot) in chain.requested_preimages
                        println("Notifying service request subscribers: service=$(service_id), hash=$(bytes2hex(preimage_hash[1:min(8, length(preimage_hash))]))..., len=$(preimage_len)")
                        RPC.notify_service_request(server, service_id, preimage_hash, preimage_len, chain.current_slot)
                        # Move to accepted_preimages so late subscribers can be notified
                        chain.accepted_preimages[(service_id, preimage_hash, preimage_len)] = chain.current_slot
                    end
                    # Clear the requested preimages now that they're in accepted_preimages
                    empty!(chain.requested_preimages)
                end

                # Check if any new subscriptions are for already-accepted preimages (only once per sub)
                subs_to_remove = Int64[]
                for (sub_id, (client_id, sub_service_id, sub_hash, sub_len)) in server.service_request_subs
                    key = (sub_service_id, sub_hash, sub_len)
                    if haskey(chain.accepted_preimages, key)
                        accepted_slot = chain.accepted_preimages[key]
                        println("Late subscription $(sub_id) for already-accepted preimage: service=$(sub_service_id), slot=$(accepted_slot)")
                        RPC.notify_service_request(server, sub_service_id, sub_hash, sub_len, accepted_slot)
                        # Remove after sending to avoid repeated notifications
                        push!(subs_to_remove, sub_id)
                    end
                end
                for sub_id in subs_to_remove
                    delete!(server.service_request_subs, sub_id)
                end

                # Queue service value notifications to be sent on the NEXT slot
                # This ensures jamt has time to set up its subscription handler after
                # submitting the work package and calling subscribeServiceValue
                # Store the block descriptor where the service was created
                current_block = chain.best_block
                for new_service_id in created_service_ids
                    # Queue for best-block notification on next slot, with the block where it was created
                    next_slot = chain.current_slot + 1
                    if !haskey(chain.pending_best_notifications, next_slot)
                        chain.pending_best_notifications[next_slot] = Tuple{UInt32, RPC.BlockDescriptor}[]
                    end
                    push!(chain.pending_best_notifications[next_slot], (new_service_id, current_block))

                    # Track for finalized notification later
                    if !haskey(chain.pending_finalized_notifications, chain.current_slot)
                        chain.pending_finalized_notifications[chain.current_slot] = UInt32[]
                    end
                    push!(chain.pending_finalized_notifications[chain.current_slot], new_service_id)

                    # Track for late subscription handling
                    # Store the most recent value for (service_id=0, key="created")
                    chain.recent_service_values[(UInt32(0), created_key)] = (new_service_id, chain.current_slot)

                    # Also persist in service 0's storage for serviceValue RPC queries
                    service_id_bytes = reinterpret(UInt8, [UInt32(new_service_id)])
                    chain.services[UInt32(0)].storage[created_key] = Vector{UInt8}(service_id_bytes)
                end
            end

            # Note: Late service value subscription handling removed - subscriptions should only
            # receive notifications for events that happen AFTER subscription, not retroactively.
            # jamt expects to wait for the new service from the work package it just submitted,
            # not get notifications about previously created services.

            # Broadcast finalized block notification if new block was finalized
            if new_finalized
                RPC.notify_block_update(server, "subscribeFinalizedBlock", chain.finalized_block)

                # Send finalized service value notifications for services created at the now-finalized slot
                finalized_slot = chain.finalized_block.slot
                if haskey(chain.pending_finalized_notifications, finalized_slot)
                    for finalized_service_id in chain.pending_finalized_notifications[finalized_slot]
                        service_id_bytes = reinterpret(UInt8, [UInt32(finalized_service_id)])
                        println("Notifying subscribeServiceValue (finalized): service 0, key='created', value=$(finalized_service_id)")
                        RPC.notify_service_value(server, UInt32(0), created_key, Vector{UInt8}(service_id_bytes), is_finalized=true)
                    end
                    delete!(chain.pending_finalized_notifications, finalized_slot)
                end
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
        RPC.stop!(server)
    end
end

export run_testnet, LiveChainState, CoreVMService

end # module

# Run if executed directly
if abspath(PROGRAM_FILE) == @__FILE__
    using .JuliaJAMTestnet
    run_testnet()
end
