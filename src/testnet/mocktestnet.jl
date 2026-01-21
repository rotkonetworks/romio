# Mock JAM Testnet - Single-node mock for jamt/frontend testing
#
# Usage:
#   julia --project=. -e 'include("src/testnet/mocktestnet.jl"); MockTestnet.run()'
#
# For real multi-node testnet, use testnet.jl instead.

module MockTestnet

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

# Include JAM protocol constants (JAM_EPOCH, P, E, jam_slot, jam_epoch)
include(joinpath(SRC_DIR, "constants.jl"))

# Include RPC server
include(joinpath(SRC_DIR, "rpc", "server.jl"))

using .RPC

# Include PVM modules for actual execution
include(joinpath(SRC_DIR, "pvm", "pvm.jl"))
include(joinpath(SRC_DIR, "pvm", "polkavm_blob.jl"))
include(joinpath(SRC_DIR, "pvm", "corevm_extension.jl"))

using .PVM
using .PolkaVMBlob
using .CoreVMExtension

# Include JAM encoding and CoreVM file hash functions
include(joinpath(SRC_DIR, "encoding", "jam.jl"))
include(joinpath(SRC_DIR, "corevm", "fs.jl"))

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

# Wrap raw PVM blob in polkavm corevm format for jamt compatibility
# Format: '<' version(0) name_len name ver_len version lic_len license author_len author <blob>
# The blob should start with PVM\0 magic
function wrap_pvm_in_corevm(pvm_blob::Vector{UInt8}, service_id::UInt32)::Vector{UInt8}
    service_name = "service-$(service_id)"
    service_version = "0.1"
    service_license = "MIT"
    service_author = "testnet"

    header = UInt8[]
    push!(header, 0x3c)  # '<' marker
    push!(header, 0x00)  # version 0
    # name with length prefix
    push!(header, UInt8(length(service_name)))
    append!(header, Vector{UInt8}(service_name))
    # version with length prefix
    push!(header, UInt8(length(service_version)))
    append!(header, Vector{UInt8}(service_version))
    # license with length prefix
    push!(header, UInt8(length(service_license)))
    append!(header, Vector{UInt8}(service_license))
    # author with length prefix
    push!(header, UInt8(length(service_author)))
    append!(header, Vector{UInt8}(service_author))

    # Append the actual PVM blob (must start with PVM\0 magic)
    append!(header, pvm_blob)

    return header
end

# CoreVM Service - wrapper that jamt expects
mutable struct CoreVMService
    service_id::UInt32
    code::Vector{UInt8}
    code_hash::Vector{UInt8}  # Hash of full corevm file (for servicePreimage lookup)
    storage::Dict{Vector{UInt8}, Vector{UInt8}}
    preimages::Dict{Vector{UInt8}, Vector{UInt8}}
    balance::UInt64
    exports::Vector{Vector{UInt8}}  # Exported segments (frames, etc.)
    metadata::Dict{String, Any}  # Runtime metadata like payload for JAM services
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

    # Pending corevm size and hash for next Bootstrap work package
    # When subscribeServiceRequest is called for Bootstrap (service 0), we store
    # the requested preimage size here so process_bootstrap_work_package! can find
    # the matching corevm by size (since jamt's hash includes padding we can't reproduce)
    # We store a dictionary mapping size -> (hash, size) so we can look up the hash for a given size
    pending_corevm_size::Union{Nothing, Int64}
    pending_corevm_hash::Union{Nothing, Vector{UInt8}}
    # Map from expected size to (hash, size) for all serviceRequest calls
    pending_corevm_by_size::Dict{Int64, Tuple{Vector{UInt8}, Int64}}
    # Segment-padded data extracted from extrinsics in submitWorkPackage
    # This is the exact data jamt expects back from servicePreimage
    pending_segment_data::Union{Nothing, Vector{UInt8}}
end

function LiveChainState()
    genesis_hash = blake2b_256(b"julia-jam-genesis")

    # Create Bootstrap service (service ID 0) - required for jamt vm new
    # Store the Bootstrap module in preimages dict with the correct key
    bootstrap_preimages = Dict{Vector{UInt8}, Vector{UInt8}}()
    # Key is BOOTSTRAP_METADATA_KEY (code_hash[2:32] + balance_prefix 0xef)
    bootstrap_preimages[Vector{UInt8}(BOOTSTRAP_METADATA_KEY)] = BOOTSTRAP_MODULE

    # Pre-load all .corevm files for PVM execution
    # jamt sends the code hash via serviceRequest, but the actual data comes from local files
    # We load all .corevm files so Bootstrap can deploy any of them
    corevm_search_paths = [
        "/tmp/polkajam-v0.1.27-linux-x86_64",
        "/home/alice/rotko/blc-service/services/output",
    ]
    for search_path in corevm_search_paths
        if isdir(search_path)
            for filename in readdir(search_path)
                if endswith(filename, ".corevm")
                    filepath = joinpath(search_path, filename)
                    if isfile(filepath)
                        data = read(filepath)
                        # Only load files with polkajam corevm format (starts with 'P' = 0x50)
                        # or doom-style format (starts with '<' = 0x3c)
                        # Skip files with old SCALE format (starts with '(' = 0x28)
                        if length(data) > 0 && data[1] in [0x50, 0x3c]
                            hash = blake2b_256(data)
                            # Store in bootstrap preimages with its hash as key
                            bootstrap_preimages[hash] = data
                            println("Loaded $filename: $(length(data)) bytes, hash=$(bytes2hex(hash[1:8]))...")
                        elseif length(data) > 0 && data[1] == 0x28
                            println("Skipping $filename: old SCALE format (starts with '(')")
                        end
                    end
                end
            end
        end
    end

    services = Dict{UInt32, CoreVMService}()
    services[UInt32(0)] = CoreVMService(
        UInt32(0),
        UInt8[],  # Bootstrap doesn't expose its code via servicePreimage
        UInt8[],  # No code_hash for Bootstrap
        Dict{Vector{UInt8}, Vector{UInt8}}(),
        bootstrap_preimages,  # Contains Bootstrap module for jamt metadata lookup
        UInt64(254_806_881),  # Match polkajam's balance
        Vector{UInt8}[],
        Dict{String, Any}()  # metadata
    )

    # Create BLC service (service ID 1) - load actual blc-vm.corevm for real PVM execution
    blc_vm_path = "/home/alice/rotko/blc-service/services/output/blc-vm.corevm"
    if isfile(blc_vm_path)
        blc_corevm_data = read(blc_vm_path)
        blc_hash = blake2b_256(blc_corevm_data)
        # Also store in bootstrap preimages so it can be looked up
        bootstrap_preimages[blc_hash] = blc_corevm_data

        # Extract PVM blob from corevm header
        pvm_start = findfirst(b"PVM\0", blc_corevm_data)
        blc_pvm_blob = pvm_start !== nothing ? blc_corevm_data[pvm_start[1]:end] : blc_corevm_data

        # Compute lookup keys
        _, _, mainblock_hash = encode_corevm_file(blc_corevm_data)
        jamt_lookup_key = vcat(mainblock_hash[1:31], UInt8[0xef])

        services[UInt32(1)] = CoreVMService(
            UInt32(1),
            blc_pvm_blob,  # Real PVM blob for execution
            mainblock_hash,  # Hash of MainBlock-encoded file
            Dict{Vector{UInt8}, Vector{UInt8}}(),  # storage
            Dict{Vector{UInt8}, Vector{UInt8}}(
                mainblock_hash => blc_corevm_data,
                jamt_lookup_key => blc_corevm_data,
                blc_hash => blc_corevm_data
            ),  # preimages
            UInt64(100_000_000),  # balance
            Vector{UInt8}[],  # exports
            Dict{String, Any}("description" => "Binary Lambda Calculus evaluator (PVM)")
        )
        println("Registered BLC service at ID 1 with $(length(blc_pvm_blob)) bytes PVM code")
    else
        # Fallback to mock if blc-vm.corevm not found
        services[UInt32(1)] = CoreVMService(
            UInt32(1),
            UInt8[0x42, 0x4c, 0x43],  # "BLC" marker as pseudo-code
            blake2b_256(b"blc-native-service"),  # pseudo code hash
            Dict{Vector{UInt8}, Vector{UInt8}}(),  # storage
            Dict{Vector{UInt8}, Vector{UInt8}}(),  # preimages
            UInt64(100_000_000),  # balance
            Vector{UInt8}[],  # exports
            Dict{String, Any}("native" => "blc", "description" => "Binary Lambda Calculus evaluator (mock)")
        )
        println("WARNING: blc-vm.corevm not found, using mock BLC service at ID 1")
    end

    # Global preimages dict
    preimages = Dict{Vector{UInt8}, Vector{UInt8}}()

    LiveChainState(
        RPC.BlockDescriptor(genesis_hash, 0),
        RPC.BlockDescriptor(genesis_hash, 0),
        Dict{Vector{UInt8}, Any}(),
        services,
        UInt32(2),  # next service IDs start at 2 (0=Bootstrap, 1=BLC)
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
        Dict{Tuple{UInt32, Vector{UInt8}}, Tuple{UInt32, UInt64}}(),  # recent_service_values
        nothing,  # pending_corevm_size
        nothing,  # pending_corevm_hash
        Dict{Int64, Tuple{Vector{UInt8}, Int64}}(),  # pending_corevm_by_size
        nothing  # pending_segment_data
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

    # Encode corevm file in MainBlock format to compute the hash
    # encode_corevm_file returns (main_block, continuation_blocks, hash)
    _, _, mainblock_hash = encode_corevm_file(code)

    # jamt lookup key: code_hash[1:31] + 0xef (balance prefix)
    # jamt reads bytes [1:32] from serviceData as the preimage lookup key
    # serviceData format: version(1) + code_hash(31) + 0xef + balance(8) + ...
    jamt_lookup_key = vcat(mainblock_hash[1:31], UInt8[0xef])

    # Store RAW corevm data (not MainBlock-encoded) - this matches polkajam behavior
    service = CoreVMService(
        service_id,
        pvm_blob,  # PVM blob for execution
        mainblock_hash,  # Hash of MainBlock-encoded file
        Dict{Vector{UInt8}, Vector{UInt8}}(),
        Dict{Vector{UInt8}, Vector{UInt8}}(
            mainblock_hash => code,    # MainBlock hash -> raw corevm data
            jamt_lookup_key => code    # jamt's lookup key -> raw corevm data
        ),
        amount,
        Vector{UInt8}[],
        Dict{String, Any}()  # metadata
    )

    chain.services[service_id] = service
    println("Created CoreVM service #$(service_id) with $(length(pvm_blob)) bytes code ($(length(code)) corevm), mainblock_hash=$(bytes2hex(mainblock_hash[1:8]))...")

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

            # Build JAM service state format (89 bytes)
            # Structure matches Bootstrap service (service 0) format exactly:
            # - version (1 byte) = 0x00 (jamt checks this is valid)
            # - code_hash (31 bytes) - first 31 bytes of the hash
            # - balance (9 bytes: 0xef prefix + 8 bytes LE for max u64)
            # - min_acc_gas (8 bytes LE)
            # - min_memo_gas (8 bytes LE)
            # - storage_octets (8 bytes LE)
            # - storage_items (8 bytes LE)
            # - preimage_octets (8 bytes LE)
            # - preimage_items (8 bytes LE)
            # Total: 1 + 31 + 9 + 8*6 = 1 + 31 + 9 + 48 = 89 bytes
            #
            # Note: jamt uses version(1) + code_hash(31) = 32 bytes as the preimage lookup key
            # So we also store the preimage under [0x00, code_hash[1:31]...] for lookup
            data = UInt8[]

            # version (1 byte) = 0x00 (required by jamt)
            push!(data, 0x00)

            # code_hash (31 bytes) - first 31 bytes of actual hash
            if isempty(svc.code_hash)
                append!(data, zeros(UInt8, 31))
            else
                append!(data, svc.code_hash[1:min(31, length(svc.code_hash))])
                if length(svc.code_hash) < 31
                    append!(data, zeros(UInt8, 31 - length(svc.code_hash)))
                end
            end

            # balance (9 bytes: 0xef prefix + 8 bytes LE)
            push!(data, 0xef)
            append!(data, encode_u64(svc.balance))

            # min_acc_gas (8 bytes LE)
            append!(data, encode_u64(UInt64(10)))

            # min_memo_gas (8 bytes LE)
            append!(data, encode_u64(UInt64(10)))

            # storage_octets (8 bytes LE)
            append!(data, encode_u64(UInt64(length(svc.code))))

            # storage_items (8 bytes LE)
            append!(data, encode_u64(UInt64(length(svc.storage))))

            # preimage_octets (8 bytes LE)
            preimage_size = sum(length(v) for (k, v) in svc.preimages; init=0)
            append!(data, encode_u64(UInt64(preimage_size)))

            # preimage_items (8 bytes LE)
            append!(data, encode_u64(UInt64(length(svc.preimages))))

            return base64encode(data)
        end
        return nothing
    end)

    # Service request - jamt uses this to request preimages
    # Format: [block_hash_b64, service_id, preimage_hash_b64, size]
    # This is a hint/request, not a data submission - jamt is telling us what it needs
    # We try to load the preimage from local files and store it for use during work package processing
    RPC.register_handler!(server, "serviceRequest", (s, p) -> begin
        if length(p) >= 4
            # p[1] = block_hash (String), p[2] = service_id (Int), p[3] = hash (String), p[4] = size (Int)
            service_id = UInt32(p[2])
            preimage_hash = base64decode(p[3])
            preimage_size = Int(p[4])
            println("serviceRequest: service=$(service_id), hash=$(bytes2hex(preimage_hash[1:min(8, length(preimage_hash))]))..., size=$(preimage_size)")

            # Track this request in chain state so we can notify when it becomes available
            chain.requested_preimages[(service_id, preimage_hash, preimage_size)] = chain.current_slot

            # Store jamt's expected hash and size for later use in process_bootstrap_work_package!
            # This is critical: jamt calculates hash differently than we do, so we must use jamt's hash
            # Also store in the size-indexed dictionary for lookup during work package processing
            chain.pending_corevm_by_size[preimage_size] = (copy(preimage_hash), preimage_size)

            # IMPORTANT: jamt sends multiple serviceRequest calls:
            #   1. CoreVM module (~272KB) - the executor that runs guest code
            #   2. Guest code (~1-10KB typically) - the actual service being deployed
            #   3. Metadata (~81 bytes) - initialization data
            # We want the GUEST CODE, which is typically in the 500-50000 byte range.
            # Filter out the corevm module (too large) and metadata (too small).
            is_likely_guest = preimage_size >= 500 && preimage_size < 100000
            current_size = chain.pending_corevm_size

            if is_likely_guest && (current_size === nothing || preimage_size < current_size || current_size >= 100000)
                # Prefer smaller guest code size over larger (smaller is more specific)
                chain.pending_corevm_hash = preimage_hash
                chain.pending_corevm_size = preimage_size
                println("  Stored pending_corevm_hash=$(bytes2hex(preimage_hash[1:8]))..., size=$(preimage_size)")
            else
                println("  Skipping size $(preimage_size) bytes (likely $(preimage_size < 500 ? "metadata" : preimage_size >= 100000 ? "corevm module" : "not preferred"))")
            end

            # Try to load from local corevm files and store as preimage
            # IMPORTANT: Store under JAMT's expected hash, not the file's computed hash
            # This enables deploying arbitrary services without hardcoding paths
            if !haskey(chain.preimages, preimage_hash)
                search_paths = [
                    "/tmp/polkajam-v0.1.27-linux-x86_64",
                    "/home/alice/rotko/blc-service/services/output",
                    "/tmp",
                ]
                for search_path in search_paths
                    if isdir(search_path)
                        for filename in readdir(search_path)
                            filepath = joinpath(search_path, filename)
                            if isfile(filepath) && (endswith(filename, ".corevm") || endswith(filename, ".jam"))
                                try
                                    data = read(filepath)
                                    # Match by size since jamt's hash includes padding
                                    # If file is smaller than expected, pad with zeros to match
                                    if length(data) == preimage_size
                                        # Exact match, use as-is
                                        padded_data = data
                                    elseif length(data) < preimage_size && preimage_size - length(data) <= 16
                                        # Pad with zeros to match expected size
                                        padded_data = vcat(data, zeros(UInt8, preimage_size - length(data)))
                                        println("  Padded $(length(data)) bytes -> $(length(padded_data)) bytes")
                                    else
                                        continue  # Size mismatch too large
                                    end

                                    # TESTNET WORKAROUND: Store under JAMT's expected hash unconditionally
                                    # We can't replicate jamt's padding algorithm, so trust jamt's hash
                                    # and store the data under that hash. jamt will verify when it fetches.
                                    chain.preimages[preimage_hash] = padded_data
                                    # Also store in Bootstrap service preimages
                                    if haskey(chain.services, UInt32(0))
                                        chain.services[UInt32(0)].preimages[preimage_hash] = padded_data
                                    end
                                    println("  Loaded preimage from $filepath: $(length(padded_data)) bytes, stored under jamt's hash (testnet mode)")
                                    break
                                catch e
                                    # Ignore read errors
                                end
                            end
                        end
                    end
                    haskey(chain.preimages, preimage_hash) && break
                end
            end
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

        # Helper function to find preimage by exact match or partial match (first 31 bytes)
        # This handles the case where serviceData returns a truncated hash (version byte + 31 bytes)
        # but the actual stored hash is 32 bytes
        function find_preimage(preimages::Dict{Vector{UInt8}, Vector{UInt8}}, hash::Vector{UInt8})
            # Try exact match first
            if haskey(preimages, hash)
                return preimages[hash]
            end

            # Try partial match (first 31 bytes) - this handles the version byte workaround
            if length(hash) >= 31
                for (k, v) in preimages
                    if length(k) >= 31 && k[1:31] == hash[1:31]
                        println("    PARTIAL MATCH on first 31 bytes: $(bytes2hex(k))")
                        return v
                    end
                end
            end

            return nothing
        end

        if haskey(chain.services, service_id)
            svc = chain.services[service_id]
            println("  service $(service_id) found, preimages count: $(length(svc.preimages))")
            for (k, v) in svc.preimages
                println("    stored key: $(bytes2hex(k)) ($(length(v)) bytes)")
            end
            # Check service's preimages (with partial match support)
            result = find_preimage(svc.preimages, preimage_hash)
            if result !== nothing
                println("  FOUND in service preimages!")
                return base64encode(result)
            end
        end

        # Check Bootstrap service (0) preimages - jamt looks up service code here
        if service_id != UInt32(0) && haskey(chain.services, UInt32(0))
            bootstrap = chain.services[UInt32(0)]
            result = find_preimage(bootstrap.preimages, preimage_hash)
            if result !== nothing
                println("  FOUND in Bootstrap preimages!")
                return base64encode(result)
            end
        end

        # Check global preimages
        println("  checking global preimages ($(length(chain.preimages)) entries)...")
        result = find_preimage(chain.preimages, preimage_hash)
        if result !== nothing
            println("  FOUND in global preimages!")
            return base64encode(result)
        end

        println("  NOT FOUND")
        return nothing
    end)

    # Work package submission - this is what jamt vm new uses
    RPC.register_handler!(server, "submitWorkPackage", (s, p) -> begin
        if length(p) < 3
            throw(RPC.RPCError(RPC.ERR_INVALID_PARAMS, "Missing parameters", nothing))
        end

        # p[1] = core_index, p[2] = work_package (base64), p[3] = extrinsics (Array of Blobs per RPC spec)
        core_index = p[1]
        wp_data = base64decode(p[2])
        extrinsics = p[3]

        # Extract segment-padded preimage data from extrinsics if present
        # jamt sends the segment-padded corevm data here, which we need to store
        # for servicePreimage to return the exact data jamt expects
        #
        # TESTNET WORKAROUND: jamt's internal hash calculation differs from our Blake2b hash
        # of the padded data. We can't replicate jamt's exact algorithm (closed source).
        # Instead, we store ANY extrinsic data matching the expected SIZE under jamt's
        # expected hash. jamt will later verify when fetching via servicePreimage.
        println("Checking extrinsics: $(typeof(extrinsics)), length=$(length(extrinsics)), pending_hash=$(chain.pending_corevm_hash !== nothing ? bytes2hex(chain.pending_corevm_hash[1:8]) : "nothing")")
        if extrinsics isa Vector && length(extrinsics) > 0 && chain.pending_corevm_hash !== nothing
            expected_size = chain.pending_corevm_size
            expected_hash = chain.pending_corevm_hash
            println("Looking for segment-padded data in extrinsics (expected size=$(expected_size))...")

            for (i, ext) in enumerate(extrinsics)
                if ext isa String
                    # Direct blob
                    ext_data = base64decode(ext)
                    ext_hash = blake2b_256(ext_data)
                    println("  extrinsics[$i]: $(length(ext_data)) bytes, hash=$(bytes2hex(ext_hash[1:8]))...")
                    # TESTNET: Match by size OR hash (size match is sufficient as workaround)
                    if length(ext_data) == expected_size || ext_hash == expected_hash
                        chain.pending_segment_data = ext_data
                        println("  Found segment data in extrinsics[$i]: $(length(ext_data)) bytes (size match=$(length(ext_data) == expected_size), hash match=$(ext_hash == expected_hash))")
                        break
                    end
                elseif ext isa Vector
                    # Array of blobs (nested structure)
                    for (j, sub) in enumerate(ext)
                        if sub isa String
                            sub_data = base64decode(sub)
                            sub_hash = blake2b_256(sub_data)
                            println("  extrinsics[$i][$j]: $(length(sub_data)) bytes, hash=$(bytes2hex(sub_hash[1:8]))...")
                            # TESTNET: Match by size OR hash
                            if length(sub_data) == expected_size || sub_hash == expected_hash
                                chain.pending_segment_data = sub_data
                                println("  Found segment data in extrinsics[$i][$j]: $(length(sub_data)) bytes (size match=$(length(sub_data) == expected_size), hash match=$(sub_hash == expected_hash))")
                                break
                            end
                        end
                    end
                    if chain.pending_segment_data !== nothing
                        break
                    end
                end
            end
        end

        # If we captured segment data from extrinsics, store it in preimages under the expected hash
        if chain.pending_segment_data !== nothing && chain.pending_corevm_hash !== nothing
            segment_data = chain.pending_segment_data
            expected_hash = chain.pending_corevm_hash
            # Store in global preimages
            chain.preimages[expected_hash] = segment_data
            # Also store in Bootstrap service (service 0) preimages for servicePreimage lookup
            if haskey(chain.services, UInt32(0))
                chain.services[UInt32(0)].preimages[expected_hash] = segment_data
            end
            println("Stored segment-padded corevm data ($(length(segment_data)) bytes) under hash=$(bytes2hex(expected_hash[1:8]))...")
            # Clear pending data
            chain.pending_segment_data = nothing
        end

        # Store work package
        wp_hash = blake2b_256(wp_data)
        push!(chain.pending_work_packages, Dict(
            "hash" => wp_hash,
            "core" => core_index,
            "data" => wp_data,
            "extrinsics" => extrinsics,
            "submitted_at" => chain.current_slot
        ))

        println("Received work package for core $(core_index), hash=$(bytes2hex(wp_hash[1:8]))..., size=$(length(wp_data))")

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

        # Also store under pending_corevm_hash if size matches or is close
        # This handles jamt's data which may need padding to match expected size
        if chain.pending_corevm_hash !== nothing
            expected_size = chain.pending_corevm_size
            if preimage_len == expected_size
                if preimage_hash == chain.pending_corevm_hash
                    println("  Preimage hash matches pending_corevm_hash - verified!")
                else
                    # Store under jamt's expected hash even if computed hash differs
                    chain.preimages[chain.pending_corevm_hash] = preimage
                    if haskey(chain.services, service_id)
                        chain.services[service_id].preimages[chain.pending_corevm_hash] = preimage
                    end
                    println("  Also stored under pending_corevm_hash=$(bytes2hex(chain.pending_corevm_hash[1:8]))...")
                end
            elseif preimage_len < expected_size && expected_size - preimage_len <= 16
                # Raw data is smaller than expected - pad with zeros and check hash
                padded = vcat(preimage, zeros(UInt8, expected_size - preimage_len))
                padded_hash = blake2b_256(padded)
                if padded_hash == chain.pending_corevm_hash
                    # Padded data matches expected hash - store it
                    chain.preimages[chain.pending_corevm_hash] = padded
                    if haskey(chain.services, service_id)
                        chain.services[service_id].preimages[chain.pending_corevm_hash] = padded
                    end
                    println("  Padded $(preimage_len) -> $(expected_size) bytes, hash verified and stored!")
                else
                    # Zero padding didn't work - store raw data under expected hash anyway
                    # jamt may be using a different padding scheme, we'll let it verify
                    chain.preimages[chain.pending_corevm_hash] = preimage
                    if haskey(chain.services, service_id)
                        chain.services[service_id].preimages[chain.pending_corevm_hash] = preimage
                    end
                    println("  Zero pad hash mismatch, storing raw under pending_corevm_hash anyway")
                    println("    Expected: $(bytes2hex(chain.pending_corevm_hash[1:8]))...")
                    println("    Got:      $(bytes2hex(padded_hash[1:8]))...")
                end
            end
        end

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

    # romio-specific: synchronous refine for testing
    # not part of jip-2 - use submitWorkPackage for standard flow
    # params: [service_id, payload_hex, gas_limit]
    RPC.register_handler!(server, "romio_refine", (s, p) -> begin
        if length(p) < 3
            throw(RPC.RPCError(RPC.ERR_INVALID_PARAMS, "refine requires: service_id, payload_hex, gas_limit", nothing))
        end

        service_id = UInt32(p[1])
        payload_hex = string(p[2])
        gas_limit = Int64(p[3])

        # Decode payload
        payload = hex2bytes(replace(payload_hex, "0x" => ""))

        println("refine: service=$(service_id), payload=$(length(payload)) bytes, gas=$(gas_limit)")

        # Get service
        if !haskey(chain.services, service_id)
            return Dict{String, Any}(
                "success" => false,
                "error" => "service not found: $(service_id)",
                "output" => "",
                "gas_used" => 0
            )
        end

        service = chain.services[service_id]

        # Check if service has code
        if isempty(service.code)
            return Dict{String, Any}(
                "success" => false,
                "error" => "service has no code blob",
                "output" => "",
                "gas_used" => 0
            )
        end

        payload_hash = blake2b_256(payload)
        println("  payload hash: $(bytes2hex(payload_hash[1:8]))...")

        # Store payload for host_fetch
        service.metadata["payload"] = payload
        service.preimages[payload_hash] = payload
        chain.preimages[payload_hash] = payload

        # Execute PVM with payload
        result = execute_refine!(chain, service, gas_limit)

        # Clear payload after execution
        delete!(service.metadata, "payload")

        return Dict{String, Any}(
            "success" => result.success,
            "payload_hash" => bytes2hex(payload_hash),
            "payload_size" => length(payload),
            "gas_limit" => gas_limit,
            "output" => result.output,
            "output_hex" => result.output_hex,
            "gas_used" => result.gas_used,
            "steps" => result.steps,
            "exports" => [bytes2hex(e) for e in result.exports],
            "error" => result.error
        )
    end)

    # blc_eval moved to separate blc service rpc (port 19801)
    # see src/services/blc_rpc.jl
end

# Result type for refine execution
struct RefineResult
    success::Bool
    output::String
    output_hex::String
    gas_used::Int64
    steps::Int64
    exports::Vector{Vector{UInt8}}
    error::String
end

# Execute PVM for refine (synchronous execution with payload)
function execute_refine!(chain::LiveChainState, service::CoreVMService, gas_limit::Int64)::RefineResult
    console_output = IOBuffer()
    export_data = Vector{Vector{UInt8}}()
    steps = 0
    gas_used = 0
    error_msg = ""

    if !PVM_ENABLED
        return RefineResult(false, "", "", 0, 0, [], "PVM execution disabled")
    end

    pvm_blob = service.code
    if isempty(pvm_blob)
        return RefineResult(false, "", "", 0, 0, [], "no code blob")
    end

    println("  executing PVM ($(length(pvm_blob)) bytes, gas=$(gas_limit))...")

    try
        # Parse PVM blob
        prog = PolkaVMBlob.parse_polkavm_blob(pvm_blob)
        opcode_mask = PolkaVMBlob.get_opcode_mask(prog)

        # Find entry point - prefer jb_refine for JAM services
        entry_pc = UInt32(0)
        entry_name = "default"
        for exp in prog.exports
            if exp.name == "jb_refine"
                entry_pc = exp.pc
                entry_name = "jb_refine"
                break
            elseif exp.name == "corevm_main" && entry_name == "default"
                entry_pc = exp.pc
                entry_name = "corevm_main"
            end
        end
        println("  entry: $(entry_name) at pc=$(entry_pc)")

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

        # Expand RW data
        rw_data_full = zeros(UInt8, prog.rw_data_size)
        copyto!(rw_data_full, 1, prog.rw_data, 1, length(prog.rw_data))

        # Initialize memory
        memory = PVM.Memory()
        PVM.init_memory_regions!(memory,
            RO_BASE, UInt32(length(prog.ro_data)), prog.ro_data,
            RW_BASE, UInt32(length(rw_data_full)), rw_data_full,
            STACK_LOW, STACK_HIGH,
            HEAP_BASE, STACK_LOW)

        # Initialize registers
        regs = zeros(UInt64, 13)
        regs[1] = UInt64(0xFFFF0000)
        regs[2] = UInt64(STACK_HIGH)

        # Create PVM state
        state = PVM.PVMState(
            entry_pc, PVM.CONTINUE, Int64(gas_limit),
            prog.code, opcode_mask, skip_distances, regs, memory, prog.jump_table,
            UInt32(0), Vector{Vector{UInt8}}(), Dict{UInt32, PVM.GuestPVM}())

        max_steps = min(gas_limit, 100_000_000)  # Cap steps for refine

        while state.status == PVM.CONTINUE && state.gas > 0 && steps < max_steps
            PVM.step!(state)
            steps += 1

            if state.status == PVM.HOST
                call_id = Int(state.host_call_id)
                handled = false

                # host_fetch - get payload
                if call_id == 1
                    buf_ptr = UInt32(state.registers[8])
                    offset = Int(state.registers[9])
                    buf_len = Int(state.registers[10])
                    discriminator = Int(state.registers[11])

                    if discriminator == 13  # FETCH_PAYLOAD
                        payload = get(service.metadata, "payload", UInt8[])
                        if !isempty(payload) && buf_len > 0
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
                        handled = true
                    else
                        # Console output (corevm style)
                        stream = state.registers[8]
                        ptr = UInt32(state.registers[9])
                        len = UInt32(state.registers[10])
                        if len > 0 && len < 10000
                            data = PVM.read_bytes_bulk(state, UInt64(ptr), Int(len))
                            write(console_output, data)
                        end
                        state.registers[8] = UInt64(0)
                        handled = true
                    end

                    if handled
                        skip = PVM.skip_distance(state.opcode_mask, Int(state.pc) + 1)
                        state.pc = state.pc + 1 + skip
                        state.status = PVM.CONTINUE
                    end

                # host_write - store to service storage
                elseif call_id == 4
                    key_ptr = UInt32(state.registers[8])
                    key_len = Int(state.registers[9])
                    val_ptr = UInt32(state.registers[10])
                    val_len = Int(state.registers[11])

                    if key_len > 0 && key_len < 256 && val_len < 4096
                        key = PVM.read_bytes_bulk(state, UInt64(key_ptr), key_len)
                        val = PVM.read_bytes_bulk(state, UInt64(val_ptr), val_len)
                        service.storage[key] = val
                        state.registers[8] = UInt64(0)
                    else
                        state.registers[8] = UInt64(-1)
                    end
                    skip = PVM.skip_distance(state.opcode_mask, Int(state.pc) + 1)
                    state.pc = state.pc + 1 + skip
                    state.status = PVM.CONTINUE
                    handled = true

                # host_export - export result
                elseif call_id == 7
                    ptr = UInt32(state.registers[8])
                    len = Int(state.registers[9])

                    if len > 0 && len < 65536
                        data = PVM.read_bytes_bulk(state, UInt64(ptr), len)
                        push!(export_data, data)
                        println("  [export] $(length(data)) bytes")
                        state.registers[8] = UInt64(0)
                    else
                        state.registers[8] = UInt64(-1)
                    end
                    skip = PVM.skip_distance(state.opcode_mask, Int(state.pc) + 1)
                    state.pc = state.pc + 1 + skip
                    state.status = PVM.CONTINUE
                    handled = true

                # corevm_gas_ext
                elseif call_id == 0
                    state.registers[8] = UInt64(state.gas)
                    skip = PVM.skip_distance(state.opcode_mask, Int(state.pc) + 1)
                    state.pc = state.pc + 1 + skip
                    state.status = PVM.CONTINUE
                    handled = true
                end

                if !handled
                    println("  unhandled host call: $(call_id)")
                    break
                end
            end
        end

        gas_used = gas_limit - state.gas
        output_str = String(take!(console_output))
        output_hex_str = bytes2hex(Vector{UInt8}(output_str))

        println("  completed: $(steps) steps, gas_used=$(gas_used), output=$(length(output_str)) bytes")

        return RefineResult(true, output_str, output_hex_str, gas_used, steps, export_data, "")

    catch e
        error_msg = string(e)
        println("  PVM error: $(error_msg)")
        return RefineResult(false, String(take!(console_output)), "", 0, steps, export_data, error_msg)
    end
end

# PVM execution configuration
const PVM_ENABLED = true  # Set to false to skip PVM execution
const PVM_MAX_FRAMES = 10  # Number of video frames to capture per execution
const PVM_MAX_STEPS = 4_000_000_000  # Max instructions per execution (~27s at 145M/s)

# Execute PVM code and capture output frames as preimages
# Returns a vector of frame hashes (each frame is stored as preimage in chain)
function execute_pvm_service!(chain::LiveChainState, service::CoreVMService, pvm_blob::Vector{UInt8})::Vector{Vector{UInt8}}
    frame_hashes = Vector{Vector{UInt8}}()

    if !PVM_ENABLED
        println("    PVM execution disabled, skipping...")
        return frame_hashes
    end

    println("    Executing PVM code ($(length(pvm_blob)) bytes)...")

    try
        # Parse the PVM blob
        prog = PolkaVMBlob.parse_polkavm_blob(pvm_blob)
        opcode_mask = PolkaVMBlob.get_opcode_mask(prog)

        println("    PVM parsed: code=$(length(prog.code))B, ro=$(length(prog.ro_data))B, rw=$(prog.rw_data_size)B")

        # Find entry point - prefer jb_refine for JAM services, else corevm_main, else 0
        entry_pc = UInt32(0)
        entry_name = "default"
        for exp in prog.exports
            if exp.name == "jb_refine"
                entry_pc = exp.pc
                entry_name = "jb_refine"
                break
            elseif exp.name == "corevm_main" && entry_name == "default"
                entry_pc = exp.pc
                entry_name = "corevm_main"
            end
        end
        println("    Entry point: $(entry_name) at pc=$(entry_pc)")

        # Memory layout constants
        VM_MAX_PAGE_SIZE = UInt32(0x10000)
        align_64k(x) = (x + VM_MAX_PAGE_SIZE - 1) & ~(VM_MAX_PAGE_SIZE - 1)

        ro_data_address_space = align_64k(prog.ro_data_size)
        RO_BASE = UInt32(0x10000)
        RW_BASE = UInt32(RO_BASE + ro_data_address_space + VM_MAX_PAGE_SIZE)
        STACK_HIGH = UInt32(0xFFFF0000 - VM_MAX_PAGE_SIZE)
        STACK_LOW = UInt32(STACK_HIGH - prog.stack_size)
        HEAP_BASE = UInt32(RW_BASE + prog.rw_data_size)

        # CoreVM extension for host calls
        corevm = CoreVMExtension.CoreVMHostCalls(width=320, height=200)
        CoreVMExtension.set_heap_base!(corevm, HEAP_BASE)

        # Precompute skip distances
        skip_distances = PVM.precompute_skip_distances(opcode_mask)

        # Expand RW data to full declared size
        rw_data_full = zeros(UInt8, prog.rw_data_size)
        copyto!(rw_data_full, 1, prog.rw_data, 1, length(prog.rw_data))

        # Initialize memory
        memory = PVM.Memory()
        PVM.init_memory_regions!(memory,
            RO_BASE, UInt32(length(prog.ro_data)), prog.ro_data,
            RW_BASE, UInt32(length(rw_data_full)), rw_data_full,
            STACK_LOW, STACK_HIGH,
            HEAP_BASE, STACK_LOW)

        # Initialize registers
        regs = zeros(UInt64, 13)
        regs[1] = UInt64(0xFFFF0000)
        regs[2] = UInt64(STACK_HIGH)

        # Create PVM state with correct entry point
        state = PVM.PVMState(
            entry_pc, PVM.CONTINUE, Int64(100_000_000_000),
            prog.code, opcode_mask, skip_distances, regs, memory, prog.jump_table,
            UInt32(0), Vector{Vector{UInt8}}(), Dict{UInt32, PVM.GuestPVM}())

        # Pre-allocate frame buffer
        WIDTH = 320
        HEIGHT = 200
        rgb_frame = Vector{UInt8}(undef, WIDTH * HEIGHT * 3)
        frame_count = Ref(0)

        # Framebuffer callback - store frames as preimages
        fb_callback = function(pvm_state, fb_addr, fb_size)
            if fb_size >= 64769 && frame_count[] < PVM_MAX_FRAMES
                # Decode palette + indexed pixels to RGB
                for i in 0:WIDTH*HEIGHT-1
                    pixel_addr = fb_addr + 769 + i
                    idx = PVM.read_u8(pvm_state, UInt64(pixel_addr))
                    pvm_state.status = PVM.CONTINUE
                    base = Int(idx) * 3
                    if base + 2 < 768
                        rgb_frame[i*3 + 1] = PVM.read_u8(pvm_state, UInt64(fb_addr + 1 + base))
                        rgb_frame[i*3 + 2] = PVM.read_u8(pvm_state, UInt64(fb_addr + 2 + base))
                        rgb_frame[i*3 + 3] = PVM.read_u8(pvm_state, UInt64(fb_addr + 3 + base))
                        pvm_state.status = PVM.CONTINUE
                    end
                end

                frame_count[] += 1

                # Hash the frame and store as preimage
                frame_hash = blake2b_256(rgb_frame)
                push!(frame_hashes, frame_hash)

                # Store frame in service preimages
                service.preimages[frame_hash] = copy(rgb_frame)

                # Also add to exports list
                push!(service.exports, frame_hash)

                println("    Frame $(frame_count[]): hash=$(bytes2hex(frame_hash)) ($(length(rgb_frame)) bytes)")

                # Save first frame to /tmp for verification
                if frame_count[] == 1
                    open("/tmp/doom_frame_1.rgb", "w") do f
                        write(f, rgb_frame)
                    end
                    println("    Saved frame 1 to /tmp/doom_frame_1.rgb (320x200 RGB)")
                end
            end
        end

        CoreVMExtension.set_framebuffer_callback!(corevm, fb_callback)

        # Run PVM until max frames or max steps
        step_count = 0
        start_time = time()

        while state.status == PVM.CONTINUE && state.gas > 0 && step_count < PVM_MAX_STEPS && frame_count[] < PVM_MAX_FRAMES
            PVM.step!(state)
            step_count += 1

            if state.status == PVM.HOST
                call_id = Int(state.host_call_id)
                handled = false

                # JAM host functions (for JAM services like blc-vm)
                if call_id == 1  # host_fetch - get work item payload
                    # a0=buf, a1=offset, a2=len, a3=discriminator, a4=w11, a5=w12
                    buf_ptr = UInt32(state.registers[8])
                    offset = Int(state.registers[9])
                    buf_len = Int(state.registers[10])
                    discriminator = Int(state.registers[11])

                    if discriminator == 13  # FETCH_PAYLOAD
                        # Return work item payload (empty for now during service creation)
                        # In real usage, this would come from the work package
                        payload = get(service.metadata, "payload", UInt8[])
                        if !isempty(payload) && buf_len > 0
                            copy_len = min(length(payload) - offset, buf_len)
                            if copy_len > 0
                                for i in 1:copy_len
                                    PVM.write_u8(state, UInt64(buf_ptr + i - 1), payload[offset + i])
                                end
                            end
                            state.registers[8] = UInt64(copy_len)
                        else
                            state.registers[8] = UInt64(0)  # no payload
                        end
                    else
                        state.registers[8] = UInt64(-1)  # HOST_NONE
                    end
                    skip = PVM.skip_distance(state.opcode_mask, Int(state.pc) + 1)
                    state.pc = state.pc + 1 + skip
                    state.status = PVM.CONTINUE
                    handled = true

                elseif call_id == 4  # host_write - store to service storage
                    key_ptr = UInt32(state.registers[8])
                    key_len = Int(state.registers[9])
                    val_ptr = UInt32(state.registers[10])
                    val_len = Int(state.registers[11])

                    if key_len > 0 && key_len < 256 && val_len < 4096
                        key = PVM.read_bytes_bulk(state, UInt64(key_ptr), key_len)
                        val = PVM.read_bytes_bulk(state, UInt64(val_ptr), val_len)
                        service.storage[key] = val
                        println("    [storage] write: $(String(copy(key))) = $(bytes2hex(val))")
                        state.registers[8] = UInt64(0)  # HOST_OK
                    else
                        state.registers[8] = UInt64(-1)  # HOST_NONE
                    end
                    skip = PVM.skip_distance(state.opcode_mask, Int(state.pc) + 1)
                    state.pc = state.pc + 1 + skip
                    state.status = PVM.CONTINUE
                    handled = true

                elseif call_id == 7  # host_export - export result
                    ptr = UInt32(state.registers[8])
                    len = Int(state.registers[9])

                    if len > 0 && len < 4096
                        data = PVM.read_bytes_bulk(state, UInt64(ptr), len)
                        push!(service.exports, data)
                        println("    [export] $(bytes2hex(data))")
                        state.registers[8] = UInt64(0)  # HOST_OK
                    else
                        state.registers[8] = UInt64(-1)
                    end
                    skip = PVM.skip_distance(state.opcode_mask, Int(state.pc) + 1)
                    state.pc = state.pc + 1 + skip
                    state.status = PVM.CONTINUE
                    handled = true

                # CoreVM host calls (corevm_gas_ext, corevm_yield_console_data_ext)
                elseif call_id == 0  # corevm_gas_ext
                    state.registers[8] = UInt64(state.gas)
                    skip = PVM.skip_distance(state.opcode_mask, Int(state.pc) + 1)
                    state.pc = state.pc + 1 + skip
                    state.status = PVM.CONTINUE
                    handled = true

                # Note: call_id == 1 is shared between host_fetch and corevm_yield_console_data
                # Disambiguate by checking if we have a service with payload vs corevm_main entry
                end

                if !handled
                    # Check if this might be console output (corevm apps)
                    if call_id == 1 && !haskey(service.metadata, "payload")
                        stream = state.registers[8]
                        ptr = UInt32(state.registers[9])
                        len = UInt32(state.registers[10])
                        if len > 0 && len < 10000
                            data = PVM.read_bytes_bulk(state, UInt64(ptr), Int(len))
                            print("    [console] ", String(copy(data)))
                        end
                        skip = PVM.skip_distance(state.opcode_mask, Int(state.pc) + 1)
                        state.pc = state.pc + 1 + skip
                        state.status = PVM.CONTINUE
                        handled = true
                    end
                end

                if !handled
                    # Try CoreVM extension (for Doom-style apps)
                    handled = CoreVMExtension.handle_corevm_host_call!(state, corevm)
                    if handled
                        skip = PVM.skip_distance(state.opcode_mask, Int(state.pc) + 1)
                        state.pc = state.pc + 1 + skip
                    else
                        println("    Unhandled host call: $(state.host_call_id)")
                        break
                    end
                end
            end
        end

        elapsed = time() - start_time
        println("    PVM executed $(step_count) steps in $(round(elapsed, digits=2))s, captured $(frame_count[]) frames")

    catch e
        println("    PVM execution error: $e")
        # Don't rethrow - let service creation continue without execution
    end

    return frame_hashes
end

# Process Bootstrap work package - creates a new service
function process_bootstrap_work_package!(chain::LiveChainState, wp::Dict)::Union{Dict, Nothing}
    # Extract work package data
    wp_data = wp["data"]
    wp_hash = wp["hash"]

    # The work package contains a JAM work package header, not the raw corevm.
    # jamt sends the corevm data via serviceRequest preimages before submitting the work package.
    # We need to find the largest preimage which contains the actual corevm.

    # First, try to find PVM blob directly in the work package (for raw uploads)
    pvm_start = findfirst(b"PVM\0", wp_data)
    actual_corevm_data = nothing
    corevm_hash = nothing

    if pvm_start !== nothing
        actual_corevm_data = wp_data
        corevm_hash = blake2b_256(wp_data)
        println("  Found PVM magic in work package at offset $(pvm_start[1])")
    else
        # Look for corevm using the pending_corevm_size from subscribeServiceRequest
        # This ensures we use the specific preimage that was requested, not just the largest one
        # We use size-based matching because jamt's hash includes padding we can't reproduce
        # Save target_size before potentially clearing it, so fallback can use it
        target_size = chain.pending_corevm_size
        if target_size !== nothing
            println("  Looking for corevm with size ~$(target_size) bytes...")

            # Search for preimage with matching size (within 8 bytes tolerance for padding)
            # Check Bootstrap service preimages first
            if haskey(chain.services, UInt32(0))
                for (hash, preimage_data) in chain.services[UInt32(0)].preimages
                    data_size = length(preimage_data)
                    # Allow for small size differences due to padding (within 16 bytes)
                    if abs(data_size - target_size) <= 16 && findfirst(b"PVM\0", preimage_data) !== nothing
                        actual_corevm_data = preimage_data
                        corevm_hash = hash
                        println("  Found matching corevm by size in Bootstrap preimages: $(data_size) bytes, hash=$(bytes2hex(corevm_hash[1:8]))...")
                        break
                    end
                end
            end

            # Check chain.preimages if not found
            if actual_corevm_data === nothing
                for (hash, preimage_data) in chain.preimages
                    data_size = length(preimage_data)
                    if abs(data_size - target_size) <= 16 && findfirst(b"PVM\0", preimage_data) !== nothing
                        actual_corevm_data = preimage_data
                        corevm_hash = hash
                        println("  Found matching corevm by size in chain.preimages: $(data_size) bytes, hash=$(bytes2hex(corevm_hash[1:8]))...")
                        break
                    end
                end
            end

            if actual_corevm_data === nothing
                println("  No corevm found matching size $(target_size)")
            end

            # Clear the pending size and hash after use
            chain.pending_corevm_size = nothing
            chain.pending_corevm_hash = nothing
        end

        # Fallback: search all preimages if specific hash wasn't found
        # If we have a target_size, prefer size-matching candidates; otherwise select largest
        if actual_corevm_data === nothing
            if target_size !== nothing
                println("  Falling back to search all preimages for size ~$(target_size)...")
            else
                println("  Falling back to search all preimages...")
            end

            candidates = Vector{Tuple{Vector{UInt8}, Vector{UInt8}}}()  # (data, hash)

            # Check submitted preimages in chain
            for (svc_id, preimage_data) in chain.submitted_preimages
                if findfirst(b"PVM\0", preimage_data) !== nothing
                    push!(candidates, (preimage_data, blake2b_256(preimage_data)))
                    println("  Candidate in submitted_preimages: $(length(preimage_data)) bytes")
                end
            end

            # Check chain.preimages
            for (hash, preimage_data) in chain.preimages
                if findfirst(b"PVM\0", preimage_data) !== nothing
                    push!(candidates, (preimage_data, hash))
                    println("  Candidate in chain.preimages: $(length(preimage_data)) bytes")
                end
            end

            # Check Bootstrap service preimages
            if haskey(chain.services, UInt32(0))
                for (hash, preimage_data) in chain.services[UInt32(0)].preimages
                    if findfirst(b"PVM\0", preimage_data) !== nothing
                        push!(candidates, (preimage_data, hash))
                        println("  Candidate in Bootstrap preimages: $(length(preimage_data)) bytes")
                    end
                end
            end

            # Select candidate: prefer size match if target_size known, otherwise use largest
            if !isempty(candidates)
                selected_idx = nothing

                # Try to find size-matching candidate first
                if target_size !== nothing
                    for (idx, (data, _)) in enumerate(candidates)
                        if abs(length(data) - target_size) <= 16
                            selected_idx = idx
                            println("  Found size-matching candidate: $(length(data)) bytes (target: $(target_size))")
                            break
                        end
                    end
                end

                # Fall back to largest if no size match
                if selected_idx === nothing
                    selected_idx = argmax(length(c[1]) for c in candidates)
                    println("  No size match, using largest candidate")
                end

                actual_corevm_data, corevm_hash = candidates[selected_idx]
                println("  Selected corevm: $(length(actual_corevm_data)) bytes, hash=$(bytes2hex(corevm_hash[1:8]))...")
            end
        end

        if actual_corevm_data === nothing
            println("  No corevm preimage found, using work package data")
            actual_corevm_data = wp_data
            corevm_hash = blake2b_256(wp_data)
        end
    end

    # If we still don't have PVM magic, skip execution
    pvm_start_final = findfirst(b"PVM\0", actual_corevm_data)
    if pvm_start_final === nothing
        println("  No PVM magic found in any data source")
        if length(wp_data) < 100
            println("  Work package too small, skipping")
            return nothing
        end
    end

    # Create new service with next available ID
    service_id = chain.next_service_id
    chain.next_service_id += 1

    # Extract the PVM blob (everything from PVM magic onwards) for execution
    pvm_blob = if pvm_start_final !== nothing
        actual_corevm_data[pvm_start_final[1]:end]
    else
        actual_corevm_data  # Use raw data
    end

    # Check if the data has polkavm corevm header
    # Three formats exist:
    # - 'P' format (0x50) - polkajam corevm format with SCALE length-prefixed fields (preferred by jamt)
    # - '<' format (0x3c 0x00) - doom.corevm style with length-prefixed fields
    # - '(' format (0x28) - old SCALE-encoded fields format (deprecated)
    # If not recognized, wrap the raw PVM blob in a polkavm corevm format for jamt compatibility
    has_corevm_header = length(actual_corevm_data) >= 2 && (
        actual_corevm_data[1] == 0x50 ||  # 'P' format (polkajam)
        (actual_corevm_data[1] == 0x3c && actual_corevm_data[2] == 0x00) ||  # '<' format
        actual_corevm_data[1] == 0x28  # '(' format (SCALE-style, deprecated)
    )
    corevm_for_preimage = if has_corevm_header
        actual_corevm_data  # Already has polkavm corevm header
    else
        # Wrap raw PVM blob in polkavm corevm format
        wrapped = wrap_pvm_in_corevm(pvm_blob, service_id)
        println("  Wrapped raw PVM blob in polkavm corevm format: $(length(wrapped)) bytes")
        wrapped
    end

    # jamt expects the service code to be the segment-padded corevm data
    # It sends serviceRequest with the expected hash and size, then queries servicePreimage with that hash
    # We need to pad our corevm data to match the expected size and use the hash jamt expects
    #
    # IMPORTANT: Use pending_corevm_by_size instead of pending_corevm_hash because the latter
    # gets cleared during work package extraction before we reach this code
    corevm_size = length(corevm_for_preimage)

    # Look up by sizes that could match (exact, or padded +8 for segment alignment)
    expected_hash = nothing
    expected_size = nothing
    for check_size in [corevm_size, corevm_size + 8, corevm_size + 1, corevm_size + 2, corevm_size + 4]
        if haskey(chain.pending_corevm_by_size, check_size)
            expected_hash, expected_size = chain.pending_corevm_by_size[check_size]
            println("  Found pending_corevm_by_size[$check_size]: hash=$(bytes2hex(expected_hash[1:8]))..., size=$(expected_size)")
            break
        end
    end

    # Compute the MainBlock hash (this is what goes into serviceData)
    # The preimage store uses MainBlock encoding for hash computation,
    # but stores the RAW corevm data (not MainBlock-encoded)
    main_block, _, mainblock_hash = encode_corevm_file(corevm_for_preimage)
    code_hash = mainblock_hash

    # Store RAW corevm data (not MainBlock-encoded)
    # This matches what polkajam does for Bootstrap service
    preimage_data = corevm_for_preimage
    println("  Code hash (MainBlock): $(bytes2hex(code_hash[1:8]))..., storing raw corevm: $(length(preimage_data)) bytes")

    # Store preimage under the actual code_hash
    # (We now send the full 32-byte hash in serviceData, so jamt will query with the correct hash)
    preimages_dict = Dict{Vector{UInt8}, Vector{UInt8}}(
        code_hash => preimage_data
    )

    # Create the service - store PVM blob for execution but corevm as preimage
    service = CoreVMService(
        service_id,
        pvm_blob,  # Code for execution (PVM blob only)
        code_hash,  # Hash of the corevm
        Dict{Vector{UInt8}, Vector{UInt8}}(),
        preimages_dict,  # Corevm as preimage under its actual hash
        UInt64(1_000_000_000),  # Initial balance from jamt request
        Vector{UInt8}[],
        Dict{String, Any}()  # metadata
    )

    chain.services[service_id] = service

    # Store the corevm as preimage under its computed hash
    # jamt extracts a 32-byte lookup key from serviceData bytes [1:32], which is:
    # code_hash[1:31] (31 bytes) + balance_prefix (0xef)
    # This is because serviceData format is: version(1) + code_hash(31) + 0xef + balance(8) + ...
    service.preimages[code_hash] = preimage_data

    # Also store under the lookup key format jamt ACTUALLY uses
    # jamt reads bytes [1:32] from serviceData as the preimage lookup key:
    # code_hash[1:31] + 0xef (balance prefix) = 32 bytes total
    jamt_lookup_key = vcat(code_hash[1:31], UInt8[0xef])
    service.preimages[jamt_lookup_key] = preimage_data
    println("  Stored preimage under jamt lookup key: $(bytes2hex(jamt_lookup_key))")

    println("  Stored corevm preimage in service #$(service_id): hash=$(bytes2hex(code_hash[1:8]))..., size=$(length(preimage_data))")

    println("  Created new service #$(service_id) with $(length(pvm_blob)) bytes code ($(length(corevm_for_preimage)) corevm), hash=$(bytes2hex(code_hash[1:8]))...")

    # Execute PVM code and capture frames as preimages
    frame_hashes = execute_pvm_service!(chain, service, pvm_blob)

    # Store frame hashes in work result for reference
    return Dict(
        "service_id" => service_id,
        "code_hash" => code_hash,
        "frame_hashes" => frame_hashes,
        "success" => true
    )
end

# Extract target service ID from work package data
# JAM work package format: header + work items, each work item starts with service_id (u32 LE)
function extract_work_item_service_id(wp_data::Vector{UInt8}, existing_services::AbstractDict=Dict{UInt32,Any}())::Union{UInt32, Nothing}
    # Work package structure (per JAM GP):
    #   - authorization: 32 bytes (auth hash) + auth_len (varies)
    #   - context: anchor (32 bytes) + state_root (32 bytes) + beefy_root (32 bytes) + lookup_anchor + prereqs
    #   - items_len: varint
    #   - items: array of work items
    # Work item:
    #   - service_id: u32 LE  <-- this is what we want
    #   - code_hash: 32 bytes
    #   - payload_len: varint + payload
    #   - gas: u64
    #   - exports: u16

    if length(wp_data) < 70
        return nothing
    end

    # Print full hex dump for debugging
    println("  Work package hex ($(length(wp_data)) bytes total):")
    for i in 1:min(300, length(wp_data))
        print(lpad(string(wp_data[i], base=16), 2, '0'), " ")
        if i % 16 == 0
            print(" | offset $(i-15)-$(i)")
            println()
        end
    end
    if min(300, length(wp_data)) % 16 != 0
        println()
    end

    # The work item starts with:
    #   service_id: u32 LE (4 bytes)
    #   code_hash: 32 bytes
    # We search for small service_id values followed by a code_hash-like pattern
    # The hash must start with a non-zero byte (first byte of blake2 hash)

    println("  Searching for service_id followed by code_hash pattern:")
    candidates = Tuple{Int, UInt32, Int}[]  # (offset, service_id, hash_score)

    # Start searching from byte 160 onwards (skip header+context)
    for offset in 160:min(210, length(wp_data)-35)
        if offset + 36 <= length(wp_data)
            svc_id = reinterpret(UInt32, wp_data[offset:offset+3])[1]
            if svc_id >= 1 && svc_id <= 255
                hash_bytes = wp_data[offset+4:offset+35]
                non_zero = count(b -> b != 0, hash_bytes)
                unique_bytes = length(Set(hash_bytes))
                # Score based on how "hash-like" the following 32 bytes are
                if non_zero > 20 && unique_bytes > 10
                    score = non_zero + unique_bytes
                    push!(candidates, (offset, svc_id, score))
                    println("    candidate at offset $(offset): service_id=$(svc_id), hash_score=$(score)")
                end
            end
        end
    end

    if !isempty(candidates)
        # Prefer candidates that match existing services (for work items to existing services)
        # Otherwise prefer higher offset + score (for Bootstrap work packages)
        existing_matches = filter(c -> haskey(existing_services, c[2]), candidates)
        if !isempty(existing_matches)
            # Pick the existing service with highest offset (most likely to be actual work item)
            sort!(existing_matches, by = x -> x[1], rev=true)
            best = existing_matches[1]
            println("    SELECTED (matches existing service): offset $(best[1]): service_id=$(best[2])")
            return best[2]
        else
            # No existing services match - return nothing so Bootstrap handles it
            println("    No candidates match existing services - falling back to Bootstrap")
            return nothing
        end
    end

    println("  No service_id found")
    return nothing
end

# Process a work item for an existing service (not Bootstrap)
function process_service_work_item!(chain::LiveChainState, wp::Dict, service_id::UInt32)::Union{Dict, Nothing}
    if !haskey(chain.services, service_id)
        println("  Service #$(service_id) not found!")
        return nothing
    end

    service = chain.services[service_id]
    wp_data = wp["data"]
    wp_hash = wp["hash"]

    println("  Processing work item for service #$(service_id)...")

    # Extract payload from work package
    # JAM work package structure has the payload near the end after work items
    # Work item: service_id(4) + code_hash(32) + payload_len(varint) + payload + gas(8) + exports(2)
    # The inline payload_len may be 0, with actual payload at end of package with length prefix
    payload = UInt8[]

    # First, find where the work item starts (service_id for our target service)
    work_item_offset = nothing
    for offset in 160:min(210, length(wp_data)-35)
        if offset + 36 <= length(wp_data)
            svc_id = reinterpret(UInt32, wp_data[offset:offset+3])[1]
            if svc_id == service_id
                work_item_offset = offset
                break
            end
        end
    end

    if work_item_offset !== nothing
        # Found work item, now extract payload
        # offset layout: service_id(4) + code_hash(32) + payload_len(varint) + payload + gas(8) + exports(2)
        payload_len_offset = work_item_offset + 4 + 32  # after service_id and code_hash
        if payload_len_offset <= length(wp_data)
            inline_payload_len = Int(wp_data[payload_len_offset])
            println("    Work item at offset $(work_item_offset), inline_payload_len=$(inline_payload_len)")

            if inline_payload_len > 0 && inline_payload_len < 128
                # Simple varint, payload follows immediately
                payload_start = payload_len_offset + 1
                payload_end = payload_start + inline_payload_len - 1
                if payload_end <= length(wp_data)
                    payload = wp_data[payload_start:payload_end]
                    println("    Extracted inline payload: $(bytes2hex(payload))")
                end
            else
                # No inline payload - look for payload at the end of work package
                # Work item structure after payload_len:
                #   gas (8 bytes) + second_gas (8 bytes) + exports (2 bytes)
                # Then after work item comes: trailing_len (varint) + payload
                #
                # From the hex dump:
                # offset 209: 00 (payload_len = 0)
                # offset 210-217: gas1 (8 bytes)
                # offset 218-225: gas2 (8 bytes)
                # offset 226-227: exports (2 bytes)
                # offset 228: trailing_len
                # offset 229: payload bytes
                gas1_offset = payload_len_offset + 1
                gas2_offset = gas1_offset + 8
                exports_offset = gas2_offset + 8
                trailing_offset = exports_offset + 2

                println("    Looking for trailing payload at offset $(trailing_offset)...")

                if trailing_offset <= length(wp_data)
                    trailing_len = Int(wp_data[trailing_offset])
                    println("    trailing_len byte at $(trailing_offset) = $(trailing_len)")
                    if trailing_len > 0 && trailing_len < 128 && trailing_offset + trailing_len <= length(wp_data)
                        payload = wp_data[trailing_offset+1:trailing_offset+trailing_len]
                        println("    Found trailing payload (len=$(trailing_len)): $(bytes2hex(payload))")
                    end
                end

                # Fallback: check if there's a length-prefixed payload at the very end
                if isempty(payload) && length(wp_data) >= 2
                    # Look for pattern: ... XX YY 00 00 where XX is length and YY... is payload
                    for end_check in (length(wp_data)-2):-1:max(1, length(wp_data)-10)
                        potential_len = Int(wp_data[end_check])
                        if potential_len > 0 && potential_len < 64
                            # Check if this matches: len + payload + padding
                            payload_end = end_check + potential_len
                            if payload_end <= length(wp_data)
                                payload = wp_data[end_check+1:payload_end]
                                println("    Fallback trailing payload at $(end_check): $(bytes2hex(payload))")
                                break
                            end
                        end
                    end
                end
            end
        end
    end

    # Fallback: look for length-prefixed data at end of package
    if isempty(payload) && length(wp_data) > 2
        # Check if last byte(s) look like a payload with preceding length
        for check_offset in (length(wp_data)-1):-1:max(1, length(wp_data)-20)
            len_byte = Int(wp_data[check_offset])
            if len_byte > 0 && len_byte < 64 && check_offset + len_byte == length(wp_data)
                payload = wp_data[check_offset+1:length(wp_data)]
                println("    Fallback: found length-prefixed payload at offset $(check_offset): $(bytes2hex(payload))")
                break
            end
        end
    end

    println("  Payload size: $(length(payload)) bytes")

    # Store the payload in service metadata for the refine function to access
    service.metadata["payload"] = payload
    service.metadata["work_hash"] = wp_hash

    # Execute the service's refine entry point with the payload
    # The service code (blc-vm) should read the payload and interpret it
    try
        pvm_blob = service.code
        println("    Executing service #$(service_id) PVM code ($(length(pvm_blob)) bytes)...")

        # Parse PVM blob
        parsed = PolkaVMBlob.parse_polkavm_blob(pvm_blob)
        println("    PVM parsed: code=$(length(parsed.code))B, ro=$(parsed.ro_data_size)B, rw=$(parsed.rw_data_size)B")

        # Find refine entry point (or blc_eval for BLC service)
        entry_pc = nothing
        blc_set_input_pc = nothing
        blc_get_output_ptr_pc = nothing
        blc_get_output_len_pc = nothing
        is_blc_service = false

        for exp in parsed.exports
            if exp.name == "refine" || exp.name == "jb_refine"
                entry_pc = exp.pc
                println("    Entry point: $(exp.name) at pc=$(entry_pc)")
                break
            elseif exp.name == "blc_eval"
                entry_pc = exp.pc
                is_blc_service = true
                println("    Entry point: $(exp.name) at pc=$(entry_pc) (BLC service)")
            elseif exp.name == "blc_set_input"
                blc_set_input_pc = exp.pc
            elseif exp.name == "blc_get_output_ptr"
                blc_get_output_ptr_pc = exp.pc
            elseif exp.name == "blc_get_output_len"
                blc_get_output_len_pc = exp.pc
            end
        end

        if entry_pc === nothing
            # Try first export
            if !isempty(parsed.exports)
                entry_pc = parsed.exports[1].pc
                println("    Using first export at pc=$(entry_pc)")
            else
                entry_pc = 0
                println("    Entry point: default at pc=0")
            end
        end

        # Setup memory
        VM_MAX_PAGE_SIZE = UInt32(0x10000)
        align_64k(x) = (x + VM_MAX_PAGE_SIZE - 1) & ~(VM_MAX_PAGE_SIZE - 1)
        ro_data_address_space = align_64k(parsed.ro_data_size)
        RO_BASE = UInt32(0x10000)
        RW_BASE = UInt32(RO_BASE + ro_data_address_space + VM_MAX_PAGE_SIZE)
        STACK_HIGH = UInt32(0xFFFF0000 - VM_MAX_PAGE_SIZE)
        STACK_LOW = UInt32(STACK_HIGH - parsed.stack_size)
        HEAP_BASE = UInt32(RW_BASE + parsed.rw_data_size)

        rw_data_full = zeros(UInt8, max(1, parsed.rw_data_size))
        if length(parsed.rw_data) > 0
            copyto!(rw_data_full, 1, parsed.rw_data, 1, min(length(parsed.rw_data), parsed.rw_data_size))
        end

        memory = PVM.Memory()
        PVM.init_memory_regions!(memory,
            RO_BASE, UInt32(length(parsed.ro_data)), parsed.ro_data,
            RW_BASE, UInt32(length(rw_data_full)), rw_data_full,
            STACK_LOW, STACK_HIGH,
            HEAP_BASE, STACK_LOW)

        # Write payload to memory for the service to read
        # Put it at a known location (e.g., start of heap area)
        PAYLOAD_ADDR = HEAP_BASE
        if length(payload) > 0 && length(payload) < 1000
            for (i, b) in enumerate(payload)
                PVM.sparse_write!(memory.sparse, PAYLOAD_ADDR + UInt32(i-1), b)
            end
        end

        opcode_mask = PolkaVMBlob.get_opcode_mask(parsed)
        skip_distances = PVM.precompute_skip_distances(opcode_mask)

        # Setup registers - pass payload address and length in a0, a1
        regs = zeros(UInt64, 13)
        regs[1] = UInt64(0xFFFF0000)  # RA
        regs[2] = UInt64(STACK_HIGH)   # SP
        regs[8] = UInt64(PAYLOAD_ADDR)  # a0 = payload address
        regs[9] = UInt64(length(payload))  # a1 = payload length

        initial_gas = Int64(10_000_000)

        # For BLC service, we need to call blc_set_input first, then blc_eval
        if is_blc_service && blc_set_input_pc !== nothing
            println("    BLC service detected - calling blc_set_input first...")
            # First call blc_set_input(ptr, len)
            set_input_state = PVM.PVMState(
                UInt32(blc_set_input_pc), PVM.CONTINUE, initial_gas,
                parsed.code, opcode_mask, skip_distances, copy(regs), memory, parsed.jump_table,
                UInt32(0), Vector{Vector{UInt8}}(), Dict{UInt32, PVM.GuestPVM}()
            )
            # Run blc_set_input until it returns
            set_input_steps = 0
            while set_input_steps < 10000 && set_input_state.status == PVM.CONTINUE && set_input_state.gas > 0
                PVM.step!(set_input_state)
                set_input_steps += 1
                if set_input_state.status == PVM.HALT
                    println("    blc_set_input completed after $(set_input_steps) steps")
                    break
                elseif set_input_state.status == PVM.HOST
                    # Handle console output
                    call_id = Int(set_input_state.host_call_id)
                    if call_id == 1
                        ptr = UInt32(set_input_state.registers[9])
                        len = UInt32(set_input_state.registers[10])
                        if len > 0 && len < 1000
                            data = PVM.read_bytes_bulk(set_input_state, UInt64(ptr), Int(len))
                            print("    [blc_set_input] ", String(copy(data)))
                        end
                    end
                    skip = PVM.skip_distance(set_input_state.opcode_mask, Int(set_input_state.pc) + 1)
                    set_input_state.pc = set_input_state.pc + 1 + skip
                    set_input_state.status = PVM.CONTINUE
                end
            end
            # Use the modified memory state for blc_eval
            memory = set_input_state.memory
        end

        state = PVM.PVMState(
            UInt32(entry_pc), PVM.CONTINUE, initial_gas,
            parsed.code, opcode_mask, skip_distances, regs, memory, parsed.jump_table,
            UInt32(0), Vector{Vector{UInt8}}(), Dict{UInt32, PVM.GuestPVM}()
        )

        # Execute with host call handling
        max_steps = 100_000
        step_count = 0
        output_data = UInt8[]

        while step_count < max_steps && state.status == PVM.CONTINUE && state.gas > 0
            PVM.step!(state)
            step_count += 1

            if state.status == PVM.HALT
                println("    HALT after $(step_count) steps")
                break
            elseif state.status == PVM.HOST
                call_id = Int(state.host_call_id)

                # JAM host_fetch (call_id=1, discriminator=13 for FETCH_PAYLOAD)
                if call_id == 1
                    buf_ptr = UInt32(state.registers[8])
                    offset = Int(state.registers[9])
                    buf_len = Int(state.registers[10])
                    discriminator = Int(state.registers[11])

                    if discriminator == 13  # FETCH_PAYLOAD
                        # Return work item payload
                        # offset is 0-indexed from C, so add 1 for Julia indexing
                        julia_start = offset + 1
                        copy_len = min(length(payload) - offset, buf_len)
                        if copy_len > 0 && julia_start <= length(payload)
                            for i in 1:copy_len
                                if julia_start + i - 1 <= length(payload)
                                    PVM.sparse_write!(state.memory.sparse, buf_ptr + UInt32(i-1), payload[julia_start + i - 1])
                                end
                            end
                        end
                        state.registers[8] = UInt64(copy_len >= 0 ? copy_len : 0xFFFFFFFFFFFFFFFF)
                    else
                        # Console output (fallback for corevm apps)
                        ptr = UInt32(state.registers[9])
                        len = UInt32(state.registers[10])
                        if len > 0 && len < 1000
                            data = PVM.read_bytes_bulk(state, UInt64(ptr), Int(len))
                            print("    [output] ", String(copy(data)))
                        end
                    end
                    skip = PVM.skip_distance(state.opcode_mask, Int(state.pc) + 1)
                    state.pc = state.pc + 1 + skip
                    state.status = PVM.CONTINUE

                # JAM host_export (call_id=7)
                elseif call_id == 7
                    ptr = UInt32(state.registers[8])
                    len = Int(state.registers[9])
                    if len > 0 && len < 10000
                        output_data = PVM.read_bytes_bulk(state, UInt64(ptr), len)
                        println("    [export] $(bytes2hex(output_data))")
                    end
                    skip = PVM.skip_distance(state.opcode_mask, Int(state.pc) + 1)
                    state.pc = state.pc + 1 + skip
                    state.status = PVM.CONTINUE

                else
                    # Unknown host call - skip
                    skip = PVM.skip_distance(state.opcode_mask, Int(state.pc) + 1)
                    state.pc = state.pc + 1 + skip
                    state.status = PVM.CONTINUE
                end
            elseif state.status == PVM.PANIC
                println("    PANIC after $(step_count) steps")
                break
            elseif state.status == PVM.OOG
                println("    OUT OF GAS after $(step_count) steps")
                break
            end
        end

        println("    PVM executed $(step_count) steps, output=$(length(output_data)) bytes")

        # For BLC services, read output from blc_get_output_ptr/len if no export was called
        if is_blc_service && isempty(output_data) && blc_get_output_ptr_pc !== nothing && blc_get_output_len_pc !== nothing
            println("    Reading BLC output via blc_get_output_ptr/len...")

            # Call blc_get_output_len to get length
            len_state = PVM.PVMState(
                UInt32(blc_get_output_len_pc), PVM.CONTINUE, Int64(1_000_000),
                parsed.code, opcode_mask, skip_distances, zeros(UInt64, 13), state.memory, parsed.jump_table,
                UInt32(0), Vector{Vector{UInt8}}(), Dict{UInt32, PVM.GuestPVM}()
            )
            len_state.registers[1] = UInt64(0xFFFF0000)
            len_state.registers[2] = UInt64(STACK_HIGH)
            len_steps = 0
            while len_steps < 1000 && len_state.status == PVM.CONTINUE && len_state.gas > 0
                PVM.step!(len_state)
                len_steps += 1
                if len_state.status == PVM.HALT
                    break
                elseif len_state.status == PVM.HOST
                    skip = PVM.skip_distance(len_state.opcode_mask, Int(len_state.pc) + 1)
                    len_state.pc = len_state.pc + 1 + skip
                    len_state.status = PVM.CONTINUE
                end
            end
            output_len = Int(len_state.registers[8])

            # Call blc_get_output_ptr to get pointer
            ptr_state = PVM.PVMState(
                UInt32(blc_get_output_ptr_pc), PVM.CONTINUE, Int64(1_000_000),
                parsed.code, opcode_mask, skip_distances, zeros(UInt64, 13), state.memory, parsed.jump_table,
                UInt32(0), Vector{Vector{UInt8}}(), Dict{UInt32, PVM.GuestPVM}()
            )
            ptr_state.registers[1] = UInt64(0xFFFF0000)
            ptr_state.registers[2] = UInt64(STACK_HIGH)
            ptr_steps = 0
            while ptr_steps < 1000 && ptr_state.status == PVM.CONTINUE && ptr_state.gas > 0
                PVM.step!(ptr_state)
                ptr_steps += 1
                if ptr_state.status == PVM.HALT
                    break
                elseif ptr_state.status == PVM.HOST
                    skip = PVM.skip_distance(ptr_state.opcode_mask, Int(ptr_state.pc) + 1)
                    ptr_state.pc = ptr_state.pc + 1 + skip
                    ptr_state.status = PVM.CONTINUE
                end
            end
            output_ptr = UInt32(ptr_state.registers[8])

            println("    BLC output: ptr=0x$(string(output_ptr, base=16)), len=$(output_len)")

            if output_len > 0 && output_len < 4096
                output_data = PVM.read_bytes_bulk(state, UInt64(output_ptr), output_len)
                println("    BLC result: $(bytes2hex(output_data))")
            end
        end

        return Dict(
            "service_id" => service_id,
            "output" => output_data,
            "success" => true
        )

    catch e
        println("    Work item execution error: $e")
        return Dict("service_id" => service_id, "success" => false, "error" => string(e))
    end
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
        wp_data = wp["data"]

        println("  Work package on core $(core), hash=$(bytes2hex(wp_hash[1:8]))...")

        # Try to extract the target service ID from the work package
        target_service_id = extract_work_item_service_id(wp_data, chain.services)

        result = nothing
        if target_service_id !== nothing && target_service_id > 0 && haskey(chain.services, target_service_id)
            # Work item for an existing service - execute that service's code
            println("  Target service: #$(target_service_id)")
            result = process_service_work_item!(chain, wp, target_service_id)
        else
            # Bootstrap service (new service creation) or unknown
            result = process_bootstrap_work_package!(chain, wp)
        end

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
                # Note: We notify for ALL requested preimages (simulating Bootstrap accepting them)
                # This allows jamt vm new to complete, even though we don't have the actual preimage data
                # TODO: Implement proper preimage handling via DA layer segments
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

const run = run_testnet

export run, run_testnet, LiveChainState, CoreVMService

end # module

# Run if executed directly
if abspath(PROGRAM_FILE) == @__FILE__
    using .MockTestnet
    run()
end
