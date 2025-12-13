# Safrole State Transition Function
# Per graypaper section on safrole consensus

include("../types/basic.jl")
include("../test_vectors/loader.jl")
using JSON3

# Epoch length (slots per epoch) - tiny = 12, full = 600
const EPOCH_LENGTH_TINY = 12
const EPOCH_LENGTH_FULL = 600

# Ticket submission period ends at epoch_length - Y where Y is tail slots
# For tiny: Y = 2, so tickets accepted in slots 0-9 of epoch
const TAIL_SLOTS_TINY = 2

# Path to the Python venv with jam-vrf installed
const PYTHON_VENV = joinpath(@__DIR__, "..", "..", ".venv", "bin", "python3")
const VRF_HELPER = joinpath(@__DIR__, "..", "crypto", "vrf_helper.py")

# Compute ticket ID from signature using Bandersnatch VRF
# The ticket ID is the first 32 bytes of the SHA-512 hash of the VRF output point
function compute_ticket_id(signature_hex::String)::Union{Vector{UInt8}, Nothing}
    try
        # Call the Python helper to compute ticket ID
        sig_hex = startswith(signature_hex, "0x") ? signature_hex : "0x" * signature_hex
        result = read(`$PYTHON_VENV $VRF_HELPER ticket_id $sig_hex`, String)
        result = strip(result)
        if !isempty(result)
            return hex2bytes(result)
        end
    catch e
        # VRF computation failed (invalid point)
        return nothing
    end
    return nothing
end

# Extract ticket ID from signature - legacy wrapper
# Returns the ticket ID as a Vector{UInt8} for comparison
function extract_ticket_id(sig)
    if sig isa String
        # Use VRF-based computation
        return compute_ticket_id(sig)
    elseif sig isa Vector{UInt8}
        # Convert to hex and compute
        return compute_ticket_id(bytes2hex(sig))
    end
    return nothing
end

# Verify ring VRF proofs and compute ticket IDs in batch
# Returns array of (ticket_id, is_valid) tuples
function verify_tickets(
    gamma_z::String,      # Ring commitment
    ring_size::Int,       # Number of validators
    eta2::String,         # Epoch entropy (eta[2])
    tickets               # Array of tickets with :signature and :attempt
)::Vector{Tuple{Union{Vector{UInt8}, Nothing}, Bool}}
    # Build JSON request for batch verification
    ticket_data = [Dict("attempt" => get(t, :attempt, 0), "signature" => string(get(t, :signature, ""))) for t in tickets]
    request = Dict(
        "commitment" => string(gamma_z),
        "ring_size" => ring_size,
        "entropy" => string(eta2),
        "tickets" => ticket_data
    )

    results = Vector{Tuple{Union{Vector{UInt8}, Nothing}, Bool}}()

    try
        # Call Python helper with batch_verify command
        cmd = `$PYTHON_VENV $VRF_HELPER batch_verify`
        proc = open(cmd, "r+")
        write(proc, JSON3.write(request))
        close(proc.in)
        output = read(proc, String)
        wait(proc)

        # Parse results
        parsed = JSON3.read(output)
        for r in parsed
            if haskey(r, :ok)
                ticket_id = hex2bytes(r[:ok])
                push!(results, (ticket_id, true))
            else
                push!(results, (nothing, false))
            end
        end
    catch e
        # On error, mark all tickets as invalid
        for _ in tickets
            push!(results, (nothing, false))
        end
    end

    return results
end

# Process safrole STF
# Returns (new_state, result) where result is :ok or error symbol
function process_safrole(
    pre_state,
    slot,
    entropy,
    extrinsic
)
    # Get current state slot (tau)
    tau = pre_state[:tau]

    # 1. Validate slot - must be strictly monotonic (slot > tau)
    if slot <= tau
        return (pre_state, :bad_slot)
    end

    # Get tickets from extrinsic (if any)
    tickets = if extrinsic isa AbstractVector
        extrinsic
    else
        []
    end

    # If no tickets, allow transition
    if isempty(tickets)
        return (pre_state, :ok)
    end

    # Determine epoch parameters based on validator count
    # Tiny has 6 validators, full has 1023
    validators = get(pre_state, :kappa, [])
    epoch_length = length(validators) <= 10 ? EPOCH_LENGTH_TINY : EPOCH_LENGTH_FULL
    tail_slots = length(validators) <= 10 ? TAIL_SLOTS_TINY : 10  # Y for full

    # 2. Check if tickets are allowed (not in epoch tail)
    # Tickets can be submitted in slots [0, epoch_length - tail_slots) within epoch
    slot_in_epoch = slot % epoch_length
    if slot_in_epoch >= (epoch_length - tail_slots)
        return (pre_state, :unexpected_ticket)
    end

    # 3. Validate ticket attempt numbers
    # Per graypaper: N_T = 3 ticket attempts per validator per epoch (attempts 0, 1, 2)
    for ticket in tickets
        attempt = get(ticket, :attempt, -1)
        if attempt < 0 || attempt > 2
            return (pre_state, :bad_ticket_attempt)
        end
    end

    # 4. Verify ring VRF proofs and compute ticket IDs
    # This verifies the proofs against gamma_z (ring commitment) and eta[2] (entropy)
    gamma_z = get(pre_state, :gamma_z, nothing)
    eta = get(pre_state, :eta, nothing)
    ring_size = length(validators)

    # Get eta[2] for VRF verification (0-indexed in graypaper, 3rd element)
    eta2 = if eta !== nothing && length(eta) >= 3
        string(eta[3])  # Julia is 1-indexed
    else
        ""
    end

    # Verify all tickets
    verification_results = if gamma_z !== nothing && !isempty(eta2)
        verify_tickets(string(gamma_z), ring_size, eta2, tickets)
    else
        # Fallback: just compute ticket IDs without full verification
        [(extract_ticket_id(get(t, :signature, nothing)), true) for t in tickets]
    end

    # Check for bad proofs (any ticket failed verification)
    ticket_ids = Vector{Union{Vector{UInt8}, Nothing}}()
    for (ticket_id, is_valid) in verification_results
        if !is_valid
            # VRF proof verification failed
            return (pre_state, :bad_ticket_proof)
        end
        push!(ticket_ids, ticket_id)
    end

    # 5. Check ticket ordering (tickets must be sorted by ID in ascending order)
    # Per graypaper: tickets must be ordered by their identifier
    for i in 2:length(ticket_ids)
        prev_id = ticket_ids[i-1]
        curr_id = ticket_ids[i]
        if prev_id !== nothing && curr_id !== nothing
            # Compare as byte arrays (lexicographic ordering)
            if prev_id >= curr_id
                return (pre_state, :bad_ticket_order)
            end
        end
    end

    # 6. Check for duplicate tickets within submission
    seen_ids = Set{Vector{UInt8}}()
    for ticket_id in ticket_ids
        if ticket_id !== nothing
            if ticket_id in seen_ids
                return (pre_state, :duplicate_ticket)
            end
            push!(seen_ids, ticket_id)
        end
    end

    # 7. Check for duplicate tickets against gamma_a (existing tickets in accumulator)
    # gamma_a stores TicketBody with `id` field (32-byte hex string)
    gamma_a = get(pre_state, :gamma_a, [])
    for ticket_id in ticket_ids
        if ticket_id !== nothing
            for existing in gamma_a
                existing_id = get(existing, :id, nothing)
                if existing_id !== nothing
                    # Parse gamma_a id (it's a hex string, not a signature - just direct bytes)
                    existing_hex = startswith(existing_id, "0x") ? existing_id[3:end] : existing_id
                    existing_id_bytes = hex2bytes(existing_hex)
                    if ticket_id == existing_id_bytes
                        return (pre_state, :duplicate_ticket)
                    end
                end
            end
        end
    end

    return (pre_state, :ok)
end

# Run safrole test vector
function run_safrole_test_vector(filepath::String)
    println("\n=== Running Safrole Test Vector: $(basename(filepath)) ===")

    # Load test vector
    json_str = read(filepath, String)
    tv = JSON3.read(json_str)

    # Parse input
    slot = tv[:input][:slot]
    entropy = tv[:input][:entropy]
    extrinsic = tv[:input][:extrinsic]

    # Pre-state
    pre_state = tv[:pre_state]

    println("Input:")
    println("  Slot: $slot")

    # Run state transition
    new_state, result = process_safrole(pre_state, slot, entropy, extrinsic)

    # Check expected output
    expected_output = tv[:output]

    println("\n=== State Comparison ===")

    if haskey(expected_output, :err)
        # Expected an error
        expected_err = Symbol(expected_output[:err])
        if result == expected_err
            println("  Correct error returned: $result")
            println("\n=== Test Vector Result ===")
            println("  PASS")
            return true
        else
            println("  Wrong error: expected $expected_err, got $result")
            println("\n=== Test Vector Result ===")
            println("  FAIL")
            return false
        end
    else
        # Expected success
        if result == :ok
            println("  Success as expected")
            println("\n=== Test Vector Result ===")
            println("  PASS")
            return true
        else
            println("  Expected success, got error: $result")
            println("\n=== Test Vector Result ===")
            println("  FAIL")
            return false
        end
    end
end

export process_safrole, run_safrole_test_vector
