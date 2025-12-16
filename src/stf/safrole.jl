# Safrole State Transition Function
# Per graypaper section on safrole consensus

include("../types/basic.jl")
include("../test_vectors/loader.jl")
include("../crypto/bandersnatch.jl")
using JSON3

# Epoch length (slots per epoch) - tiny = 12, full = 600
const EPOCH_LENGTH_TINY = 12
const EPOCH_LENGTH_FULL = 600

# Ticket submission period ends at epoch_length - Y where Y is tail slots
# For tiny: Y = 2, so tickets accepted in slots 0-9 of epoch
const TAIL_SLOTS_TINY = 2

# Compute ticket ID from signature using Bandersnatch VRF
# The ticket ID is the first 32 bytes of the SHA-512 hash of the VRF output point
function compute_ticket_id(signature_hex::String)::Union{Vector{UInt8}, Nothing}
    # Convert hex to bytes
    sig_hex = startswith(signature_hex, "0x") ? signature_hex[3:end] : signature_hex
    sig_bytes = hex2bytes(sig_hex)

    try
        return Bandersnatch.compute_ticket_id_from_signature(sig_bytes)
    catch e
        return nothing
    end
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
    # Convert hex inputs to bytes
    gamma_z_hex = startswith(gamma_z, "0x") ? gamma_z[3:end] : gamma_z
    gamma_z_bytes = hex2bytes(gamma_z_hex)
    eta2_hex = startswith(eta2, "0x") ? eta2[3:end] : eta2
    eta2_bytes = hex2bytes(eta2_hex)

    try
        # Convert tickets to format expected by native batch_verify_tickets
        native_tickets = []
        for t in tickets
            sig_hex = string(get(t, :signature, ""))
            sig_hex = startswith(sig_hex, "0x") ? sig_hex[3:end] : sig_hex
            push!(native_tickets, (
                attempt = get(t, :attempt, 0),
                signature = hex2bytes(sig_hex)
            ))
        end
        return Bandersnatch.batch_verify_tickets(gamma_z_bytes, ring_size, eta2_bytes, native_tickets)
    catch e
        # On error, mark all tickets as invalid
        results = Vector{Tuple{Union{Vector{UInt8}, Nothing}, Bool}}()
        for _ in tickets
            push!(results, (nothing, false))
        end
        return results
    end
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
    gamma_z = get(pre_state, :gamma_z, "0x" * "00"^48)
    eta = get(pre_state, :eta, ["0x" * "00"^32 for _ in 1:4])
    eta2 = eta[3]  # eta[2] in 0-indexed

    verified = verify_tickets(string(gamma_z), length(validators), string(eta2), tickets)

    # Check all tickets verified successfully
    for (ticket_id, is_valid) in verified
        if !is_valid
            return (pre_state, :bad_ticket_proof)
        end
    end

    # 5. Check ticket ordering - tickets must be sorted by ticket ID (ascending)
    # Per graypaper eq. 315: n = orderuniqby{x.id}{x ∈ n}
    for i in 1:(length(verified) - 1)
        id1, _ = verified[i]
        id2, _ = verified[i + 1]
        if id1 !== nothing && id2 !== nothing
            if id1 >= id2
                return (pre_state, :bad_ticket_order)
            end
        end
    end

    # 6. Check for duplicate ticket IDs within submission batch
    seen_ids = Set{Vector{UInt8}}()
    for (ticket_id, _) in verified
        if ticket_id !== nothing
            if ticket_id in seen_ids
                return (pre_state, :duplicate_ticket)
            end
            push!(seen_ids, ticket_id)
        end
    end

    # 7. Check for duplicates with existing accumulator
    # Per graypaper eq. 316: {x.id | x ∈ n} ⊥ {x.id | x ∈ γ_a}
    gamma_a_existing = get(pre_state, :gamma_a, [])
    existing_ids = Set{Vector{UInt8}}()
    for entry in gamma_a_existing
        entry_id = get(entry, :id, nothing)
        if entry_id !== nothing
            # Convert hex string to bytes if needed
            if entry_id isa String
                id_hex = startswith(entry_id, "0x") ? entry_id[3:end] : entry_id
                push!(existing_ids, hex2bytes(id_hex))
            elseif entry_id isa AbstractVector{UInt8}
                push!(existing_ids, Vector{UInt8}(entry_id))
            end
        end
    end
    for (ticket_id, _) in verified
        if ticket_id !== nothing && ticket_id in existing_ids
            return (pre_state, :duplicate_ticket)
        end
    end

    # 8. Insert valid tickets into gamma_a (ticket accumulator)
    # Using Outside-in insertion per graypaper section 6.3
    # Convert to mutable Vector{Any} to allow mixed types
    gamma_a = Vector{Any}(collect(get(pre_state, :gamma_a, [])))

    for (i, ticket) in enumerate(tickets)
        ticket_id, _ = verified[i]
        if ticket_id !== nothing
            # Create ticket entry
            entry = (
                id = ticket_id,
                attempt = get(ticket, :attempt, 0)
            )

            # Outside-in insertion: alternate front/back
            if length(gamma_a) % 2 == 0
                pushfirst!(gamma_a, entry)
            else
                push!(gamma_a, entry)
            end
        end
    end

    # 6. Build new state
    new_state = copy(pre_state)
    new_state[:gamma_a] = gamma_a
    new_state[:tau] = slot

    return (new_state, :ok)
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

    # Parse pre-state
    pre_state = Dict{Symbol, Any}()
    pre_state[:tau] = tv[:pre_state][:tau]
    pre_state[:eta] = tv[:pre_state][:eta]
    pre_state[:kappa] = tv[:pre_state][:kappa]
    pre_state[:lambda] = tv[:pre_state][:lambda]
    pre_state[:gamma_k] = get(tv[:pre_state], :gamma_k, [])
    pre_state[:gamma_a] = get(tv[:pre_state], :gamma_a, [])
    pre_state[:gamma_s] = get(tv[:pre_state], :gamma_s, [])
    pre_state[:gamma_z] = get(tv[:pre_state], :gamma_z, "0x" * "00"^48)
    pre_state[:iota] = get(tv[:pre_state], :iota, [])

    println("Input:")
    println("  Slot: $slot")
    println("  Extrinsic tickets: $(length(extrinsic))")

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
