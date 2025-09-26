# src/blocks/extrinsic.jl
# extrinsic data structures

struct BandersnatchProof
    data::BandersnatchSig
end

struct TicketExtrinsic
    entries::Vector{Tuple{UInt32, BandersnatchProof}}
end

struct PreimageExtrinsic
    preimages::Vector{Tuple{ServiceId, Blob}}
end

struct Guarantee
    report::WorkReport
    timeslot::TimeSlot
    credentials::Vector{Tuple{ValidatorId, Ed25519Sig}}
end

struct GuaranteeExtrinsic
    guarantees::Vector{Guarantee}
end

struct Assurance
    anchor::Hash
    bitfield::BitVector
    validator_index::ValidatorId
    signature::Ed25519Sig
end

struct AssuranceExtrinsic
    assurances::Vector{Assurance}
end

struct Verdict
    report_hash::Hash
    epoch::UInt32
    judgments::Vector{Tuple{Bool, ValidatorId, Ed25519Sig}}
end

struct Culprit
    target::Hash
    key::Ed25519Key
    signature::Ed25519Sig
end

struct Fault
    target::Hash
    vote::Bool
    key::Ed25519Key
    signature::Ed25519Sig
end

struct DisputeExtrinsic
    verdicts::Vector{Verdict}
    culprits::Vector{Culprit}
    faults::Vector{Fault}
end

struct Extrinsic
    tickets::TicketExtrinsic
    preimages::PreimageExtrinsic
    guarantees::GuaranteeExtrinsic
    assurances::AssuranceExtrinsic
    disputes::DisputeExtrinsic
end
