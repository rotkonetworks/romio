# validator-related types

struct ValidatorKey
    bandersnatch::BandersnatchKey
    ed25519::Ed25519Key
    bls::BlsKey
end

struct ValidatorStats
    blocks_produced::UInt32
    tickets_submitted::UInt32
    disputes_raised::UInt32
end

struct CoreStats
    reports_processed::UInt32
    gas_used::Gas
end

struct ServiceStats
    accumulations::UInt32
    total_gas::Gas
end

struct Ticket
    identifier::Hash
    attempt::UInt32
end

# tagged type for imports
struct Tagged{T}
    value::T
    tag::UInt8
end
