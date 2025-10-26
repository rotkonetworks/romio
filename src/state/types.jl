# state-specific types

struct PendingReport
    workreport::WorkReport
    timestamp::TimeSlot
end

struct AccumulationEntry
    service::ServiceId
    output::Hash
    timeslot::TimeSlot
end

struct MerkleMountainBelt
    peaks::Vector{Hash}
    root::Hash
end

function MerkleMountainBelt()
    MerkleMountainBelt(Vector{Hash}(), zeros(32))
end