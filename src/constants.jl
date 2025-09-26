# src/constants.jl
# jAM Protocol Constants per spec 0.7.1

# time
const P = 6          # slot period in seconds
const E = 600        # epoch length in timeslots
const JAM_EPOCH = 1_735_732_800  # 2025-01-01 12:00 UTC

# network
const C = 341        # total cores
const V = 1023       # total validators
const HISTORY_DEPTH = 8          # recent history blocks
const L = 14400      # max lookup anchor age (D = L + 4800 = 19200)
const D = 19200      # preimage expiry period

# work and Gas
const GA = 10_000_000         # accumulation gas
const GI = 50_000_000         # is-Authorized gas
const GR = 5_000_000_000      # refine gas
const GT = 3_500_000_000      # total accumulation gas

# sizes (in octets)
const WA = 64_000             # max is-authorized code
const WB = 13_794_305         # max work-package size
const WC = 4_000_000          # max service code
const WE = 684                # erasure piece size
const WG = 4104               # segment size (WP * WE)
const WM = 3072               # max imports
const WX = 3072               # max exports
const WR = 48 * 1024          # max work-report size
const WT = 128                # transfer memo size
const WP = 6                  # pieces per segment

# limits
const I = 16         # max work items per package
const J = 8          # max dependencies in report
const K = 16         # max tickets per extrinsic
const N = 2          # ticket entries per validator
const O = 8          # max authorizations in pool
const Q = 80         # authorization queue size
const R = 10         # rotation period
const S = 2^16       # min public service index
const T = 128        # max extrinsics in package
const U = 5          # report timeout
const Y = 500        # ticket submission deadline

# balance
const BI = 10        # balance per storage item
const BL = 1         # balance per storage octet
const BS = 100       # base service balance

# pVM
const ZA = 2         # dynamic address alignment
const ZI = 2^24      # input data size
const ZP = 2^12      # memory page size (4096)
const ZZ = 2^16      # zone size

# reed-Solomon specific
const DS = 342       # data shards
const TS = 1023      # total shards(same as total V)

# contexts (signing domains)
const XA = b"jam_available"
const XB = b"jam_beefy"
const XE = b"jam_entropy"
const XF = b"jam_fallback_seal"
const XG = b"jam_guarantee"
const XI = b"jam_announce"
const XT = b"jam_ticket_seal"
const XU = b"jam_audit"
const X_VALID = b"jam_valid"
const X_INVALID = b"jam_invalid"
