# src/constants.jl
# JAM Protocol Constants

# Time - JAM common era
const P = 6          # Slot period in seconds
const E = 600        # Epoch length in timeslots
const JAM_EPOCH = 1735732800  # 2025-01-01 12:00 UTC

# Network
const C = 341        # Total cores
const V = 1023       # Total validators
const H = 8          # Recent history blocks
const L = 14400      # Max lookup anchor age
const D = 19200      # Preimage expiry period

# Work and Gas
const GA = 10_000_000         # Accumulation gas
const GI = 50_000_000         # Is-Authorized gas
const GR = 5_000_000_000      # Refine gas
const GT = 3_500_000_000      # Total accumulation gas

# Sizes
const WA = 64_000             # Max is-authorized code
const WB = 13_794_305         # Max work-package size
const WC = 4_000_000          # Max service code
const WE = 684                # Erasure piece size
const WG = 4104               # Segment size
const WM = 3072               # Max imports
const WX = 3072               # Max exports
const WR = 48 * 1024          # Max work-report size
const WT = 128                # Transfer memo size

# Limits
const I = 16         # Max work items per package
const J = 8          # Max dependencies in report
const K = 16         # Max tickets per extrinsic
const N = 2          # Ticket entries per validator
const O = 8          # Max authorizations in pool
const Q = 80         # Authorization queue size
const R = 10         # Rotation period
const S = 2^16       # Min public service index
const T = 128        # Max extrinsics in package
const U = 5          # Report timeout
const Y = 500        # Ticket submission deadline

# Balance
const BI = 10        # Balance per storage item
const BL = 1         # Balance per storage octet
const BS = 100       # Base service balance

# PVM
const ZA = 2         # Dynamic address alignment
const ZI = 2^24      # Input data size
const ZP = 2^12      # Memory page size
const ZZ = 2^16      # Zone size

# Contexts
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

# Erasure coding
const DS = 342      # Amount of Data shards
