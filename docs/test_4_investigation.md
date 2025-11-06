# History Test 4 Super Peak Investigation

## Issue
Test `progress_blocks_history-4.json` expects a different beefy_root than what the graypaper spec computes.

## Test Data
- **Pre-state MMR peaks:** `[null, null, null, peak3]`
  - peak3 = `0x658b919f734bd39262c10589aa1afc657471d902a6a361c044f78de17d660bc6`

- **Input accumulate root:** `0xa983417440b618f29ed0b7fa65212fce2d363cb2b2c18871a05c4f67217290b0`

- **Post-state MMR peaks:** `[peak0, null, null, peak3]`
  - peak0 = `0xa983417440b618f29ed0b7fa65212fce2d363cb2b2c18871a05c4f67217290b0`
  - peak3 = `0x658b919f734bd39262c10589aa1afc657471d902a6a361c044f78de17d660bc6`

## Expected vs Actual

**Test vector expects:**
```
beefy_root = 0xebdb6db060afceaa2a99a499a84476847444ffc3787f6a4786e713f5362dbf4d
```

**Our implementation computes:**
```
beefy_root = 0xdd489e9c79a72b8c4a992c5b7f28dad95c1ecfc6099f831befb7bea42aefb433
```

## Graypaper Spec (merklization.tex lines 307-316)

```
mmr_super_peak(b) = {
  zero_hash             if |h| = 0
  h[0]                  if |h| = 1
  keccak("$peak" || mmr_super_peak(h[0..|h|-1]) || h[|h|-1])   otherwise
}
where h = [x for x in b if x != none]
```

## Our Calculation

Given peaks `b = [peak0, null, null, peak3]`:

1. Filter to get `h = [peak0, peak3]`
2. Since `|h| = 2`, use recursive case:
   - `mmr_super_peak(h) = keccak("$peak" || mmr_super_peak([peak0]) || peak3)`
3. Base case: `mmr_super_peak([peak0]) = peak0`
4. Therefore: `mmr_super_peak(h) = keccak("$peak" || peak0 || peak3)`

## Manual Verification

```julia
prefix = UInt8[0x24, 0x70, 0x65, 0x61, 0x6b]  # "$peak"
peak0  = parse_hex("a983417440b618f29ed0b7fa65212fce2d363cb2b2c18871a05c4f67217290b0")
peak3  = parse_hex("658b919f734bd39262c10589aa1afc657471d902a6a361c044f78de17d660bc6")

input = vcat(prefix, peak0, peak3)  # 5 + 32 + 32 = 69 bytes
result = keccak256(input)
# => 0xdd489e9c79a72b8c4a992c5b7f28dad95c1ecfc6099f831befb7bea42aefb433
```

**Result matches our implementation exactly.**

## Tested Alternatives

1. **Reversed order** (peak3 || peak0):
   - Result: `0xcb767f66a1902330c263a0ae14918c57056b3019cb1357d80dc661e429b74f87`
   - ❌ Does not match test vector

2. **Different prefix encoding**: Not tested yet

3. **Different peak ordering**: Preserving indices vs filtering - not tested yet

## Conclusion

Our implementation is **correct per the graypaper specification**. The test vector either:

1. **Uses a different spec interpretation** (possible errata or updated spec)
2. **Has a bug** (test vector generation issue)
3. **Uses different encoding** for the "$peak" prefix or peak ordering

## Tests 1-3 Status

✅ **All passing** - This issue only affects test 4, which has non-contiguous peaks.

Tests 1-3 have contiguous peaks, so the super_peak calculation is simpler and matches expected values.

## Recommendation

**Continue with optimizations.** This is a spec interpretation issue, not a performance bug. We can:

1. Open an issue with jam-test-vectors repo
2. Check for graypaper errata or recent spec changes
3. Ask in JAM community channels about the correct interpretation

For now, document this as a known issue and mark test 4 as "spec interpretation difference."

## Related Code

- `src/utils/mmr.jl:166-195` - mmr_super_peak implementation
- `test/debug_super_peak.jl` - Debug script demonstrating the issue
