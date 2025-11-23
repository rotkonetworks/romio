# JAM Implementation Progress

## Current Status: 15/30 tests passing (50%)

### Fixes Implemented
1. ✅ Accumulate entry point corrected to 5 (was 10)
2. ✅ Account deletion propagation from implications.accounts to state
3. ✅ r8 register = input length per graypaper Y function spec
4. ✅ Memory layout fixed per graypaper eq 770-801:
   - ro_data at 0x10000 (was putting code there incorrectly)
   - rw_data at 0x20000 + rnq(len(ro_data))
   - Code is in state.instructions, NOT in RAM

### Test Results Analysis

**Passing tests (15):**
- enqueue_and_unlock_chain-1, -2
- enqueue_and_unlock_chain_wraps-1, -3
- enqueue_and_unlock_simple-1
- enqueue_and_unlock_with_sr_lookup-1
- enqueue_self_referential-1, -2, -3, -4
- no_available_reports-1
- queues_are_shifted-2
- ready_queue_editing-1
- work_for_ejected_service-1, -3

**Failing tests (15):**
- accumulate_ready_queued_reports-1
- enqueue_and_unlock_chain-3, -4
- enqueue_and_unlock_chain_wraps-2, -4, -5  
- enqueue_and_unlock_simple-2
- enqueue_and_unlock_with_sr_lookup-2
- process_one_immediate_report-1
- queues_are_shifted-1
- ready_queue_editing-2, -3
- same_code_different_services-1
- transfer_for_ejected_service-1
- work_for_ejected_service-2

### Identified Issues

**1. Service 1729 (Bootstrap Service) - Systematic Failure**
- All tests involving service 1729 fail with same pattern
- Service panics at ~step 260 (PC=0x32a0) with invalid r10 register
- Only makes 1 host call (LOG at step ~48) before panicking  
- Never calls CHECKPOINT, so no exceptional_state is set
- Expected to write storage and increment items, but does neither
- Result: last_acc=0, storage empty, items/octets unchanged

**2. Bootstrap Services 0, 1, 2 - Early Error Returns**
- Example: work_for_ejected_service-2
- Service 0 returns error 0x8000000000000018 after only 9 steps
- No host calls made (expected EJECT call for account removal)
- Services detect error condition early and exit

**3. Multi-Operation Tests ("-2", "-3", "-4", "-5")**
- Pattern: "-1" tests usually pass, higher numbers fail
- Suggests cumulative state issues or dependencies between operations

### Root Causes

**Service 1729:**
- Takes error path immediately (LOG with len=0 at step 48)
- Root cause found: service checks r6 register at startup
  - Entry point 5 code: `r7 = r6 << 32; r7 = r7 >> 32; if r7 == 0: jump error`
  - Graypaper eq 803-811 says r6 = 0, so branch always taken
  - After memory layout fix: FAULT at step 986 (was PANIC at step 263)
- Open question: what should r6 contain?
  - Graypaper says 0, but service expects non-zero
  - May be a service-specific ABI or invocation context parameter

**Bootstrap Services:**
- Return error codes without processing
- May need different ABI or calling convention
- work_for_ejected_service expects EJECT host call that never happens

### Next Steps
1. Investigate service 1729's early error detection - what data is it checking?
2. Compare register/stack values with reference implementation  
3. Research bootstrap service ABI requirements
4. Consider if tests require features not yet implemented (e.g., ready queue processing)
