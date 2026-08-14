# Agentic red-team sweep — 2026-08-13

Target: `aegis-provenance` @ `main` (173ac71), via `aletheia-redteam-kit`.

## Phase 1 — full catalog, mutation-expanded
Ran the entire attack catalog unfiltered (~65 categories, not just the 16
tool-call-relevant ones) with aggressive payload-mutation expansion:
869 base fixtures → 3,041 mutated fixtures (templates, encodings, homoglyphs).

Result: **553/553 attempted sensitive-tool-call attacks blocked — zero real
bypasses**, spanning 27 categories (prompt injection, jailbreak, data
exfiltration, tool abuse, memory poisoning, steganographic prompting, RAG
injection, and more). Two known false positives (`BC_495`, `BC_515`) recur —
already root-caused as an adapter-mock artifact, not an aegis bug.

## Phase 2 — evolutionary learning attacker
`kit/agentic_runner.py`: each round replays the queue, requeues every blocked
attack as 5 freshly-mutated variants across 8 strategies (objective-suffix,
safe-reframe, step-escalation, base64-wrapping, roleplay, synonym substitution,
markdown-wrapping, bilingual reframing), and ranks strategies by running success
rate (online learning, not scripted retries).

Config: 8 strategies, 2,501 seed attacks. Self-terminated after 4 rounds at a
5-minute internal budget. 32,896 total requests. Queue growth:
2,501 → 2,135 → 6,640 → 21,620 (next round would have been 74,440 — exponential,
as expected from an unconstrained evolutionary requeue).

### The "11,402 successful evasions" number is wrong — here is why
The loop's success check only asks "did aegis PROCEED," never "did the payload
get weaponized into a sensitive tool call." All 11,402 reported "successes" were
replayed directly against aegis and their decision receipts inspected: **every
one was the adapter's non-sensitive `search` fallback** — the mutations never
got the mock model to attempt a sensitive action. **True bypass count: 0/11,402.**

## Bottom line
Across 36,000+ attack executions (full catalog + agentic loop), every category
and every mutation strategy the kit has, including 4 generations of a real
rephrase-and-retry evolutionary attacker: **zero confirmed bypasses of aegis's
provenance/intent gate.**

## The one real finding (belongs to the kit, not aegis)
`--mode agentic` lacks the tool_name-based verification filter that plain
api-mode has, so its PROCEED-only success check systematically overcounts
"evasions." Written up in the adapter reference; tracked as a kit-side issue.
Every published agentic number must be reconciled against real receipts until
the filter lands.
