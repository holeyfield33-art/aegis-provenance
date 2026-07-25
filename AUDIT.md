# Pre-Launch Audit — aegis-provenance

Date: 2026-07-25
Branch: `claude/aegis-provenance-audit-0ye1r1`
Auditor: Claude (automated pre-launch audit session)

## Classification

**TypeScript CLI/library** (npm package, in-process only — README's own "Honest
limitations" state *"the current implementation is Mode A only: in-process
harness, no HTTP proxy"*). No frontend, no HTTP server, no database.
**Skipped**: frontend/XSS-in-browser phase, API/route auth phase, DB-layer
phase — none of these components exist. Audited instead: input handling,
injection surfaces in the provenance/attribution/normalization logic (the
actual product of this repo), path/file handling, packaging
(`npm ci`/`build`/`test`/`demo`/`benchmark` from a clean tree), and README
claim verification.

## Baseline (Phase 1) — evidence

All commands below were actually executed in this session, from a clean
`node_modules`/`dist`.

```
$ rm -rf node_modules dist && npm ci
added 55 packages, and audited 56 packages in 3s
1 high severity vulnerability   (see Open findings — postcss, dev-only, transitive)

$ npm run typecheck        # tsc --noEmit
(clean, no output)

$ npm test                 # vitest run
Test Files  12 passed (12)
Tests       107 passed (107)     [110/110 after this session's fixes+regression tests]

$ npm run build            # tsc -p tsconfig.build.json
(clean, dist/ produced)

$ npm run demo              # tsx ./src/demo.ts demo
Aegis blocked execution: Blocked because tool arguments originate only from
inert spans for a sensitive action.

$ npm run benchmark         # tsx ./src/benchmark.ts
Total fixtures:      99
Correct:             99
Accuracy:            100% (threshold >= 95%)
Crashes:             0
Benchmark PASSED.
```

Secret scan: `git log -p --all` and working tree grepped for AWS keys,
`sk-`/`hf_`/PEM private-key headers, and `AEGIS_SIGNING_KEY`-shaped hex
blobs, plus history scan for ever-added `.env`/`.pem`/`.key`/`.p12` files —
**none found**. `.gitignore` already excludes `*.env`/`*.key`.

## Phase 2 — core flow under attack

Core flow (from README's own worked example): `runAegis()` ingests
system/user/retrieved spans, calls the model, and deterministically decides
`allow`/`block`/`flag` on the resulting tool call, emitting a hash-linked
receipt. Executed for real via `tsx` scripts against the built pipeline
(not just imagined):

| Input | Result |
|---|---|
| empty string system/user message | OK — allowed, no crash |
| whitespace-only | OK — allowed, no crash |
| `null`/`undefined` system or user message | **Crashed** — see Fixed #2 |
| 100KB input | OK — handled, no crash |
| unicode + emoji | OK — handled, no crash |
| `<script>alert(1)</script>` | OK — treated as inert content data, not executed (no DOM in this runtime) |
| `'; DROP TABLE users;--` | OK — no SQL layer exists; treated as inert text |
| `../../../etc/passwd` in span content | OK — no filesystem read of span content occurs |
| tool_call with missing `tool_name` | OK — throws typed `AegisAttributionError` |
| tool_call with unregistered `tool_name` | OK — throws typed `AegisAttributionError` |
| `tool_args` as a raw string instead of object | OK — blocked cleanly (no crash) |
| `tool_args` with a circular reference | **Crashed** — `RangeError: Maximum call stack size exceeded` (see Open findings) |
| rapid repeat / concurrent identical calls (in-memory) | OK |
| concurrent `ReceiptStore.appendReceipt` on the same file (double-submit) | **Chain corrupted** (see Open findings — race condition) |
| README's own worked exfiltration example + one incidental unrelated argument field | **Bypassed** — verdict `allow` instead of `block` (see Fixed #1 — this is the headline finding) |

## Phase 3 — README claim verification

| Claim | Verdict |
|---|---|
| `npm install` / `npm ci` works from clean env | Verified — ran above |
| `npm test` passes | Verified — 110/110 after this session's fixes (107/107 before) |
| `npm run demo` blocks the malicious-page scenario | Verified — ran above |
| `npm run benchmark` — "fails if accuracy drops below 95% or any fixture crashes" | Verified — 99/99, 100%, 0 crashes |
| "Aegis rejects tool calls whose trigger text is only found in untrusted content" | **Was false** for the case in Fixed #1 (now true — see fix + regression test) |
| "Receipt persistence is file-based and intended for demo/testing" | Consistent with finding — see race-condition item below; README already scopes this down correctly, so not a false claim |
| Real-model evaluation (`npm run llm-eval`) | **UNVERIFIED** — requires `AEGIS_EVAL_API_KEY` and outbound calls to a real model endpoint; not exercised in this session. README itself already caveats this as a "complementary check," not a core claim |
| "publishing to npm is pending... use it from source" | Verified accurate — package is not on the npm registry per README's own note |

## Fixed (P0/P1)

Both fixes are on this branch, each with a regression test that fails before
and passes after (verified in this session by stashing the source fix and
re-running the test file).

### 1. [P0 — Security] Core exfiltration-blocking guarantee bypassed by an unrelated argument field

**File**: `src/attribution.ts` (`argumentProvenanceMatch`, `decideAttribution`)

**Repro** (executed against the pre-fix code):
```
$ npx tsx poc1.ts
# runAegis() with README's own exact worked example, plus tool_args
# { recipient: 'admin@evil.com', subject: 'email' } instead of just
# { recipient: 'admin@evil.com', subject: 'Report' }
BYPASS: call was ALLOWED
{ ... "verdict": "allow", "reason": "Allowed by deterministic provenance checks." ... }
```

**Root cause**: `argumentProvenanceMatch` scanned every argument value
against every span, then OR'd the "is any matched span actionable"
signal across *all* values into a single `actionablePresent` flag, and
`decideAttribution` only blocked when the *whole call* had zero actionable
matches (`inertOnly && !actionablePresent`). A single unrelated,
plausible field (e.g. a `subject` a real model would fill in) that happens
to share a common word with the user's own message (e.g. "email") flips
`actionablePresent` true for the entire call — masking that the actually
dangerous value (`recipient: 'admin@evil.com'`) matched **only** the
attacker's untrusted span. This is the exact scenario the README's headline
security claim describes, defeated by one incidental extra field.

**Fix**: track inert-only-ness **per argument value**, not aggregated
across the whole call. Added `anyValueInertOnly` to
`ProvenanceMatchResult` — true iff at least one individual argument value's
matches are exclusively inert spans, regardless of what any *other* value
matched. `decideAttribution`'s block condition now uses this instead of the
aggregate `inertOnly && !actionablePresent`.

**Regression test**: `test/attribution.test.ts` →
`describe('per-argument inert-only provenance (aggregate-match bypass)')`
(2 tests). Verified failing on pre-fix code (`git stash` the source change,
re-run — both new tests fail with `expected 'allow' to be 'block'` and
`expected undefined to be true`), passing after.

**Re-verified after fix**: full baseline re-run above (110/110 tests, clean
typecheck/build, demo still blocks its own scenario, benchmark still 99/99
100%).

### 2. [P1 — Broken core flow] Crash on realistic null/undefined input

**File**: `src/ingest.ts` (`wrapSpan`)

**Repro** (executed against the pre-fix code):
```
$ npx tsx trace_null.ts
TypeError: Cannot read properties of undefined (reading 'replace')
    at stripInvisible (src/normalize.ts:68:15)
    at normalizeMatchText (src/normalize.ts:165:45)
    at candidateRepresentations (src/normalize.ts:172:13)
    at argumentProvenanceMatch (src/attribution.ts:106:33)
    at decideAttribution (src/attribution.ts:365:27)
    at runAegis (src/harness.ts:83:23)
```

**Root cause**: `wrapSpan` accepted non-string `content` (e.g. `undefined`,
realistic for a caller forwarding an optional field from an HTTP request or
config that was never set) without validation, signed it without error, and
the crash only surfaced much later, deep inside the provenance-matching
internals, as an opaque low-level `TypeError` rather than a clear, typed
error at the point of ingest — the opposite of this library's own
"fail-closed" design principle used everywhere else (e.g.
`AegisVerificationError`).

**Fix**: `wrapSpan` now validates `typeof content === 'string'` up front and
throws `AegisSigningError` with a clear message; `runAegis`'s existing
ingest `try/catch` wraps this into `AegisReceiptError` as it does for any
other ingest failure.

**Regression test**: `test/harness.test.ts` → `'fails closed with a typed
error instead of crashing on non-string content'` — covers `system`,
`userMessage`, and a retrieved span's `content` all being non-string.
Verified failing (raw `TypeError`, uncaught) on pre-fix code, passing after.

**Re-verified after fix**: full baseline re-run above.

## Open findings (P2/P3 — logged, not fixed per audit scope)

| # | Priority | Finding | Repro (executed) | Notes |
|---|---|---|---|---|
| 1 | P2 — Reliability | `ReceiptStore.appendReceipt` has no file locking: concurrent/rapid-repeat calls against the same store race on read-then-append, corrupting the hash chain (`prev_receipt_hash` mismatch) even though every individual write succeeds. | `npx tsx poc_race.ts` — 10 concurrent `appendReceipt()` calls against one file all resolve `fulfilled`, but `verifyChain()` afterward reports `chain valid: false` (`Receipt 1 prev_receipt_hash mismatch`). | README already scopes receipt persistence as "file-based and intended for demo/testing," so this is a known-limitation gap, not a false claim. Not fixed: a correct fix needs real file locking/serialization, which is more than a trivial (<10 line) change and carries its own behavior/deadlock risk to get right under audit time pressure. |
| 2 | P2 — Reliability | `tool_args` containing a circular reference crashes with an uncaught `RangeError: Maximum call stack size exceeded` (stack overflow in `extractStrings` recursion / `JSON.stringify` in canary detection), instead of a controlled error. | `npx tsx poc_edge.ts` → `ERR (tool_args circular reference): RangeError: Maximum call stack size exceeded` | Low realistic likelihood: `tool_args` normally comes from `JSON.parse`d model output, which cannot contain cycles. Only reachable via a hand-written `ModelClient` that constructs a cyclic JS object directly. Logged, not fixed (not trivial to guard recursion depth/cycles without care). |
| 3 | P2 — Security (dev-only) | `npm audit` reports 1 high-severity transitive dev dependency: `postcss <=8.5.17` (path traversal in source-map auto-loading, GHSA-r28c-9q8g-f849), pulled in via a dev/build tool, not `dependencies`. | `npm audit --json` (executed above) | Not in the shipped `dist`/`exports` surface (`dependencies` are only `@noble/curves`, `@noble/hashes`). `npm audit fix` reports a fix is available; recommend running it before launch as routine hygiene, but it does not affect the published package's runtime. |
| 4 | P3 — Polish | Inert-span framing (`[[AEGIS-INERT-SPAN-START]]`/`END]]` in `src/assembly.ts`) does not escape or reject literal occurrences of those exact delimiter tokens inside untrusted span content, so an attacker could in principle inject a fake frame boundary in the *text the model sees*. | Not executed as a live PoC — reasoned from code (`renderInertSpan` in `src/assembly.ts` inserts `span.content` verbatim between the frame markers with no escaping). | Does **not** bypass actual enforcement: `trust` is derived cryptographically from `origin` at ingest/verify time (`src/ingest.ts`), never from the rendered text, so the deterministic egress checks in `decideAttribution` are unaffected regardless of what framing the model believes it saw. This only affects the model-facing "make output easier to inspect" framing signal, not the security boundary. Cosmetic/defense-in-depth polish item. |

## Unverified

- **Real-model evaluation** (`npm run llm-eval`, `docs/llm-evaluation.md` claims about baseline/framed ASR, enforcement rate, benign allow rate against real Hugging Face-hosted or local llama.cpp models). Requires `AEGIS_EVAL_API_KEY` and outbound network calls to a model endpoint; not exercised in this session. The README/docs already explicitly scope this as a complementary check to the deterministic benchmark, not a launch-blocking claim.
- Behavior on Node versions other than the one available in this session (v22.22.2) against the stated `engines.node >= 20` — not cross-tested on Node 20/21 directly.
- GitHub Actions CI/benchmark workflows (`.github/workflows/*.yml`) were read and mirror exactly the commands run locally in this session (`npm ci` → `npm run typecheck` → `npm test`; `npm ci` → `npm run benchmark`), but the actual hosted Actions runs were not triggered/observed from this session.

## Stop condition

Baseline green (install/typecheck/test/build/demo/benchmark all pass from a
clean tree) — **met**. Core flow survives Phase 2 attack inputs without
unhandled crashes on realistic input — **met after fixes** (the one
remaining crash, circular `tool_args`, is not reachable via realistic
JSON-sourced model output and is logged as P2, not a launch blocker). All
P0/P1 found are fixed with regression tests, and the full baseline was
re-run clean after each fix — **met**.

**Ship recommendation**: no DO NOT SHIP blockers remain open. The one item
worth a conscious decision before launch is Open Finding #1 (receipt-store
race under concurrent writes) — acceptable given the README already scopes
file-based receipt persistence as demo/testing-only, but worth flagging
explicitly to the team since "tamper-evident audit trail" is a headline
README claim and this is the one condition under which it currently breaks.
