# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **Security (P0, #39 — sensitive-tool/egress-contract mismatch)**: a tool
  name that matched the sensitivity table's name pattern (e.g. `/^send_/`)
  but was not one of the exact aliases documented in
  `src/tool-contracts.ts`'s `TOOL_ALIASES` resolved to egress contract
  `'none'`, which `egressAuthorizationCheck` could not distinguish from "a
  recognized tool with no destination" — it returned `'not-applicable'`
  either way, silently falling back to the generic, whole-call
  `hasUserSessionIntent` gate. That gate is satisfied by ANY authorized
  destination appearing anywhere in the arguments, so a call with an
  authorized recipient plus an unauthorized sibling field (a BCC) was
  allowed. **Confirmed live and exploitable pre-fix**:
  `decideAttribution('send_widgets', { to: 'alice@corp.example', bcc:
  'attacker@evil.example' }, ...)` returned `allow`. `decideAttribution` now
  fails closed, explicitly, whenever a sensitive action's tool name does not
  resolve to a documented contract at all (`resolveCanonicalTool(...) ===
  null`) — before evaluating destinations or generic gates. Canonical tools
  that are deliberately non-egress (`delete_file`, `transfer_funds`,
  `set_permission`, `search`, `read_file`) are unaffected; only a name Aegis
  has no registry entry for at all takes the new path. Regression coverage
  includes the exact PoC plus a property-style sweep of unregistered names
  satisfying every sensitivity-table pattern.
- **Security (P0, #40 — canary detection normalization weakness)**:
  `canaryDetection` normalized with a local `normalizeText` (whitespace
  collapse + lowercase only) instead of the canonical `normalizeMatchText`
  the provenance-matching pipeline uses (invisible-character stripping +
  NFKC/homoglyph folding). Since the canary value is rendered directly into
  the model's own context, a model instructed by injected content to
  reproduce "internal markers" with a zero-width character spliced in, or a
  Cyrillic/Greek look-alike substituted for a Latin letter, could reflect an
  altered canary that went undetected — silently defeating hidden-
  instruction-use detection. Both sides of the comparison now go through
  `normalizeMatchText`. Regression fixtures cover ZWJ/ZWNJ, zero-width
  spaces, Cyrillic confusables, and NFKC-foldable fullwidth characters.
  (Combining-diacritical-mark/"zalgo" obfuscation is a related but distinct
  gap, tracked separately as #46 — `normalizeMatchText` does not yet strip
  Unicode category Mn.)
- **Security (P0, #41 — JSON-in-string provenance blind spot)**:
  `argumentProvenanceMatch` and `contentSensitivityCheck` (`attribution.ts`)
  walked tool-call arguments with a hand-rolled traversal that, unlike the
  egress destination extractor, never parsed JSON embedded in string leaves.
  A sensitive value nested inside a JSON-stringified sub-field (or
  double-escaped) was checked as one opaque blob that essentially never
  matches a span verbatim, so it silently failed to attribute to its
  originating inert span — defeating the "arguments originate only from
  inert spans" gate for every sensitive tool other than the two
  (`send_email`, `http_post`) with bespoke egress handling. Both call sites
  now go through a single shared, guarded traversal (`src/traversal.ts`)
  that parses JSON-in-string (including double-escaped payloads), matching
  what `egress.ts` already did. `egress.ts` and the circular-reference guard
  now consume the same shared module, closing the drift between the two
  independently-evolving traversals for good.
- **Reliability (#44, closed as a side effect of #41)**: the shared
  traversal is depth-guarded (`TRAVERSAL_MAX_DEPTH`), so a deeply nested
  (but acyclic) `tool_args` payload no longer risks a stack-overflow crash
  in `collectLeafStrings`/`hasCircularReference`. `decideAttribution` also
  wraps the `JSON.stringify(args)` call used for args-canary detection (not
  depth-guarded, and Node's native circular-structure detection is not
  depth-limited either) and converts any failure there to the same typed,
  fail-closed `AegisAttributionError` the existing circular-reference guard
  uses, instead of an uncaught crash. (Caught on PR review by Copilot: an
  earlier version of this fix converted only `RangeError`, missing the case
  where a cycle's back-edge sits deeper than the traversal's depth budget —
  `hasCircularReference`'s capped walk misses such a cycle, but
  `JSON.stringify` still throws a `TypeError`, not a `RangeError`, since its
  own circular-structure detection isn't depth-limited. Fixed by catching at
  the single narrow call site instead of guessing at error subtypes.)
- The shared traversal's cycle guard uses an ancestor-path `Set` (matching
  `attribution.ts`'s existing correct semantics) rather than egress.ts's
  previous "seen anywhere" `Set`, which silently dropped a DAG's second,
  non-circular reference to a shared sub-object from destination extraction.

## [0.1.1] - 2026-09-02

### Fixed

- **Security (receipt/response tool-name integrity, audit follow-up)**: the
  harness signed the resolved canonical tool name into the receipt but returned
  the raw model-emitted name, so a caller could execute a call whose name
  differed from what the immutable receipt attests. `runAegis` now returns the
  canonical tool name; a regression asserts `response.tool_name ===
  receipt.model_action.tool_name` for allowed tool calls.
- **Security posture (default tool authorization narrowed, audit follow-up)**:
  the harness no longer expands semantic aliases (`mail`, `send_http`, `post`)
  to registered tools — registering one tool never implicitly authorizes model
  output under a different name; only case/punctuation variants of an explicitly
  registered name resolve. Contract CLASSIFICATION remains alias-aware, so a tool
  a deployment *does* register under such a name is still enforced correctly. A
  fixture that exercises an alias registers that name explicitly (new per-fixture
  `tools` field).
- **Release integrity (audit follow-up)**: publication is gated on a real tag
  **push** (`github.event_name == 'push'`), so a manual `workflow_dispatch`
  targeting a tag can no longer publish; and recovery no longer trusts version
  occupancy — it verifies npm's recorded `gitHead` matches the tagged commit
  before skipping a republish or creating a Release.
- **Docs/robustness (audit follow-up)**: corrected the threat model and README
  to state that destination EXTRACTION applies only lossless forms (invisible
  strip, homoglyph fold, percent-decode) — base64/hex/rot13 decoding is used on
  the span side for provenance tracing, not to pull destinations from a call.
  The package smoke test surfaces an actionable error if `tar` is unavailable,
  and `Destinations.hosts` was renamed `origins` to reflect that it holds URL
  origins, not bare hostnames.

- **Security (tool-name/contract confusion masking, audit follow-up)**: egress
  destination extraction inferred the email contract from a `/^send_/` name
  prefix, so `send_http` (which a lenient dispatcher and the tool oracle resolve
  to `http_post`) was treated as an email tool and its URL host never extracted —
  an authorized host masked an unauthorized one. Tool classification now goes
  through an explicit alias resolver (`src/tool-contracts.ts`) that mirrors the
  oracle: network aliases (`send_http`, `http_request`, `post`, `upload`,
  `webhook`, …) extract URL hosts, email aliases (`mail`, `sendmail`, …) extract
  recipients, and an unknown tool receives no positive egress authorization. The
  same resolver makes the sensitivity classifier and the harness alias-aware, so
  a documented alias reaches and is enforced as the tool it denotes instead of
  being blind-rejected. Added an `attacks/alias-contract/` fixture category and
  resolver unit tests covering every network/email alias and unknown `send_*`.
- **Security (egress destinations follow a per-tool contract, audit
  follow-up)**: egress destination extraction is now tool-aware and matches the
  tool's actual contract, kept in lock-step with the differential tool oracle.
  `send_email` transmits to email recipients (any address, at any depth) — a URL
  in its arguments is body payload, not a destination; `http_post` transmits to
  URL hosts — an email in its arguments is payload. This corrects an earlier
  over-broad extraction that treated any email/URL in any egress call as a
  destination, which over-blocked ignored payload fields and forced
  hand-declared oracle labels that contradicted the independent oracle. When a
  call carries destinations of more than one kind, authorization is evaluated
  across all kinds together (an authorized destination of one kind never
  licenses an unauthorized one of another).
- **Security (network destination granularity, audit follow-up)**: URL
  authorization compared bare hostname, so authorizing `https://host/status`
  also permitted `https://host:444/admin` or an `http://` downgrade.
  Destinations are now matched at **origin** granularity (scheme + host + port);
  path remains intentionally unbound (documented in the threat model).
- **Packaging (audit follow-up)**: `npm run build` now runs a path-validated
  `clean` step first, and the package smoke test builds explicitly then packs
  with `npm pack --ignore-scripts` — `npm pack` can select its file list before
  `prepack` runs, so relying on prepack's clean was not reliable across npm
  versions. The smoke test plants a `dist/testing/stale.js` regression and
  inspects the actual packed tarball (`tar -tzf`) to prove it is excluded.
- **Release evidence integrity (audit follow-up)**: the differential release
  gate now also fails on any label/oracle disagreement (a declared
  `oracle_sensitive` contradicting the independent oracle), so the confusion
  matrix can never certify release on unverified ground truth.
- **Release workflow (audit follow-up, #6)**: `workflow_dispatch` runs are now
  dry-run only (gate + build, never publish); publication happens only on a
  `vX.Y.Z` tag push and fails unless the tag equals `v` + the `package.json`
  version. The workflow now also **creates the GitHub Release from the same
  tag**, so npm + tag + Release align, and the publish step is **idempotent** —
  a re-run after a partial failure skips the already-published version and
  repairs the missing Release. Removed the silent OIDC→token fallback; trusted
  publishing only.
- **Security (recipient/destination authorization, #27/#28/#29)**: a sensitive
  egress call (`send_email`, `http_post`) that carried an authorized recipient
  *plus* an extra, unauthorized destination — a BCC/CC, a nested routing field,
  a JSON-in-string blob, a header-injected `Bcc:` line, a CSV list, an array
  element, or an encoded/homoglyph address — was allowed, because the authorized
  recipient supplied user intent and the smuggled destination need not appear in
  any span. New `src/egress.ts` extracts every destination a downstream tool
  would actually consume (deep traversal, JSON-in-string incl. double-escaped,
  comma/newline lists, homoglyph folding, percent/base64/hex/rot13 decoding) and
  requires each to be authorized by the user session. The independent
  differential benchmark's dangerous false negatives went from 21 (23.6% FN
  rate) to **0 (100% recall)**; the genuine over-block rate dropped to 7.7%.
- **Security (span identity, finding #2)**: the Ed25519 span signature did not
  cover `span.id`, so an attacker holding a serialized signed span could rewrite
  its id — its identity in provenance matches and receipts — without
  invalidating the signature. The signed payload is now versioned
  (`aegis-span-sig-v2`) and binds `id`, `trust`, and `parent_span` in addition
  to origin/source_uri/ingested_at/content. Tamper tests cover every
  security-relevant span field.
- **Security (receipt chain concurrency, #10)**: `ReceiptStore.appendReceipt`
  was read-modify-write with no serialization, so two concurrent appends could
  read the same chain tail and write receipts referencing the same previous
  hash, forking the chain. Appends are now serialized per store; a concurrency
  test fires 25 simultaneous appends and asserts a single valid chain with
  distinct predecessors.
- **Tooling / usability (#32, partial)**: the harness now resolves a
  case/punctuation variant of a registered tool name (`SendEmail`,
  `send-email`) to its canonical registered tool instead of rejecting it, while
  a genuinely different name still fails closed. Broader semantic aliasing
  remains a documented limitation.
- **Security**: `argumentProvenanceMatch` aggregated the actionable/inert
  match signal across all argument values in a tool call into a single
  flag, so one benign argument value that happened to match a trusted
  (actionable) span could mask that a different, dangerous argument value
  in the same call matched only an untrusted (inert) span — allowing a
  call that should have been blocked. Fixed by tracking inert-only-ness
  per argument value (`anyValueInertOnly`) instead of aggregating across
  the whole call. Reproduced and verified against the README's own worked
  exfiltration example.
- `wrapSpan` now validates that span `content` is a string and throws a
  typed `AegisSigningError` immediately, instead of signing invalid input
  and crashing later with an opaque `TypeError` deep inside
  provenance-matching internals.
- **Security**: closed two findings from the aletheia-redteam-kit audit —
  circular `tool_args` could crash attribution with an uncaught `RangeError`
  instead of failing closed (#11), and untrusted content could forge literal
  inert-span frame delimiters in the model-facing rendering (#13; the
  provenance/intent decision boundary itself was unaffected either way, this
  is defense-in-depth framing hygiene). Also bumped `nanoid` and `postcss`
  (transitive dev dependencies) to close two HIGH `npm audit` advisories
  surfaced by the same audit.

### Added

- Content-based sensitive-action classification (`contentSensitivityCheck` in
  `src/attribution.ts`): a tool call is now classified sensitive from what its
  *arguments* contain — secret/credential material, path-traversal sequences,
  direct requests for secret material, or identity/system-framing override
  attempts — independent of the tool's name. Closes a gap where a call to an
  innocuous-sounding tool (`search`, `read_file`) carrying exfiltration-shaped
  arguments never reached the provenance/user-intent checks at all.
- `src/normalize.ts`: text normalization for provenance matching — invisible-
  character stripping, Cyrillic/Greek homoglyph + NFKC folding, and
  base64/hex/rot13 decode-candidate expansion. `argumentProvenanceMatch` now
  matches against these normalized/decoded representations of each span, not
  just its literal text, recovering the byte-level link when a model decodes
  an obfuscated span or folds confusable characters when repeating it.
- Correction-as-escalation detection for free-text model responses
  (`textEscalationCheck` in `src/attribution.ts`): flags — does not block — a
  response that asserts a technical correction about a tool/system's scope
  and then supplies offensive-tooling artifacts later in the same response.
- `docs/threat-model.md`: what Aegis defends against, the behavioral contract
  for integrators, and the residual risks/non-goals it does not cover.
- `examples/demo-narrative.ts` (`npm run demo:narrative`): a three-beat
  scenario — a legitimate action allowed, the same tool blocked when the
  request originates from injected content instead, and the resulting
  receipt chain verified — for the README/demo recording.
- New `attacks/tool-args/` fixture category (origin `tool-result`) exercising
  the content-based classifier via `search`/`read_file` calls — neither
  sensitive by name — plus new `encoded/` fixtures for decode-and-retype and
  homoglyph evasion. Corpus grows from 87 to 99 fixtures (cap remains 100).
  `VulnerableModelClient` gained matching trigger patterns and a decode/fold
  fallback pass so the benchmark exercises both additions end to end.

### Changed

- **Release gate (finding #4)**: the differential adversarial benchmark now has
  an explicit, machine-checked threshold (`RELEASE_GATE`): 0 false negatives, 0
  crashes, and effect false-positive rate ≤ 10%. It runs in CI
  (`npm run benchmark:differential:gate`) and in `prepublishOnly`, so a green
  build means the adversarial suite passed, not only the older provenance
  regression suite.
- **Packaging (finding #7)**: `src/testing/**` (differential, tool-oracle,
  real-model harnesses) is excluded from the published `dist`; the tarball ships
  only `dist/` (sans testing), `README.md`, and `LICENSE`. A clean-pack smoke
  test (`npm run smoke:package`) packs, installs into an isolated consumer,
  imports the ESM entrypoint, and asserts the surface — wired into CI and
  `prepublishOnly`.
- **CI hardening (finding #7)**: GitHub Actions are pinned by full commit SHA
  instead of floating `@v4` tags. A provenance-producing `release` workflow
  (`npm publish --provenance`) and a `RELEASING.md` checklist were added so the
  npm package, git tag, and GitHub Release identify the same commit (finding
  #6) and the package can carry trusted-publisher provenance.
- Benchmark and README documentation now state explicitly that
  `npm run benchmark` measures provenance/sensitivity enforcement against a
  fixed, deterministic surrogate — not real-model injection resistance or an
  adversarial red-team result — and points to the real-model evaluation and
  broader adversarial validation as the appropriate next checks.

## [0.1.0] - 2026-07-11

Initial public release of the Aegis provenance-enforcing context proxy.

### Added

- Deterministic prompt-injection enforcement: every input chunk is wrapped
  in a signed span, untrusted origins are marked inert, and sensitive tool
  calls whose arguments trace only to inert content are blocked before
  execution.
- Cryptographic attribution with Ed25519: spans are signed and verified on
  use, and trust is re-derived from origin at verification time so a tampered
  trust field fails closed without ever calling the model.
- Tamper-evident audit trail: each request emits a hash-linked receipt, and
  the append-only receipt store verifies the full chain before adding a new
  entry.
- Canary detection: unique tokens are injected into inert spans to flag when
  hidden untrusted content is echoed into tool arguments or model output.
- Attack validation benchmark: 87 fixtures across web, HTML, Markdown,
  encoded, memory, and tool-result vectors, with a 95% accuracy merge gate
  that fails CI if any fixture regresses or crashes the pipeline.
- OpenAI-compatible real-model evaluation harness: drives any
  OpenAI-compatible endpoint over the attack and benign corpora to report
  baseline ASR, framed ASR, enforcement rate, benign allow rate, and
  format-compliance rate per model.

[0.1.1]: https://github.com/holeyfield33-art/aegis-provenance/releases/tag/v0.1.1
[0.1.0]: https://github.com/holeyfield33-art/aegis-provenance/releases/tag/v0.1.0
