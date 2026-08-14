# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-08-12

### Fixed

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
