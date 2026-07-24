# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[0.1.0]: https://github.com/holeyfield33-art/aegis-provenance/releases/tag/v0.1.0
