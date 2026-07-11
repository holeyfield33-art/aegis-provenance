# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
