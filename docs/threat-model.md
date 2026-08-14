# Threat Model

This document states what Aegis Provenance defends against, the behavioral
contract an integrator can rely on, and — just as importantly — the residual
risks it does **not** cover. Read the residual-risk section before you describe
Aegis as "secure" anywhere public.

Aegis is pre-1.0. This threat model describes the `0.1.x` line.

## 1. What Aegis is

Aegis is a **provenance-enforcing context proxy** and **egress gate** for LLM
tool-calling agents. It does one job: decide whether a model's proposed tool
call is attributable to trusted intent, and block it when it is not.

It is **not** a general policy engine, a content filter, or a sandbox. It does
not decide what a user is *allowed* to do. It decides whether an action traces
back to a trusted origin (`system` or `user-session`) or to untrusted content
(`inert` spans: retrieved web pages, files, tool results, memory, prior model
output). An action sourced only from untrusted content, on a sensitive tool, is
blocked.

## 2. Trust model

Every input chunk becomes a **span** at ingest. Each span carries an `origin`,
and `trust` is *derived* from origin — never set by the caller:

| Origin | Derived trust |
| --- | --- |
| `system` | `actionable` |
| `user-session` | `actionable` |
| `tool-result`, `untrusted-web`, `untrusted-file`, `memory`, `model` | `inert` |

Spans are signed with Ed25519 over `origin`, `source_uri`, `ingested_at`, and a
hash of `content`. `trust` is **not** in the signed payload by design: it is
recomputed from the signed `origin` at verify time (`verifySpanIntegrity`) and
rejected on mismatch. A wire- or store-tampered `trust` value therefore fails
verification — either the `origin` was altered (breaking the signature) or the
recomputed trust disagrees with the stored one. `runAegis` verifies every span,
including externally supplied `signedSpans`, before assembling context.

**This holds only as long as `deriveTrust` remains a pure function of `origin`.**
Any future change that lets trust depend on caller-supplied state would reopen
the escalation path. This is a deliberate invariant, not an implementation
detail.

## 3. What Aegis defends against

- **Prompt injection via untrusted content.** Injected instructions arrive in
  `inert` spans. A tool call whose arguments originate only from inert spans, on
  a sensitive action, is blocked (`anyValueInertOnly`).
- **Sensitive tool calls without user intent.** A sensitive action requires
  user-session intent that references the action or its arguments. Bare
  existence of a user-session span is not intent (the harness always injects
  one).
- **Argument-masking.** Provenance is evaluated **per argument value**, so a
  benign field matching a trusted span cannot mask a sibling field sourced only
  from an untrusted span.
- **Content-shaped exfiltration on innocuously-named tools.** Arguments
  containing secret-key-shaped names, credential tokens, credential file paths,
  path-traversal sequences, or identity/system-framing override make an action
  sensitive regardless of the tool's name (`contentSensitivityCheck`), routing
  it through the same intent gate.
- **Obfuscated repetition of untrusted content.** Provenance matching compares
  against decoded/folded representations (base64, hex, rot13, homoglyphs), so a
  model that decodes an injected payload before using it is still linked to the
  inert source.
- **Hidden-instruction use.** Each inert span is framed with a unique canary
  token. A canary surfacing in tool arguments blocks a sensitive action; a
  canary in free-text output is flagged as read-only exfiltration evidence.
- **Frame-delimiter breakout.** Literal inert-frame delimiters inside untrusted
  content are escaped before rendering, so injected content cannot forge a
  "trusted" frame.
- **Correction-as-escalation.** A free-text response that asserts a technical
  correction about a tool/system's scope and then supplies offensive-tooling
  artifacts after that correction is flagged for review.
- **Tamper-evident audit.** Every request emits a hash-linked receipt; the chain
  is verified before append and can be re-verified end to end.

## 4. Behavioral contract for integrators

If you build on Aegis, you can rely on the following:

1. **Trust is assigned at ingest, from origin.** You must classify each input's
   `origin` correctly. Aegis cannot know that a "tool result" is actually
   attacker-controlled if you label it `user-session`. Correct origin labeling
   is *your* responsibility and the foundation the entire model rests on.
2. **Only `system` and `user-session` are actionable.** Everything a connector
   returns is `inert`. As you add connectors, more of your context becomes
   inert — this is correct and intended.
3. **Sensitive actions require referencing user intent.** For a sensitive tool
   call to be allowed, the user-session content must reference the action name,
   an argument value, or carry an explicit `intent:<tool_name>` marker.
4. **The low-friction fallback is conditional.** Aegis allows bare token overlap
   between the action name and user text (so "email the report to my manager"
   works when the model resolves the recipient from context) **only when no
   inert span is present anywhere in the context.** The moment any untrusted
   content is in scope, this fallback is disabled and stronger evidence is
   required. As you add connectors, the situations where this fallback applies
   shrink toward zero — plan for user intent to be expressed explicitly.
5. **`block` throws; `flag` and `allow` return.** A blocked action raises
   `AegisBlockedError` carrying the receipt ID. Flags are advisory and do not
   halt execution — they are for the receipt trail and human review.
6. **Set a persistent signing key in production.** With no `AEGIS_SIGNING_KEY`
   (or `AEGIS_SIGNING_KEY_FILE`), Aegis generates an ephemeral per-process key.
   Span signatures then cannot be verified across restarts or processes. For any
   deployment that persists or transports spans, set a stable key.

## 5. Residual risks and non-goals

These are the things Aegis does **not** protect against in `0.1.x`. State these
alongside any "launch-ready" claim.

- **Heuristic content classification has gaps.** `contentSensitivityCheck`
  inspects *raw* argument strings, not their decoded representations. An
  obfuscated secret name or path-traversal sequence (base64/hex/homoglyph) on a
  non-name-sensitive tool can evade classification, leaving the action
  non-sensitive so the provenance gate never engages. The regex patterns are a
  floor, not a proof. The durable fix is upstream resolution of sensitive
  arguments into host-derived intent markers rather than pattern-matching model
  output; that work is on the roadmap.
- **Receipts are hash-linked, not externally anchored.** The chain is
  tamper-*evident* only against an appender that plays by the rules. Anyone with
  write access to the receipt store can recompute the entire chain. External
  anchoring / signed receipts is a roadmap item; until then, treat the store as
  needing its own integrity controls.
- **Aegis gates egress, it does not sandbox execution.** A `flag` verdict does
  not stop anything. If your tools have side effects, a flagged-but-not-blocked
  action still runs.
- **The trust model assumes correct origin labeling.** Everything follows from
  the host classifying `origin` correctly at ingest. Mislabeling untrusted
  content as `user-session` defeats the system entirely, and Aegis cannot detect
  that mislabeling.
- **Red-team coverage is bounded by test fidelity.** Published red-team results
  report *"no bypass found among attacks the harness could actually weaponize."*
  Mutation-space coverage is now broad: a 36,000+ execution sweep (full catalog
  plus a 4-generation evolutionary rephrase-and-retry attacker) exercised every
  mutation strategy the kit generates — synonym substitution, roleplay,
  bilingual reframing, encoding-wrapping, step-escalation — with zero confirmed
  bypasses of the provenance/intent gate. The residual gap is specifically a
  mock-fidelity ceiling: no attacker in-harness can drive the mock model to
  *weaponize* a reconstructed instruction into a sensitive tool call, so the
  reconstruction class remains formally untested against the gate. See
  `docs/audits/2026-08-13-agentic-sweep.md` and `docs/audits/` generally for
  the current baseline and its methodology caveats.

## 6. Assumptions

- The host controls the Ed25519 signing key and its distribution.
- The host assigns `origin` correctly and does not label untrusted content as
  `system` or `user-session`.
- The sensitivity table reflects the deploying application's actual sensitive
  tools; the defaults are a starting point, not a complete policy.
- Consumers of receipts verify the chain rather than trusting individual
  receipts in isolation.

## 7. Reporting

Security issues: see [`SECURITY.md`](../SECURITY.md). Report privately via the
repository Security tab; do not open public issues for vulnerabilities.
