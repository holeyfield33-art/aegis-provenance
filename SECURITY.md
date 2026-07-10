# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | ✅        |

Aegis is pre-1.0. Only the `0.1.x` line receives security fixes.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's private vulnerability
reporting:

> Repository **Security** tab → **Report a vulnerability**

**Do not open public issues for security vulnerabilities.** Public disclosure
before a fix is available puts users at risk.

When reporting, please include:

- A description of the issue and its impact.
- A minimal reproduction (a fixture, span sequence, or code snippet is ideal).
- The affected version and your environment (Node version, OS).

## Response expectation

We aim to acknowledge every valid report **within 72 hours**. After
acknowledgment we will work with you on a fix and a coordinated disclosure
timeline.

## Scope

Aegis is a runtime enforcement floor around tool execution. Its security
guarantees are about the **deterministic egress checks**, not about model
behavior.

**In scope (welcome):**

- Novel bypasses of the deterministic egress checks — for example, getting a
  sensitive tool call through despite arguments originating only from inert
  spans, defeating the canary detection, or forging/altering a span or receipt
  such that verification still passes.
- Signature or receipt-chain verification flaws.
- Any way to make Aegis emit an `allow`/`flag` verdict where the deterministic
  rules should have produced `block`.

**Out of scope (documented limitation, not a vulnerability):**

- Attribution-bypass via paraphrase evasion. Aegis attribution is an
  approximation, not ground-truth attention; a model may still comply with
  attacker input that has been paraphrased so it no longer matches provenance
  signals. This is called out in the README "Honest limitations" section and is
  a known design boundary — the enforcement layer is a floor, not a guarantee of
  model intent.

If you are unsure whether something is in scope, report it privately anyway and
we will help triage.
