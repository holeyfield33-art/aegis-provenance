# Releasing aegis-provenance

This project is a security-enforcement library. A release is only allowed to go
out when the adversarial evidence supports the claim. This document is the
checklist and the rationale.

## Release gate (must all pass)

Run locally, or let CI + `prepublishOnly` run them:

| Check | Command | Threshold |
| --- | --- | --- |
| Type check | `npm run typecheck` | clean |
| Unit tests | `npm test` | all pass |
| Original benchmark | `npm run benchmark` | accuracy ≥ 95% (currently 99/99), 0 crashes |
| **Differential security gate** | `npm run benchmark:differential:gate` | **0 false negatives, 0 crashes, effect-FP rate ≤ 10%** |
| Clean-pack smoke test | `npm run smoke:package` | passes; `dist/testing` not shipped |
| Production audit | `npm audit --omit=dev` | 0 high/critical |

`prepublishOnly` chains the type check, unit tests, both benchmarks (under the
gate), the build and the package smoke test, so a plain `npm publish` cannot
skip them.

### What the differential gate measures

The differential benchmark (`src/testing/differential.ts`) scores Aegis's real
verdict against an independent tool oracle that models what a downstream tool
would actually do. The gate is defined in code (`RELEASE_GATE`) and is
fail-closed on security:

- **False negatives = 0.** A sensitive operation reaching the tool un-blocked is
  the one thing this product must never do.
- **Crashes = 0.** An unanalyzable call is a correctness bug.
- **Effect false-positive rate ≤ 10%.** Measured over benign calls with a
  concrete resolved effect (genuine over-blocks ÷ (genuine over-blocks + true
  negatives)). Degenerate surrogate no-ops — a sensitive-class tool the
  surrogate emitted with no resolvable destination — are reported for context
  but excluded from the gate, because they are attack payloads that happen to
  lack a target, not realistic benign requests. The raw FP rate (including those
  no-ops) is printed alongside.

## Provenance: one commit, three places (finding #6)

The npm package, the git tag, and the GitHub Release **must identify the same
commit**. The published 0.1.0 did not (npm metadata and tag `v0.1.0` pointed at
different commits ~two weeks apart), which makes the package non-reproducible
from the release tag. Do not repeat this.

The supported way to guarantee it is the `release` workflow
(`.github/workflows/release.yml`): pushing a `vX.Y.Z` tag builds and publishes
from exactly that commit and attaches **npm build provenance**
(`npm publish --provenance`). The workflow **fails** if the git tag does not
equal `v` + the `package.json` version, so npm, tag and release cannot drift.
Running the workflow manually (`workflow_dispatch`) is a **dry run only** — it
runs the full gate and builds/packs but never publishes, so a manual run cannot
push an arbitrary branch to npm. A manual `npm publish` from a laptop does **not**
get trusted-publisher provenance — prefer the workflow.

If you must publish manually:

1. Check out the exact commit you will tag; ensure the working tree is clean.
2. Run the full release gate above.
3. `npm publish` from that commit.
4. Create the git tag on that same commit and push it.
5. Create the GitHub Release from that same tag, with notes drawn only from
   verified results (see `CHANGELOG.md`).

## One-time repository controls (finding #7)

These are GitHub settings, not code, and must be configured by a repo admin:

- **Branch protection on `main`:** require the `ci` and `benchmark` checks to
  pass, require PR review, and disallow direct pushes.
- **npm trusted publisher** for this repo + the `release` workflow, so
  provenance can be attached via OIDC. The workflow deliberately has **no
  token fallback**: if trusted publishing is not configured, the publish step
  fails loudly rather than silently using a long-lived token.

## Not shipped to consumers

The published tarball contains only `dist/` (excluding `dist/testing`),
`README.md`, `LICENSE`, and package metadata. The differential, tool-oracle and
real-model harnesses under `src/testing/**` are dev-only tooling run via `tsx`
from source and are excluded from the build (`tsconfig.build.json`). The
`smoke:package` test asserts this.
