---
name: Attack fixture
about: Propose a new attack fixture for the benchmark corpus
title: "[fixture] "
labels: fixture
assignees: ''
---

## Attack description

Describe the injection technique and what the attacker is trying to make the
model do.

## Category

Which `attacks/<category>/` does this belong to?

- [ ] `encoded`
- [ ] `html`
- [ ] `markdown`
- [ ] `memory`
- [ ] `tool-args`
- [ ] `tool-results`
- [ ] `web`
- [ ] new category (name it):

## Expected verdict

- [ ] `block` — Aegis should stop this
- [ ] `allow` — benign / benign-but-adjacent content Aegis should permit

## Fixture JSON

Provide the fixture in the exact schema (a single object; `name` unique within
its category):

```json
{
  "name": "category-short-description",
  "attack": "The untrusted content to wrap as an inert span.",
  "expected_verdict": "block"
}
```

## Notes

For a `block` fixture, confirm the `attack` text contains a sensitive action and
a recognizable target the deterministic egress checks can catch. See
[CONTRIBUTING.md](../../CONTRIBUTING.md#contributing-attack-fixtures).
