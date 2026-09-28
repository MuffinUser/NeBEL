# nebel — Specs

Each file is one implementable, testable unit, derived from
`../REQUIREMENTS.md` and `../USER_INTERACTIONS.md`. Acceptance criteria
(AC) are atomic and map roughly 1:1 to a unit/integration test.

## MVP scope

First implementation pass covers **whole-file encryption only**. Per-value
(SOPS-style) encryption is deferred to a later phase. Concretely:

- `01-key-derivation.md` — full scope, unchanged.
- `02-encryption-primitive.md` — full scope, unchanged.
- `03-value-encoding.md` — only the whole-file case: the `ENC[...]` tag
  wraps the entire file's ciphertext; `type:` field is not needed for
  whole-file blobs (there's no native scalar type to preserve).
- `04-config-file.md` — only `mode: file` rules; `encrypt` list and
  `mode: value` are deferred.
- `05-format-handlers.md` — **entirely deferred** (only needed for
  per-value mode).
- `06-git-filter-driver.md` — only the whole-file clean/smudge path
  (AC-6.1, not AC-6.2); AC-6.3 through AC-6.9 still apply.
- `07-cli-init.md` — full scope, unchanged.
- `08-cli-add.md` — only `add <glob>` (no `--field`); field-related ACs
  deferred.
- `09-cli-status.md` — only the whole-file encrypted/PLAINTEXT reporting
  (AC-9.4); per-value ACs (9.3, 9.8) deferred.
- `10-cross-platform-build.md` — full scope, unchanged.
- `11-cli-rotate.md` — added post-MVP, once per-value mode (05/06/08) was
  already implemented; not part of the original whole-file-only MVP pass
  above. Full scope.

## Suggested implementation order (dependency order)

1. `01-key-derivation.md` — password → AES-SIV key material
2. `02-encryption-primitive.md` — AES-256-SIV encrypt/decrypt + AAD
3. `03-value-encoding.md` — `ENC[...]` tag format
4. `04-config-file.md` — `.nebel.yaml` rules parsing
5. `05-format-handlers.md` — YAML/JSON/.env/.properties path resolution + in-place edit
6. `06-git-filter-driver.md` — clean/smudge, ties 1–5 together
7. `07-cli-init.md` — bootstrap/join
8. `08-cli-add.md` — register new files/fields
9. `09-cli-status.md` — inspection/CI gate
10. `10-cross-platform-build.md` — build/release
11. `11-cli-rotate.md` — rotate the shared password/key; depends on
    01–04 (key derivation, encryption, canary) and 06/07 (filter, init)

Each later spec depends on all earlier ones being green. Within a spec
file, ACs can usually be tested independently of each other.

## Conventions used in each spec

- `AC-N.M`: numbered, testable, single-behavior acceptance criterion.
- Every AC is phrased so a failing test has one unambiguous cause.
- "Clear error" means: a typed/wrapped error a caller can check, no panic,
  no silent fallback to wrong-but-plausible behavior.
