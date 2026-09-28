# Spec 06 — Git filter driver (clean/smudge)

Ties specs 01–05 together into the `clean`/`smudge` commands git invokes.
See REQUIREMENTS.md § Git integration, § Bootstrapping & no-key operation.

## Acceptance criteria

- **AC-6.1 Whole-file clean**: for a `mode: file` rule, `clean` encrypts
  all of stdin and writes a single `ENC[...]`-wrapped ciphertext blob to
  stdout.
- **AC-6.2 Per-value clean**: for a `mode: value` rule, `clean` parses the
  file (via spec 05), encrypts only the configured paths in place, and
  passes everything else through unchanged.
- **AC-6.3 Idempotent clean**: running `clean` twice on the same input,
  with the same registered key, produces byte-identical output both
  times — end-to-end confirmation of the determinism requirement.
- **AC-6.4 No double-encryption**: `clean` run on input where the target
  path(s) already contain a well-formed `ENC[...]` tag leaves those values
  unchanged (spec 03 AC-3.3 detection used here). This is also the safety
  net for a value `clean` can't decrypt because its key version is
  missing locally (AC-6.11 fired on the last checkout): it stays as-is
  rather than getting double-wrapped.
- **AC-6.5 Exact reversal**: `smudge(clean(input)) == input` byte-for-byte
  when the correct key is registered, for both modes.
- **AC-6.6 No-key passthrough**: when the local keyring is *empty* (no
  `nebel init` has ever run on this clone), both `clean` and `smudge`
  pass input through **unchanged** — no error, no partial processing, no
  non-zero exit that would abort the git operation. Once the keyring
  holds at least one version, a value needing a version that isn't in it
  is AC-6.11, not this — passthrough is only for "nothing registered at
  all," not "missing this particular version."
- **AC-6.7 Tolerant smudge**: `smudge` on a value that isn't a well-formed
  `ENC[...]` tag (e.g. a value-mode field that's still plaintext) passes
  it through unchanged rather than erroring — needed so partially
  migrated files don't break checkout.
- **AC-6.8 Real git integration**: in a temporary real git repository with
  `.gitattributes` wired to the filter and the local filter registered,
  `git add` + `git commit` + `git checkout` produce the expected
  encrypted blob in the git object store and the expected decrypted
  content in the working tree.
- **AC-6.9 Tamper surfaced**: `smudge` on a well-formed but tampered
  `ENC[...]` tag (fails spec 02 AC-2.6 authentication) fails with a clear
  error rather than emitting corrupted plaintext into the working tree.
- **AC-6.10 Current-version key integrity**: if the local keyring holds
  an entry for the config's *current* `key_version`, that entry must
  verify against the current canary. A mismatch is a clear error naming
  `nebel init` — it indicates local corruption or a keyring entry that
  was never actually validated, not an expected state (unlike AC-6.11,
  which is routine after rotation).
- **AC-6.11 Unknown key version surfaced**: `smudge` on a tag whose
  declared version isn't in the local keyring fails with a clear error
  naming the missing version and `nebel init --version N` as the fix —
  never passthrough (that's only the empty-keyring case, AC-6.6), and
  never a guess.
- **AC-6.12 Clean always targets the current version**: `clean` encrypts
  every value/file it touches using the config's current `key_version`,
  regardless of what version that value previously carried. This is what
  makes rotation converge lazily as files are naturally edited (spec 11)
  — no repo-wide rewrite step exists or is needed.
- **AC-6.13 Smudge selects by tag version**: `smudge` decrypts each
  value/file using the keyring entry matching *that value's own*
  tag-declared version, not the config's current version — a file whose
  fields span several versions decrypts correctly as long as the keyring
  holds all of them.
