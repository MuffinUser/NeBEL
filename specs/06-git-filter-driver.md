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
  missing locally (AC-6.11's passthrough, from the last checkout or
  smudge): it stays as-is rather than getting double-wrapped — and,
  since nothing here needs encrypting, doing this never requires the
  current version's key either (AC-6.12).
- **AC-6.5 Exact reversal**: `smudge(clean(input)) == input` byte-for-byte
  when the correct key is registered, for both modes.
- **AC-6.6 No-key passthrough**: when the local keyring is *empty* (no
  `nebel init` has ever run on this clone), both `clean` and `smudge`
  pass input through **unchanged** — no error, no partial processing, no
  non-zero exit that would abort the git operation, no warning printed
  either (there is nothing yet to warn about — this is simply what a
  clone before its first `nebel init` looks like). Once the keyring holds
  at least one version, a value needing a version that isn't in it is
  AC-6.11, not this: same passthrough, but now worth a warning, since
  something (usually `nebel rotate`, spec 11) *has* moved and this clone
  hasn't caught up.
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
- **AC-6.11 Unknown key version passes through, with a warning**: `smudge`
  on a well-formed tag whose declared version isn't in the local keyring
  leaves it unchanged — the same passthrough as the empty-keyring case
  (AC-6.6) — rather than aborting the git operation that triggered it. It
  is not silent, though: it prints a warning to stderr naming the path
  (and field, for `mode: value`), the version needed, and the fix — `nebel
  init` with the new password when the missing version is the config's
  *current* one (the routine case right after someone else's `nebel
  rotate`), otherwise `nebel init --version N`. This is what lets a plain
  `git pull` after a teammate's rotation succeed instead of failing
  outright: the changed files land as ciphertext, exactly as "clean" as a
  fresh clone before its first `nebel init` would see them, and a
  subsequent `nebel init` with the new password decrypts them in place
  like any other join. Never a guess, either way: this is still a
  well-formed tag naming a real version, just one this clone hasn't
  fetched — distinct from a malformed tag or a failed decryption (AC-6.9),
  both of which remain hard errors.
- **AC-6.12 Clean always targets the current version**: `clean` encrypts
  every value/file it touches using the config's current `key_version`,
  regardless of what version that value previously carried. `nebel
  rotate` (spec 11) relies on this to eagerly re-encrypt everything it
  can onto the version it just minted; anything left over still converges
  the same way, lazily, the next time it's naturally edited. The current
  version's key is required only when something in the input actually
  still needs encrypting (AC-6.4): a path that's already fully tagged
  needs no key at all, current or otherwise, so git's routine
  re-invocation of `clean` on already-converged content — refreshing a
  racily-clean index entry, `git add -u`, `git status`, `git add
  --renormalize` — never hard-fails just because a clone has fallen
  behind a rotation it hasn't rejoined yet.
- **AC-6.13 Smudge selects by tag version**: `smudge` decrypts each
  value/file using the keyring entry matching *that value's own*
  tag-declared version, not the config's current version — a file whose
  fields span several versions decrypts correctly as long as the keyring
  holds all of them.
