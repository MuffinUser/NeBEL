# Spec 09 — `nebel status`

Read-only inspection and CI gate. See USER_INTERACTIONS.md § 3.

## Acceptance criteria

- **AC-9.1**: reports whether the local git filter is registered
  (registered / not registered).
- **AC-9.2**: reports whether the locally registered key verifies against
  the config's canary (verified / not verified / no key registered) —
  without requiring any real secret file to be present.
- **AC-9.3**: for every file matching a `mode: value` rule, reports each
  configured field as `encrypted` (well-formed `ENC[...]` tag present) or
  `PLAINTEXT` (field exists but isn't encrypted).
- **AC-9.4**: for every file matching a `mode: file` rule, reports the
  whole file as `encrypted` or `PLAINTEXT`.
- **AC-9.5**: exit code is non-zero if any tracked field/file is
  `PLAINTEXT`, or if the filter isn't registered.
- **AC-9.6**: exit code is zero when all tracked fields/files are
  encrypted and the filter/key check out.
- **AC-9.7**: output never includes decrypted secret values — only file
  paths, field paths, and state labels.
- **AC-9.8**: a field present in a file but not listed in that rule's
  `encrypt` is reported separately (e.g. "not tracked") rather than being
  conflated with `PLAINTEXT`, so users can distinguish "forgot to encrypt
  this" from "this was never supposed to be encrypted."
- **AC-9.9**: every encrypted field/file is reported with its key version
  (from its tag), alongside its `encrypted` state.
- **AC-9.10**: `status` summarizes, per key version found anywhere in the
  tracked tree, how many fields/files still depend on it — so a team can
  tell when a version has zero dependents left and its password is safe
  to discard (spec 11 AC-11.10 for how to force the last stragglers off).
- **AC-9.11**: a field/file whose declared version isn't in the local
  keyring is reported distinctly (e.g. "needs key version N — not
  registered locally"), not conflated with `PLAINTEXT` or a generic
  error, and counts toward the non-zero exit code (extends AC-9.5) since
  it means that content can't currently be verified on this machine.
