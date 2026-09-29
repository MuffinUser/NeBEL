# Spec 08 — `nebel add`

Register a new file pattern and/or field in the committed config. See
USER_INTERACTIONS.md § 2.

## Acceptance criteria

`add file` and `add field` are separate subcommands rather than one
command with a `--field` flag: they produce different kinds of rule, take
different arguments, and are chosen for different reasons — whole-file for
blobs with no readable structure, per-value for config you still want to
diff. A bare `add <glob>` names neither and is refused with usage.

- **AC-8.1**: `add file <glob>` creates a new `mode: file` rule for that
  glob in `.nebel.yaml`, and wires the glob to the filter in
  `.gitattributes`.
- **AC-8.2**: `add field <file> <path>...` with no existing rule for that
  file creates a `mode: value` rule with those paths in `encrypt`.
- **AC-8.3**: `add field` against an existing `mode: value` rule for the
  identical pattern appends the new paths to its `encrypt` list.
- **AC-8.4**: every path is checked against the named file before the rule
  is written. A path that doesn't resolve is refused there and then, not
  left to fail on whoever first stages the file.
- **AC-8.5**: re-running either subcommand with an already-present
  glob/field combination is a no-op — no duplicate rules, no duplicate
  entries in `encrypt`.
- **AC-8.6**: `add field` against an existing `mode: file` rule for the
  identical pattern fails with a clear "mode conflict" error (mirrors spec
  04 AC-4.6) rather than silently mutating the rule, and vice versa.
- **AC-8.7**: `add field <file>` with no paths lists the file's scalars,
  with their values, for interactive selection — accepting numbers, a
  comma- or space-separated list, or `all`. Values already encrypted or
  already configured are not offered. Unparseable input is refused rather
  than partially applied, since a silently dropped selection would leave a
  field the user believed they had protected.
- **AC-8.8**: with no paths and no terminal to prompt on, `add field`
  fails with an error naming the paths-as-arguments form, rather than
  hanging on a read.

- **AC-8.9**: writing the updated config preserves unrelated existing
  rules, their field order, and (as much as the YAML library allows)
  formatting/comments.
- **AC-8.10**: after `add` succeeds, the new rule is immediately visible to
  `nebel status` (spec 09) and to the git filter driver (spec 06) —
  no separate reload step needed.
- **AC-8.11**: after writing the rule, `add` re-encrypts every file
  already tracked and matching it — a `git add --renormalize` equivalent,
  scoped to files the new rule (or an existing rule it just added a field
  to) resolves to, per spec 04's `MatchRule` precedence rather than a raw
  pathspec match on the glob itself. Without this, a file that was
  already tracked and unchanged in the working tree stays plaintext
  indefinitely: git only re-invokes the clean filter for a path when it
  can't trust its own cached stat info for that path, and an
  already-settled, already-tracked file commonly gives it no reason not
  to, a new `.gitattributes` line notwithstanding. A pattern matching no
  tracked file yet — the common case for a brand new rule — is not an
  error. Files it does re-encrypt are reported, along with a reminder
  that this only protects future commits: content already committed in
  plaintext is still recoverable from history.
