# Spec 08 — `strucrypt add`

Register a new file pattern and/or field in the committed config. See
USER_INTERACTIONS.md § 2.

## Acceptance criteria

- **AC-8.1**: `add <glob>` with no `--field` creates a new `mode: file`
  rule for that glob in `.strucrypt.yaml`.
- **AC-8.2**: `add <glob> --field <path>` with no existing rule for that
  glob creates a new `mode: value` rule with `encrypt: [<path>]`.
- **AC-8.3**: `add <glob> --field <path>` against an existing `mode:
  value` rule for the identical glob appends `<path>` to its `encrypt`
  list.
- **AC-8.4**: re-running `add` with an already-present glob/field
  combination is a no-op — no duplicate rules, no duplicate entries in
  `encrypt`.
- **AC-8.5**: `add <glob> --field <path>` against an existing `mode: file`
  rule for the identical glob fails with a clear "mode conflict" error
  (mirrors spec 04 AC-4.6) rather than silently mutating the rule.
- **AC-8.6**: writing the updated config preserves unrelated existing
  rules, their field order, and (as much as the YAML library allows)
  formatting/comments.
- **AC-8.7**: after `add` succeeds, the new rule is immediately visible to
  `strucrypt status` (spec 09) and to the git filter driver (spec 06) —
  no separate reload step needed.
