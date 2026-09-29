# Spec 04 — Config file (`.nebel.yaml`)

The committed rules config: salt, canary, and file/field selection rules.
See REQUIREMENTS.md § Value selection, § File selection, and
USER_INTERACTIONS.md § init / add.

## Acceptance criteria

- **AC-4.1 Schema**: config parses these top-level fields: `format_version`
  (int, this file's schema version — see AC-4.11/4.12; absent means 1),
  `created_with` (string, the `nebel version` output that bootstrapped this
  repo — informational only, never checked by Load), `key_version` (int,
  the current key version — spec 11), `salt` (base64, for `key_version`),
  `canary` (an `ENC[...]` tag, for `key_version`), `rules: []` where each
  rule has `files` (glob string), `mode` (`file` | `value`), and — for
  `mode: value` only — `encrypt: []` (list of dot-notation paths). Only
  the *current* version's salt/canary live in the file — see AC-4.9 for
  how an older version's are found.
- **AC-4.2 Glob semantics**: pattern matching follows `.gitattributes`-style
  glob syntax (document the exact library/semantics chosen, incl. `**`
  recursive matching); a unit test enumerates matching and non-matching
  paths per pattern.
- **AC-4.3 Rule precedence**: when a file matches more than one rule's
  `files` glob, the defined precedence (e.g. "first matching rule in
  file order wins") is explicit and tested — no undefined/ambiguous
  behavior.
- **AC-4.4 Invalid mode rejected**: a `mode` value other than `file` or
  `value` fails config loading with a clear error.
- **AC-4.5 Empty encrypt list rejected**: a `mode: value` rule with an
  empty or missing `encrypt` list fails config loading with a clear error
  (nothing to encrypt is a misconfiguration, not a valid no-op).
- **AC-4.6 Mode conflict rejected**: two rules with the identical `files`
  glob but different `mode` fail config loading with a clear error.
- **AC-4.7 Hand-editable**: a config file written by hand (not only via
  `nebel add`) that satisfies the schema loads correctly — the format
  is plain YAML, no tool-specific serialization quirks required.
- **AC-4.8 Canary format**: the `canary` field is a valid Spec-03 `ENC[...]`
  tag (so it also carries `key:<key_version>`, like any other tag) over a
  fixed, documented plaintext constant (e.g. `"nebel-ok"`) with
  `AAD = "nebel-canary"`.
- **AC-4.9 Historical version lookup**: given a version `N`, walking this
  file's own git history finds the (unique) commit whose `key_version`
  equals `N` and returns that commit's salt/canary. An `N` that never
  existed in the history is a clear error, not an empty/zero result.
- **AC-4.10 Bootstrap starts at version 1**: a freshly bootstrapped config
  (spec 07) always sets `key_version: 1`.
- **AC-4.11 format_version defaults to 1**: a config with no `format_version`
  field (every file written by a released version through v0.4.x) loads
  exactly as if it declared `format_version: 1` — no error, no behavior
  change. A freshly bootstrapped config always writes the current build's
  `format_version` explicitly.
- **AC-4.12 Future format rejected up front**: a config declaring a
  `format_version` greater than this build's `CurrentFormatVersion` fails
  to load with a clear "upgrade nebel" error naming both versions — checked
  before the rest of the file is parsed or validated, so a genuinely
  incompatible schema change (a renamed or retyped field, say) never
  surfaces as a confusing parse or validation error instead.
