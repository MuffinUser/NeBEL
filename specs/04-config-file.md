# Spec 04 — Config file (`.nebel.yaml`)

The committed rules config: salt, canary, and file/field selection rules.
See REQUIREMENTS.md § Value selection, § File selection, and
USER_INTERACTIONS.md § init / add.

## Acceptance criteria

- **AC-4.1 Schema**: config parses these top-level fields: `key_version`
  (int, the current key version — spec 11), `salt` (base64, for
  `key_version`), `canary` (an `ENC[...]` tag, for `key_version`),
  `rules: []` where each rule has `files` (glob string), `mode` (`file` |
  `value`), and — for `mode: value` only — `encrypt: []` (list of
  dot-notation paths). Only the *current* version's salt/canary live in
  the file — see AC-4.9 for how an older version's are found.
- **AC-4.2 Glob semantics**: pattern matching follows `.gitattributes`, so
  a rule covers exactly the files its `.gitattributes` line sends through
  the filter. A pattern without a `/` matches the base name at any depth
  (`*.env` matches `config/prod.env`). A pattern with a `/` matches the
  path relative to the repository root, and a leading `/` only anchors
  (`/prod.env` matches the root file alone). Segment syntax is
  doublestar's (`*` doesn't cross `/`, `**` matches any number of
  directories). A unit test enumerates matching and non-matching paths per
  pattern, and an integration test checks each answer against
  `git check-attr`.
- **AC-4.3 Rule precedence**: when a file matches more than one rule's
  `files` glob, the first matching rule in file order wins. One exception
  keeps older configs resolving as before: a bare pattern's any-depth
  match (against the base name) is tried only after no rule matched the
  whole path, so `config/*.env` keeps `config/prod.env` even when `*.env`
  is listed first. (Bare patterns used to match root files only.)
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
- **AC-4.11 Format-aware field validation**: `Validate` checks each
  `encrypt` entry against the format of its rule's `files` glob, detected
  by applying spec 05 AC-5.16 to the glob's last path segment (`*.env` →
  env, `config/*.properties` → properties, `**/*.yaml` → YAML,
  `.env.*` → env).
  - YAML/JSON: the entry must parse with `format.ParsePath` (as today).
  - env/properties: the entry is a literal key. It must be non-empty and
    contain no control characters. For env it must also contain no
    whitespace and no `=`. So `a..b`, `.x` and `foo[` are valid
    properties keys and must load.
  - Undetectable (e.g. `config/*`, `.env*`, `**/*.{env,properties}`):
    such a glob may match several formats, so the entry gets the loosest
    check, the properties literal key. A typo like `api.keys[` in a YAML
    rule then loads, but still fails with `ErrBadPath` when a matched YAML
    file is staged, and `nebel add field` checks entries against the real
    file. Requiring dot notation here instead would reject valid literal
    keys under globs that can't name a single format.

  This removes a conflict with REQUIREMENTS.md § Value selection: today
  every entry goes through `ParsePath`, which rejects legal literal keys.
