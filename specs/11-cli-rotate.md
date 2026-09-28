# Spec 11 — `nebel rotate`

Mint a new, current key version and eagerly re-encrypt everything this
clone can reach onto it, so a single password decrypts everything the
repository currently tracks. See REQUIREMENTS.md § Key rotation.

## Model

One current key per revision; several versions can be in play across a
project's history. Every `ENC[...]` value/file tag names the version
that produced it. `clean` always encrypts with the *current* version;
`smudge` decrypts with whichever version a tag names. Each machine keeps
every version it has ever derived in a small local keyring, not just one
key.

```plantuml
@startuml
title One field's key version over time
state "tagged key:1" as v1
state "tagged key:2" as v2

[*] --> v1 : encrypted under v1

v1 --> v1 : smudge (keyring has 1)\nfield read, unchanged
v1 --> v2 : rotate (renormalizes\nevery field this clone\ncan decrypt), or an\nordinary edit + stage
v2 --> v2 : smudge (keyring has 2)

note right of v1
  if keyring lacks key 1:
  smudge fails clearly —
  "needs key version 1"
  (run nebel init --version 1);
  rotate itself refuses rather
  than strand this field on v1
end note
@enduml
```

`clean` always targeting the current version (AC-6.12) is what makes both
edges out of `v1` possible: `rotate` drives the bulk migration itself,
immediately, for every field the running clone can currently decrypt;
an ordinary edit-and-stage drives the same transition lazily, later, for
anything rotate couldn't reach (AC-11.10) — one field this clone had
never registered a key for, say. `nebel init --version N` (spec 07) is
how a clone backfills a missing key, either to unblock its own `rotate`
up front or to pick up that lazy convergence afterward.

## Acceptance criteria

- **AC-11.1 Requires a valid current key**: `rotate` requires the local
  keyring to hold an entry for the config's *current* `key_version` that
  verifies against the current canary. With no such entry, it fails with
  a clear error naming `nebel init`.
- **AC-11.2 Version bump**: `rotate` increments `key_version` by 1,
  generates a fresh salt, derives a new key from a new password, and
  writes a new canary — replacing the previous values in `.nebel.yaml`.
  `rules` is left unchanged.
- **AC-11.3 New password input**: same source precedence and
  restrictions as `init` (spec 07 § Password input): `--password-stdin`,
  then `$NEBEL_PASSWORD`, else a freshly generated passphrase printed
  exactly once; a positional password argument is refused; no
  interactive prompt fallback.
- **AC-11.4 Eager re-encryption**: after minting the new version, `rotate`
  re-encrypts every managed file/field this clone can currently decrypt
  onto it — equivalent to running `git add --renormalize` over every
  managed path itself, so nothing is left dangling as a manual follow-up.
  A file/field this clone cannot currently decrypt (its working tree
  content is still an `ENC[...]` tag — AC-6.4) can't be reached this way;
  see AC-11.11.
- **AC-11.5 Keyring updated additively**: the new version's key is added
  to the local keyring; no previously cached version is removed or
  overwritten, so the machine that rotated can still read everything it
  could read before.
- **AC-11.6 Stages the config and everything migrated**: `rotate` runs
  `git add` on `.nebel.yaml`, then stages every path AC-11.4 actually
  re-encrypted — nothing else. The operator commits explicitly.
- **AC-11.7 Output states the consequences**: output names the new
  version and how many files were re-encrypted, and states plainly that
  once the resulting commit is pulled, other clones/CI need `nebel init`
  again with the new password before they can read *or* write anything
  the repo currently tracks — not only to write, since AC-11.4/AC-11.11
  together guarantee nothing committed is left on an older version.
- **AC-11.8 No secrets printed**: output never includes decrypted values
  — only the version number and, when generated, the new password
  (printed exactly once).
- **AC-11.9 Not idempotent, by design**: running `rotate` again right
  after a successful rotation succeeds and mints a third, independent
  version — there is no "already rotated" state to converge on.
- **AC-11.10 Lazy convergence for what rotate couldn't reach**: content
  AC-11.11 didn't block on (this clone had no rule matching it, say, or
  it didn't exist yet) still converges the ordinary way once rotate has
  run: the next edit-and-stage, or an explicit `git add --renormalize --
  <path>`, re-encrypts it under whatever is current by then. This is the
  same mechanism AC-11.4 itself is built on (spec 06 AC-6.12) — rotate
  just also drives it immediately, itself, for everything it can.
- **AC-11.11 Refuses rather than strand content**: before changing
  anything, `rotate` checks every managed file/field against what's
  currently on disk. If any of them is still an `ENC[...]` tag — this
  clone was never able to decrypt it, so AC-11.4's re-encryption cannot
  reach it — `rotate` fails, naming each stuck path (and field, and the
  version it's stuck on) and pointing at `nebel init --version N`, and
  leaves the committed config untouched. Minting a new version while
  silently leaving part of the repo unreadable under it is exactly the
  outcome AC-11.4 exists to prevent.
