# nebel — Requirements

## Purpose

Encrypt secrets so they can live safely on the remote (in the git repo),
with transparent local decryption for developers.

## Use cases

- Application config files (`.env`)
- Infrastructure-as-code secrets (Terraform, Ansible, Kubernetes manifests, etc.)
- CI/CD pipeline secrets

## Storage

- Encrypted values are stored **in place**, inline within the original file
  (same filename, same structure) — not extracted into a separate encrypted
  file or external store.

## Key management

- Symmetric key, shared out-of-band (password manager, Signal, etc.) — no
  per-user asymmetric keypairs. Target scale: small team, 2–10
  people/machines.
- **Key derivation**: a human password + a stored (non-secret) salt →
  **Argon2id** → **HKDF** → the AES-256-SIV key material (see
  Encryption). The salt is checked into the repo so every clone derives
  identical key material from the same password.
- At any commit there is exactly one **current** key, identified by a
  `key_version` integer — see Key rotation for why a project can have
  more than one version in play across its history.

## Key rotation

- **One key per revision, multiple possible keys per project.** Rotating
  (`nebel rotate`) mints a new key version — new salt, new
  password-derived key, new canary — in the committed config. It does
  **not** touch any already-encrypted content.
- Every encrypted value/file tag (spec 03) records which key version
  produced it. `clean` always encrypts with the *current* version;
  `smudge` decrypts with whichever version a value's own tag names. Each
  machine keeps every version it has ever derived (`nebel init` /
  `nebel rotate`) in a small local keyring, not just one key.
- **Convergence is lazy**: a value migrates to the current version only
  the next time it's edited and staged — not via a repo-wide rewrite.
  This is also what makes a branch encrypted under an older version safe
  to merge later: only the fields still on that version need it, with a
  clear "needs key version N" error if it's missing, and they self-heal
  on their next edit.
- **The cost this doesn't remove**: a version stays load-bearing until
  nothing depends on it. `nebel status` reports which versions are still
  in use so a team knows when a password is finally safe to discard —
  discarding one too early makes whatever still depends on it permanently
  unreadable.
- **Forward-only, distribution unchanged**: rotation only protects *new*
  encryption going forward, and the new password is shared out-of-band
  the same way as the original. A leaked password still requires
  changing the underlying secrets, not just rotating the key.

## Git integration

- Transparent via git's **clean/smudge filter driver** (like
  git-crypt/transcrypt) — encryption happens automatically on `git add`
  (clean) and decryption on checkout (smudge). No manual hook invocation
  required by the user.
- **Determinism requirement**: the clean filter must produce the same
  ciphertext for the same plaintext input on repeated runs, or every
  `git add` will show spurious diffs. **Resolved** — see Encryption
  section: AES-256-SIV provides deterministic authenticated encryption
  without a hand-rolled nonce scheme.
- This determinism requirement applies to **both** whole-file and
  per-value modes — an unchanged file re-encrypted with a
  non-deterministic scheme would still produce a new ciphertext blob (and
  a spurious diff) on every `git add`, even with no content change.

## Bootstrapping & no-key operation

- Modeled on transcrypt:
  - **Checked into the repo**: `.gitattributes` (declares which file
    patterns are filter-managed) and the encryption rules config (per-file
    key-selection rules, see above) — every clone gets the same filter
    assignments and rules automatically, no manual per-dev setup of rules.
  - **Local per clone, not checked in**: the actual git filter
    registration (`git config filter.nebel.clean` /
    `filter.nebel.smudge`), set up by running a one-time
    `nebel init <password>` command locally with the shared key.
- **The repo must remain fully usable without the key**: `clone`, `pull`,
  `commit`, and `push` must all work for someone who has not run `init`.
  Without a local key, the filter must **pass content through unchanged**
  (stays encrypted) rather than erroring or aborting the git operation.
  Only someone who runs `init` with the password sees/works with decrypted
  content on disk.
- CI/CD follows the same pattern: run `nebel init` non-interactively
  using the key injected from the CI secret store before any step that
  needs cleartext secrets.

## Encryption

- **AES-256-SIV (RFC 5297)** — deterministic, misuse-resistant AEAD.
  Replaces plain AES-256-GCM as the encryption primitive.
- **Why SIV over GCM**: the determinism requirement (same plaintext → same
  ciphertext, needed for clean diffs and idempotency) is incompatible with
  GCM's random-nonce design, and hand-deriving a deterministic nonce for
  GCM (e.g. `HMAC(key, plaintext)`) is a DIY reinvention of a solved
  problem — if subtly wrong, the failure mode is catastrophic (full
  auth-key recovery, plaintext-relationship leakage across all values, via
  the GCM "forbidden attack"). AES-SIV is the standardized, purpose-built
  primitive for deterministic authenticated encryption (Google Tink ships
  it as its dedicated "Deterministic AEAD" primitive for exactly this
  scenario) — **misuse-resistant by construction**: the worst case, if two
  plaintexts under the same key ever collide, is that "these two values
  are equal" leaks — nothing worse. That's the same ceiling any
  deterministic scheme must accept, not an added risk.
- **Associated data (AAD) binding**: every SIV encryption call binds
  `AAD = repo-relative file path + field path (+ mode)`. Without this, two
  different fields holding the same secret value would produce identical
  ciphertext (cross-field equality leakage), and a ciphertext blob could be
  copy-pasted from one field to another and still decrypt validly there.
  With path-bound AAD, ciphertext is only ever identical when it's
  literally the same field, in the same file, holding the same
  value — exactly what's needed for diff stability, and nothing more.
- **Key sizing**: AES-SIV needs a 512-bit key (two 256-bit subkeys
  internally, per RFC 5297) — see Key management for how this is derived
  from the shared password.
- Applied uniformly to **both** whole-file and per-value modes.

## Encrypted value encoding (idempotency / state detection)

- Adopt SOPS's approach: each encrypted leaf value is stored as a
  self-describing tagged string, e.g.:

  ```
  ENC[AES256_SIV,data:Bx7f3K...==,type:str]
  ```

  (No separate `iv`/`tag` fields — AES-SIV's synthetic IV is derived
  internally from the key, plaintext, and AAD, and is embedded as part of
  `data`, so there's no external nonce to manage or leak.)

- Benefits:
  - **Detection**: the clean filter checks for the `ENC[` prefix to tell
    already-encrypted values from plaintext, so it can skip re-encrypting
    (and smudge can skip trying to decrypt plaintext) — solves the
    idempotency problem without any external/side-car state.
  - **Self-contained crypto material**: `data` travels with the value
    itself — consistent with the in-place, no-side-car storage
    requirement.
  - **Type preservation**: the `type:` field records the original scalar
    type (`str`, `int`, `bool`, `float`) so smudge restores the correct
    native type on decryption (e.g. `port: 5432` stays an integer, not a
    string).
  - **Format-agnostic**: the same wrapper works as a YAML/JSON scalar value
    or as the right-hand side of `KEY=ENC[...]` in `.env`/`.properties` —
    no format-specific variant needed.

## Granularity — user-selectable

- Supports **both** modes:
  - **Whole-file** encryption (git-crypt style) — for files without
    meaningful internal structure (binaries, certs, etc.).
  - **Per-value** encryption (SOPS style) — only selected fields are
    encrypted; the rest of the file stays readable/diffable in git.
- Mode is chosen **per file/pattern** in the config file, not hardcoded
  globally.

## Value selection (per-value mode)

- User selects the **exact key(s)** to encrypt, per file pattern, via the
  config file — not fuzzy/regex name matching.
- Generic addressing scheme across formats: **dot-notation path syntax**
  (gjson/JSONPath-like, e.g. `database.password`, `api.keys[0]`).
  - **YAML / JSON**: path walks the real nested structure, supports array
    indices.
  - **.properties / .env**: no real nesting — the "path" is an **exact
    literal match** on the full key/variable name (a dot in a `.properties`
    key is just a character, not a path separator).

Example config shape:

```yaml
rules:
  - files: "config/*.yaml"
    mode: value
    encrypt: ["database.password", "api.keys[0]"]
  - files: "*.env"
    mode: value
    encrypt: ["DATABASE_PASSWORD"]
  - files: "*.properties"
    mode: value
    encrypt: ["database.password"]
  - files: "secrets/*.pem"
    mode: file
```

## Supported file formats

- YAML
- JSON
- `.env`
- `.properties`

## File selection

- Pattern-based config file (glob patterns, `.gitattributes`-style) declares
  which files/paths participate, which mode applies (whole-file vs
  per-value), and which keys are encrypted per pattern.

## CI/CD

- Decryption key is delivered via the CI platform's own secret store
  (GitHub Actions secrets, GitLab CI variables, etc.) and injected as an
  environment variable during the build — no separate key-delivery
  mechanism needed.

## Cross-platform support

- Must run on:
  - Linux (specifically **UBI/Red Hat Universal Base Images** — minimal,
    glibc-based; assume no extra packages are preinstalled)
  - macOS
  - Windows
- Implies a single **statically-linked binary** with no runtime dependency.

## Language / platform

- **Go** — chosen for:
  - Native cross-compilation to Linux/macOS/Windows static binaries from
    one machine, no toolchain setup.
  - Mature format-preserving edit libraries fitting the in-place, per-value
    requirement (`yaml.v3` Node API for comment/order-preserving YAML edits,
    `tidwall/sjson` for surgical in-place JSON edits).
  - Well-vetted stdlib crypto (`crypto/aes`, `crypto/cipher`, `golang.org/x/crypto/argon2`,
    `golang.org/x/crypto/hkdf`) for key derivation; AES-256-SIV itself
    isn't in stdlib, needs a vetted third-party implementation (e.g.
    `github.com/secure-io/siv-go`) — evaluate during implementation
    planning.

## Out of scope for v1 (explicitly deprioritized)

- Concurrent/per-environment keys (e.g. different keys for staging vs.
  prod within the same rule set) — only one sequential, project-wide
  version history (see Key rotation) is supported.
- Audit logging
