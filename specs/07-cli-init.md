# Spec 07 — `strucrypt init`

Bootstrap a new repo or join an existing one. See
USER_INTERACTIONS.md § 1.

## Acceptance criteria

### Bootstrap mode (no committed config yet)

- **AC-7.1**: running `init` with no `.strucrypt.yaml` present creates
  `.strucrypt.yaml` (with a fresh salt and canary, spec 04) and a
  `.gitattributes` entry wiring configured patterns to the strucrypt
  filter.
- **AC-7.2**: with no password argument, a strong random passphrase is
  generated and printed exactly once; it is not written to disk anywhere
  in the repo.
- **AC-7.3**: `--password <value>` uses the supplied password instead of
  generating one.
- **AC-7.4**: the generated/derived key correctly decrypts the config's
  own canary value immediately after bootstrap (self-consistency check).
- **AC-7.5**: bootstrap registers the local git filter
  (`git config --get filter.strucrypt.clean` / `.smudge` return the
  expected commands afterward).

### Join mode (`.strucrypt.yaml` already exists)

- **AC-7.6**: `init <correct-password>` verifies the password by
  decrypting the config's canary, then registers the local filter.
- **AC-7.7**: `init <wrong-password>` fails with a clear error and does
  **not** register the filter (leaves the clone in the no-key passthrough
  state from spec 06 AC-6.6).
- **AC-7.8**: after a successful join, files matching filter patterns that
  were left as ciphertext passthrough at clone time are re-checked-out and
  appear decrypted in the working tree.
- **AC-7.9**: re-running `init` with the same correct password on an
  already-initialized clone is a safe no-op (no error, no duplicate
  config entries, filter registration unchanged).

### CI / non-interactive

- **AC-7.10**: `init "$PASSWORD"` (password as an argument, sourced from
  an env var by the caller) completes with no TTY interaction required —
  usable in a CI job.
