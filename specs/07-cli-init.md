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
- **AC-7.3**: a password supplied by the user (see § Password input) is
  used instead of generating one.
- **AC-7.4**: the generated/derived key correctly decrypts the config's
  own canary value immediately after bootstrap (self-consistency check).
- **AC-7.5**: bootstrap registers the local git filter
  (`git config --get filter.strucrypt.clean` / `.smudge` return the
  expected commands afterward). The command names the binary by absolute
  path — see spec 11.

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
  already-initialized clone is safe and idempotent (no error, no
  duplicate config entries). Filter registration is refreshed to the
  running binary's absolute path, which is the documented repair for a
  clone set up by an older version — see spec 11 AC-11.5.

### Password input

The password must be able to reach `init` without ever appearing in the
command line: `argv` is world-readable on Linux (`/proc/<pid>/cmdline`), so
an argument leaks the shared password to every other user on the machine,
and to shell history and CI log echoes.

Sources are consulted in order of decreasing safety: `--password-stdin`,
then `$STRUCRYPT_PASSWORD`, then an interactive prompt. There is no
command-line password argument.

- **AC-7.10**: `$STRUCRYPT_PASSWORD` supplies the password with no TTY
  interaction required — the supported CI path.
- **AC-7.11**: `--password-stdin` reads the password from stdin, stripping
  a single trailing line ending, so it can be piped from a secret store.
- **AC-7.12**: a positional password argument is refused with a clear
  error naming the supported inputs, and registers nothing. Accepting it
  with a warning would leave the password equally exposed for anyone who
  didn't read the warning.
- **AC-7.13**: in join mode with no password from any source, `init`
  prompts on a terminal with echo disabled; with no terminal it fails,
  naming the alternatives, and registers nothing.
