# strucrypt — User Interactions

Design principle: **minimal surface**. Day-to-day use should require zero
commands — `git add`/`git commit`/`git checkout` just work via the filter
driver. Only three explicit commands are needed: bootstrap/join a repo,
register what to encrypt, and check status.

## 1. `strucrypt init [password]`

One command, two modes, auto-detected by whether the repo already has a
committed strucrypt config.

### Bootstrap mode — no `.strucrypt.yaml` in the repo yet

First person to introduce strucrypt to a repo:

```
$ strucrypt init
Generated password: correct-horse-battery-staple-9f3a
⚠ This password will not be shown again — store it in your password
  manager now and share it with your team out-of-band.

Created:
  .strucrypt.yaml   (encryption rules config — commit this)
  .gitattributes    (filter assignment — commit this)

Local filter registered. You're ready to use git normally.
```

- If no password is given, one is generated (strong random passphrase).
- `--password <value>` lets the user supply their own instead.
- Writes the committed config (`.strucrypt.yaml`) with: the Argon2id salt
  (not secret), an empty/example rule set, and a **canary value** — a
  well-known constant string encrypted under the derived key
  (`AAD = "strucrypt-canary"`). This lets future `init` runs verify a
  password is correct before trusting it, without needing any real secret
  to test against.
- Registers the local git filter (`git config filter.strucrypt.*`).

### Join mode — `.strucrypt.yaml` already exists (clone of an existing repo)

```
$ strucrypt init 'correct-horse-battery-staple-9f3a'
Password verified.
Local filter registered.
Re-checking out managed files...
Done. 3 files decrypted locally.
```

- Derives the key from the given password + the committed salt, then
  decrypts the canary value to **verify the password is correct** before
  registering anything — fails fast with a clear error on a wrong
  password, rather than silently registering a filter that produces
  garbage.
- Registers the local git filter.
- Re-runs checkout on filter-managed files (e.g. `git checkout -- .` under
  the hood), since files matching the filter were smudged as ciphertext
  passthrough at clone time, before the filter was registered.

### CI usage

Same command, non-interactive:

```
strucrypt init "$STRUCRYPT_PASSWORD"
```

run once at the start of a CI job (password sourced from the CI
platform's own secret store), before any step that needs cleartext.

## 2. `strucrypt add <glob> [--field <path>]`

Registers a new file pattern (and, optionally, a specific field) in the
committed rules config — the only manual step needed when a new secret
file or field shows up, since selection is pattern/exact-key based, not
automatic.

```
# New file, whole-file mode
$ strucrypt add "secrets/*.pem"
Added rule: secrets/*.pem (mode: file)

# New file, per-value mode with one field
$ strucrypt add "config/staging.yaml" --field "database.password"
Added rule: config/staging.yaml (mode: value)
  encrypt: [database.password]

# Adding another field to an existing per-value rule
$ strucrypt add "config/staging.yaml" --field "api.token"
Updated rule: config/staging.yaml
  encrypt: [database.password, api.token]
```

- No `--field` → whole-file mode rule.
- `--field` (repeatable) → per-value mode; appends to the pattern's
  `encrypt` list if a rule for that pattern already exists.
- Idempotent: re-running with the same glob/field is a no-op.
- After running, the normal `git add`/`git commit` flow picks up the new
  rule automatically — no further manual step.
- If a new file just matches an **existing** glob pattern already in
  `.strucrypt.yaml`, no command is needed at all — it's covered
  automatically.

## 3. `strucrypt status`

Read-only inspection / debugging. No secrets are printed.

```
$ strucrypt status
Local filter:     registered ✓
Password:         verified ✓

config/staging.yaml         (mode: value)
  database.password         encrypted
  api.token                 encrypted
  api.retry_count            plaintext (not a tracked field)

secrets/prod.pem            (mode: file)
  encrypted

config/new-service.yaml     (mode: value)
  database.password         ⚠ PLAINTEXT — matches rule, not yet encrypted
```

- Shows whether the local filter is registered and the password verifies
  (via the canary) — surfaces the "forgot to run init" failure mode from
  the bootstrapping design instead of it failing silently.
- Walks all files matching configured patterns; for per-value rules,
  reports each tracked field as `encrypted` / `⚠ PLAINTEXT` (matches a
  rule but hasn't gone through the clean filter yet — e.g. filter isn't
  registered, or the file was edited outside git); for whole-file rules,
  reports the file as `encrypted` / `⚠ PLAINTEXT`.
- Non-zero exit code if any tracked field/file is `⚠ PLAINTEXT` — usable
  as a CI check to catch the "filter wasn't registered, plaintext got
  staged" failure mode called out earlier.

## Command surface summary

| Command | Who runs it | When |
|---|---|---|
| `strucrypt init [password]` | Repo owner (bootstrap) / every other clone / CI | Once per person/machine, and once per repo |
| `strucrypt add <glob> [--field <path>]` | Any dev | When a new secret file or field is introduced |
| `strucrypt status` | Any dev / CI | Ad hoc debugging, or as a CI gate |

Everything else (encrypt on stage, decrypt on checkout) happens
transparently through the git filter driver — no dedicated
encrypt/decrypt commands in the day-to-day flow.
