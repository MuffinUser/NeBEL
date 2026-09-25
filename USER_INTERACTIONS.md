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
- To supply your own instead, see § Password input below.
- Writes the committed config (`.strucrypt.yaml`) with: the Argon2id salt
  (not secret), an empty/example rule set, and a **canary value** — a
  well-known constant string encrypted under the derived key
  (`AAD = "strucrypt-canary"`). This lets future `init` runs verify a
  password is correct before trusting it, without needing any real secret
  to test against.
- Registers the local git filter (`git config filter.strucrypt.*`).

### Join mode — `.strucrypt.yaml` already exists (clone of an existing repo)

```
$ strucrypt init
Password:
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

### Password input

The password never has to appear on the command line — `argv` is
world-readable on Linux, so an argument exposes the shared password to
every other user on the machine, and to shell history and CI logs.
Sources, in order of precedence:

1. `--password-stdin` — read from stdin, for piping out of a secret store.
2. `$STRUCRYPT_PASSWORD` — the recommended CI path.
3. An interactive prompt with echo disabled, when join mode needs a
   password and nothing else supplied one.

A password given as a command-line argument is refused, not accepted with
a warning.

### CI usage

Same command, non-interactive — export the password from the CI platform's
own secret store and run this once, before any step that needs cleartext:

```
STRUCRYPT_PASSWORD="$SECRET" strucrypt init
```

or pipe it in, without putting it in the environment either:

```
get-secret strucrypt | strucrypt init --password-stdin
```

## 2. `strucrypt add file` / `strucrypt add field`

Two subcommands, because they register two different kinds of rule.

### `add file <glob>` — whole-file mode

For blobs with no readable structure: certificates, keyrings, dumps.

```
$ strucrypt add file "secrets/*.pem"
Added rule: secrets/*.pem (mode: file)
```

### `add field <file> [path...]` — per-value mode

For config you still want to read and diff in git. Paths are dot notation
with array indices; quote them, or the shell will eat the brackets.

```
$ strucrypt add field config/staging.yaml database.password 'api.keys[0]'
Added to rule config/staging.yaml (mode: value):
  database.password
  api.keys[0]
```

With no paths, the file's values are listed to choose from — so nobody has
to hand-write dot notation for a deeply nested key:

```
$ strucrypt add field config/staging.yaml
Values in config/staging.yaml:

   1) database.host                            "db.internal"
   2) database.password                        "s3cr3t"
   3) database.port                            5432
   4) api.keys[0]                              "alpha"
   5) api.token                                "tok_live_abcdefghijklmnopqrstuvwxyz0123…"

Encrypt which? (numbers, e.g. "1 3"; "all"; empty to cancel): 2 5
Added to rule config/staging.yaml (mode: value):
  database.password
  api.token
```

- Values already encrypted, or already in the rule, are not offered.
- Every path is checked against the file before the rule is written, so a
  typo fails here rather than on whoever next stages the file.
- Re-running with the same paths is a no-op.
- Supported formats: YAML and JSON. `.env` and `.properties` are not
  implemented yet.
- Both subcommands also add the pattern to `.gitattributes`. After that the
  normal `git add`/`git commit` flow picks the rule up — no further step.

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
