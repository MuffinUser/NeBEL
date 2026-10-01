# nebel

Encrypt secrets in place so they can live safely in the git repo, with
transparent local decryption. Encryption happens on `git add`, decryption on
checkout, via git's clean/smudge filter driver — day to day you just use git.

## Foreword
This tool is derived from Tools like [git-crypt](https://github.com/agwa/git-crypt) and [transcrypt](https://github.com/elasticdog/transcrypt). 
The Concept for inplace encryption is derived from [SOPS](https://github.com/getsops/sops).

### Name
`nebel` is German for "fog" — a fitting image for a tool whose whole job is to
make secrets unreadable. It also doubles as a backronym: **N**och **E**ine
git-**B**lob-**E**ntschlüsselungs-**L**ösung, German for "yet another
git-blob decryption solution" — a self-deprecating nod to the fact that
git-crypt, transcrypt, and SOPS already exist, in the same spirit as other
recursive/joke project acronyms (GNU, YAML, ...).

### Advantages over git-crypt and transcrypt
- **Cross-platform.** Written in Go and shipped as a single static binary, it
  runs the same way on macOS, Windows, and Linux. git-crypt needs a C++
  toolchain and GPG; transcrypt is a bash script — both struggle on Windows.
- **Field-level, not just whole-file, encryption.** `nebel add field`
  encrypts individual values inside a file and leaves the rest as plaintext.
  git-crypt and transcrypt only ever encrypt an entire file, which makes
  diffs opaque and merges inside that file effectively impossible; nebel's
  in-place encryption keeps most of the file mergeable as normal.
- **Versioned key rotation.** `nebel rotate` mints a new key version and
  re-encrypts everything under it, while clones that haven't run `nebel
  init` with the new password yet keep working — `git pull` still succeeds,
  it just leaves the rotated files as ciphertext with a warning instead of
  failing outright.

### Things to Concider
At the Moment only Symetric-Encryption is provided. You have to Roate Keys on your own.
This Project is entirely Vibe Coded. At best changes are peer-reviewed by a human.
The only thing written by a Human is this Foreword. So take it for what it is.

## Install

One static binary, which **must be on your `PATH`** — git invokes it by name
(`nebel clean %f`).

### From the internet

Downloads the latest release, verifies its checksum, and puts `nebel` on
your `PATH`.

**macOS / Linux:**

```sh
curl -fsSL https://raw.githubusercontent.com/MuffinUser/NeBEL/main/scripts/install.sh | sh
# or: wget -qO- https://raw.githubusercontent.com/MuffinUser/NeBEL/main/scripts/install.sh | sh
```

**Windows** (PowerShell), then open a new terminal:

```powershell
irm https://raw.githubusercontent.com/MuffinUser/NeBEL/main/scripts/install.ps1 | iex
```

From `cmd.exe`:

```bat
powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol='Tls12'; irm https://raw.githubusercontent.com/MuffinUser/NeBEL/main/scripts/install.ps1 | iex"
```

Both scripts install the latest release by default. To pin a version, set
`NEBEL_VERSION` first:

```sh
curl -fsSL https://raw.githubusercontent.com/MuffinUser/NeBEL/main/scripts/install.sh | NEBEL_VERSION=v0.5.2 sh
```

```powershell
$env:NEBEL_VERSION = 'v0.5.2'; irm https://raw.githubusercontent.com/MuffinUser/NeBEL/main/scripts/install.ps1 | iex
```

### From a local file (no internet)

Get the archive onto the machine however you like (from
[Releases](https://github.com/MuffinUser/nebel/releases), a share, a USB
stick); the steps below install from that local file and need no internet.
Adjust the filename to your version.

**Windows** (PowerShell), then open a new terminal:

```powershell
$Zip  = "$HOME\Downloads\nebel_v0.3.0_windows_amd64.zip"
$Dest = "$env:LOCALAPPDATA\Programs\nebel"

Unblock-File $Zip     # clears the "downloaded from the internet" mark
Expand-Archive $Zip -DestinationPath $env:TEMP\nebel-install -Force
New-Item -ItemType Directory -Force -Path $Dest | Out-Null
Copy-Item "$env:TEMP\nebel-install\*\nebel.exe" $Dest -Force
[Environment]::SetEnvironmentVariable('Path',
  [Environment]::GetEnvironmentVariable('Path', 'User') + ";$Dest", 'User')

# Git Bash (incl. IntelliJ's) reads PATH from ~/.bash_profile, not the
# Windows PATH above.
$Posix = '/' + $Dest.Substring(0,1).ToLower() + $Dest.Substring(2).Replace('\','/')
Add-Content "$HOME\.bash_profile" "`nexport PATH=`"`$PATH:$Posix`""
```

Then **fully restart IntelliJ** (File > Exit, not just closing the
project) — it keeps the PATH it had when it started.

**macOS** (`amd64` instead of `arm64` on Intel):

```sh
tar -xzf ~/Downloads/nebel_v0.3.0_darwin_arm64.tar.gz -C /tmp
sudo mv /tmp/nebel_*_darwin_*/nebel /usr/local/bin/
xattr -d com.apple.quarantine /usr/local/bin/nebel   # if Gatekeeper blocks it
```

**From source**: `go build -o nebel ./cmd/nebel`, then move it onto
your `PATH`.

Check with `nebel version`.

## Quick start

Set up a repo (first person to introduce nebel):

```sh
nebel init                          # generates a password — store it now
nebel add file "secrets/*.pem"      # encrypt whole files
nebel add field config/app.yaml     # or pick values to encrypt, interactively
git add . && git commit -m "encrypt secrets"
```

`.nebel.yaml` and `.gitattributes` are committed and shared; the password
is not — distribute it to your team out of band.

Join an existing repo, after cloning — `init` prompts for the shared
password:

```sh
nebel init
```

A password given as an argument is refused — it would be readable by other
users on the machine, via the process list. Non-interactively, use the
environment or stdin instead:

```sh
NEBEL_PASSWORD="$SECRET" nebel init   # CI
get-secret nebel | nebel init --password-stdin
```

A clone that never runs `init` still works normally — `clone`, `pull`,
`commit`, and `push` all succeed, the managed files just stay encrypted on
disk.

`init` reports how many files it decrypted on join (`Done. 3 files decrypted
locally.`). If it reports zero, the password was still correct, but nothing
in the repo is wired to the filter — almost always a `.gitattributes` that
was never committed. Check with:

```sh
git check-attr filter -- <path>   # should report "filter: nebel"
```

## Commands

| Command | What it does |
| --- | --- |
| `nebel init [--password-stdin]` | Bootstrap a repo, or join one with the shared password |
| `nebel init --version N [--password-stdin]` | Fetch and register locally a specific (possibly older) key version, e.g. after `nebel rotate` |
| `nebel add file <glob>` | Encrypt whole files matching a glob |
| `nebel add field <file> [path...]` | Encrypt named values inside a file; with no paths, pick them interactively |
| `nebel rotate [--password-stdin]` | Mint a new key version with a new password, and re-encrypt everything under it |
| `nebel version` | Print the build version |

`nebel clean` and `nebel smudge` exist for git to call; you never run
them yourself.

## Pulling after a teammate rotates

`nebel rotate` re-encrypts every secret it can reach onto the new
version, so the commit it produces changes those files' ciphertext, not
just `.nebel.yaml`. A plain `git pull` on another clone still succeeds
once that commit lands, even though this clone doesn't have the new key
yet — the changed files just land as ciphertext, with a warning:

```
$ git pull
warning: nebel: secrets/prod.pem needs key version 2 — left encrypted; was the key rotated? run `nebel init` with the new password
Fast-forward
 .nebel.yaml      | 6 +++---
 secrets/prod.pem | 2 +-
 2 files changed, 4 insertions(+), 4 deletions(-)
```

That's the same state a brand-new clone is in before its first `nebel
init`: filter-managed content sitting as ciphertext, `git status`
reporting nothing locally modified. Run `nebel init` with the new
password to decrypt it in place, exactly like joining any other repo:

```sh
git pull
nebel init   # with the new password
```

No other recovery steps are needed, and nothing is lost if you run
`nebel init` some time after the pull rather than immediately — the
ciphertext just sits there, unreadable without the new key, until you do.

## Upgrading from a pre-rotation repository

Key rotation (`nebel rotate`, above) changed the `ENC[...]` tag format:
every tag now records which key version produced it. A repository created
by a build from before rotation existed (v0.3.0 or earlier) has tags with
no version at all, and the new build refuses to parse those — including
in its own committed config's canary, which every command checks first.
There is no automatic migration: `nebel init`, `nebel rotate`, and even
`git add --renormalize` all fail the same way until the config is fixed.

The fix is two hand-edits to `.nebel.yaml`, not per-file surgery — do this
from a machine whose working tree is currently decrypted (i.e. any
machine using the repo normally, with every managed file checked out and
readable — not one that's only ever seen ciphertext passthrough):

1. Add a `key_version: 1` line to `.nebel.yaml`.
2. In its `canary` field, insert `key:1,` right after the algorithm name,
   e.g. `ENC[AES256_SIV,data:...]` becomes
   `ENC[AES256_SIV,key:1,data:...]`.
3. Run `git add --renormalize -- .`.
4. Confirm nothing old-format survived: `git grep --cached -F
   'ENC[AES256_SIV,data:'` must find nothing. Anything it lists is a file
   or field this machine never had decrypted, so renormalize saw it
   already starting with `ENC[` and left it alone instead of re-encrypting
   it — run the migration again from a machine that does have it
   decrypted, or decrypt-and-recommit that path specifically first.
5. Commit.

Step 3 re-encrypts every already-decrypted file/field from scratch under
the new (current build's) tag format — it does not need to touch any
already-committed ciphertext by hand, because renormalizing re-cleans
from whatever the working tree currently holds, which for an
actively-used clone is the plaintext, not the old blob. Step 4 exists
because that shortcut silently does nothing for a file this machine
couldn't decrypt.

Every clone and CI job must upgrade its `nebel` binary before pulling the
migration commit — the old binary can't read the new tag format, and vice
versa; there is no build that reads both. A clone that already ran the old
`nebel init` doesn't need to run it again: its key is registered under the
same local git config name this build still reads. But pulling the
migration commit itself needs one precaution: if git happens to re-smudge
a managed file before it updates the working tree's `.nebel.yaml`, that
smudge reads the *old* `.nebel.yaml` still on disk and fails the canary
check. Avoid that ordering risk with:

```sh
git fetch
git checkout @{u} -- .nebel.yaml   # not filter-managed, always safe
git pull
```

History from before the migration commit remains unreadable to the new
build — checking out an old commit's content still requires an old
binary, the same way any other breaking format change would.

## Licence

Copyright (C) 2026 Marwin Moellers. nebel is free software under the
[GNU General Public License v3.0 or later](LICENSE); there is NO WARRANTY,
to the extent permitted by law.

**Using it at a company is unrestricted.** Running nebel on your repos,
in CI, or across an entire organisation triggers no obligation whatsoever —
the GPL's conditions attach to *distributing* the program, not to using it.
Encrypting your files with nebel says nothing about the licence of those
files or of the repository they live in; the tool and your data stay
separate.

Obligations begin only if you hand nebel itself to someone else:
redistribute it, modified or not, and you must pass on the source under the
same licence. The corresponding source for every release is at
<https://github.com/MuffinUser/nebel>.

Third-party code statically linked into the binary — Tink, `x/crypto`,
`goccy/go-yaml`, and others, all under permissive licences — is credited in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), regenerated with
`sh scripts/gen-notices.sh` whenever dependencies change.

If the GPL does not suit your case, ask me about a commercial licence.
