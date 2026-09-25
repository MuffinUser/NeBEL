# strucrypt

Encrypt secrets in place so they can live safely in the git repo, with
transparent local decryption. Encryption happens on `git add`, decryption on
checkout, via git's clean/smudge filter driver — day to day you just use git.

## Install

One static binary, which **must be on your `PATH`** — git invokes it by name
(`strucrypt clean %f`). Get the archive onto the machine however you like
(from [Releases](https://github.com/MarwinMoellers/strucrypt/releases), a
share, a USB stick); the steps below install from that local file and need
no internet. Adjust the filename to your version.

**Windows** (PowerShell), then open a new terminal:

```powershell
$Zip  = "$HOME\Downloads\strucrypt_v0.3.0_windows_amd64.zip"
$Dest = "$env:LOCALAPPDATA\Programs\strucrypt"

Unblock-File $Zip     # clears the "downloaded from the internet" mark
Expand-Archive $Zip -DestinationPath $env:TEMP\strucrypt-install -Force
New-Item -ItemType Directory -Force -Path $Dest | Out-Null
Copy-Item "$env:TEMP\strucrypt-install\*\strucrypt.exe" $Dest -Force
[Environment]::SetEnvironmentVariable('Path',
  [Environment]::GetEnvironmentVariable('Path', 'User') + ";$Dest", 'User')
```

**macOS** (`amd64` instead of `arm64` on Intel):

```sh
tar -xzf ~/Downloads/strucrypt_v0.3.0_darwin_arm64.tar.gz -C /tmp
sudo mv /tmp/strucrypt_*_darwin_*/strucrypt /usr/local/bin/
xattr -d com.apple.quarantine /usr/local/bin/strucrypt   # if Gatekeeper blocks it
```

**From source**: `go build -o strucrypt ./cmd/strucrypt`, then move it onto
your `PATH`.

Check with `strucrypt version`.

## Quick start

Set up a repo (first person to introduce strucrypt):

```sh
strucrypt init                          # generates a password — store it now
strucrypt add file "secrets/*.pem"      # encrypt whole files
strucrypt add field config/app.yaml     # or pick values to encrypt, interactively
git add . && git commit -m "encrypt secrets"
```

`.strucrypt.yaml` and `.gitattributes` are committed and shared; the password
is not — distribute it to your team out of band.

Join an existing repo, after cloning — `init` prompts for the shared
password:

```sh
strucrypt init
```

A password given as an argument is refused — it would be readable by other
users on the machine, via the process list. Non-interactively, use the
environment or stdin instead:

```sh
STRUCRYPT_PASSWORD="$SECRET" strucrypt init   # CI
get-secret strucrypt | strucrypt init --password-stdin
```

A clone that never runs `init` still works normally — `clone`, `pull`,
`commit`, and `push` all succeed, the managed files just stay encrypted on
disk.

`init` reports how many files it decrypted on join (`Done. 3 files decrypted
locally.`). If it reports zero, the password was still correct, but nothing
in the repo is wired to the filter — almost always a `.gitattributes` that
was never committed. Check with:

```sh
git check-attr filter -- <path>   # should report "filter: strucrypt"
```

## Commands

| Command | What it does |
| --- | --- |
| `strucrypt init [--password-stdin]` | Bootstrap a repo, or join one with the shared password |
| `strucrypt add file <glob>` | Encrypt whole files matching a glob |
| `strucrypt add field <file> [path...]` | Encrypt named values inside a file; with no paths, pick them interactively |
| `strucrypt version` | Print the build version |

`strucrypt clean` and `strucrypt smudge` exist for git to call; you never run
them yourself.
