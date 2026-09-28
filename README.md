# nebel

Encrypt secrets in place so they can live safely in the git repo, with
transparent local decryption. Encryption happens on `git add`, decryption on
checkout, via git's clean/smudge filter driver — day to day you just use git.

## Foreword
This tool is derived from Tools like [git-crypt](https://github.com/agwa/git-crypt) and [transcrypt](https://github.com/elasticdog/transcrypt). 
The Concept for inplace encryption is derived from [SOPS](https://github.com/getsops/sops).

### Advantages
This Tool is written in go. Making it easy to run on all Platforms(MacOS, Windows, Linux). This is where git-crypt and transcrypt struggle.
The Transparent inplace Encryption enables useful Merges within a File. Beacaus git-crypt and transcrypt only encrypt the whole file. 

### Things to Concider
At the Moment only Symetric-Encryption is provided. You have to Roate Keys on your own.
This Project is entirely Vibe Coded. At best changes are peer-reviewed by a human.
The only thing written by a Human is this Foreword. So take it for what it is.

## Install

One static binary, which **must be on your `PATH`** — git invokes it by name
(`nebel clean %f`). Get the archive onto the machine however you like
(from [Releases](https://github.com/MarwinMoellers/nebel/releases), a
share, a USB stick); the steps below install from that local file and need
no internet. Adjust the filename to your version.

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
| `nebel add file <glob>` | Encrypt whole files matching a glob |
| `nebel add field <file> [path...]` | Encrypt named values inside a file; with no paths, pick them interactively |
| `nebel version` | Print the build version |

`nebel clean` and `nebel smudge` exist for git to call; you never run
them yourself.

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
<https://github.com/MarwinMoellers/nebel>.

Third-party code statically linked into the binary — Tink, `x/crypto`,
`goccy/go-yaml`, and others, all under permissive licences — is credited in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), regenerated with
`sh scripts/gen-notices.sh` whenever dependencies change.

If the GPL does not suit your case, ask me about a commercial licence.
