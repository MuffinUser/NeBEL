# strucrypt

Encrypt secrets in place so they can live safely in the git repo, with
transparent local decryption. Encryption happens on `git add`, decryption on
checkout, via git's clean/smudge filter driver — day to day you just use git.

## Install

A single static binary, which **must be on your `PATH`** — git invokes it by
name (`strucrypt clean %f`) on every staged or checked-out managed file.
Grab an archive from
[Releases](https://github.com/MarwinMoellers/strucrypt/releases) and set
`VERSION` below to match.

**macOS** (use `amd64` instead of `arm64` on Intel):

```sh
VERSION=v0.1.0
curl -LO "https://github.com/MarwinMoellers/strucrypt/releases/download/${VERSION}/strucrypt_${VERSION}_darwin_arm64.tar.gz"
tar -xzf "strucrypt_${VERSION}_darwin_arm64.tar.gz"
sudo mv "strucrypt_${VERSION}_darwin_arm64/strucrypt" /usr/local/bin/
# The binaries aren't code-signed; if Gatekeeper blocks it:
xattr -d com.apple.quarantine /usr/local/bin/strucrypt
```

**Windows** (PowerShell; reopen your terminal afterwards for `PATH`):

```powershell
$Version = 'v0.1.0'
$Dest    = "$env:LOCALAPPDATA\Programs\strucrypt"
Invoke-WebRequest "https://github.com/MarwinMoellers/strucrypt/releases/download/$Version/strucrypt_${Version}_windows_amd64.zip" -OutFile "$env:TEMP\s.zip"
Expand-Archive "$env:TEMP\s.zip" -DestinationPath $env:TEMP -Force
New-Item -ItemType Directory -Force -Path $Dest | Out-Null
Move-Item "$env:TEMP\strucrypt_${Version}_windows_amd64\strucrypt.exe" $Dest -Force
setx PATH "$env:PATH;$Dest"
```

**From source**, into `$(go env GOPATH)/bin`:

```sh
go install github.com/MarwinMoellers/strucrypt/cmd/strucrypt@latest
```

Check it worked with `strucrypt version`. Each release also ships
`checksums.txt` if you want to verify the download.

## Quick start

Set up a repo (first person to introduce strucrypt):

```sh
strucrypt init                 # generates a password — store it now
strucrypt add "secrets/*.pem"  # register what to encrypt
git add . && git commit -m "encrypt secrets"
```

`.strucrypt.yaml` and `.gitattributes` are committed and shared; the password
is not — distribute it to your team out of band.

Join an existing repo, after cloning:

```sh
strucrypt init '<the shared password>'
```

A clone that never runs `init` still works normally — `clone`, `pull`,
`commit`, and `push` all succeed, the managed files just stay encrypted on
disk.

## Commands

| Command | What it does |
| --- | --- |
| `strucrypt init [password]` | Bootstrap a repo, or join one with the shared password |
| `strucrypt add <glob>` | Register a whole-file encryption rule |
| `strucrypt version` | Print the build version |

`strucrypt clean` and `strucrypt smudge` exist for git to call; you never run
them yourself.
