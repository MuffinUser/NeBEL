# strucrypt

Encrypt secrets in place so they can live safely in the git repo, with
transparent local decryption. Encryption happens on `git add`, decryption on
checkout, via git's clean/smudge filter driver — day to day you just use git.

## Install

One static binary. Put it anywhere and add that directory to your `PATH` so
you can run `strucrypt` yourself; `strucrypt init` then records the binary's
**absolute path** in the repo's local git config, so git never has to find
it on `PATH` (see [Troubleshooting](#troubleshooting)). Get the archive onto
the machine however you like (from
[Releases](https://github.com/MarwinMoellers/strucrypt/releases), a share, a
USB stick); the steps below install from that local file and need no
internet. Adjust the filename to your version.

**Windows** (PowerShell):

```powershell
$Zip  = "$HOME\Downloads\strucrypt_v0.2.0_windows_amd64.zip"
$Dest = "$env:LOCALAPPDATA\Programs\strucrypt"

Unblock-File $Zip     # clears the "downloaded from the internet" mark
Expand-Archive $Zip -DestinationPath $env:TEMP\strucrypt-install -Force
New-Item -ItemType Directory -Force -Path $Dest | Out-Null
Copy-Item "$env:TEMP\strucrypt-install\*\strucrypt.exe" $Dest -Force

# Persist on the user PATH (for cmd, PowerShell, and apps started later)...
$UserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($UserPath -split ';' -notcontains $Dest) {
  [Environment]::SetEnvironmentVariable('Path', "$UserPath;$Dest", 'User')
}
# ...and in this shell, so you don't have to reopen it.
$env:Path += ";$Dest"

# Git Bash builds its PATH from the Windows one at launch, so a Git Bash
# inside an already-running IDE keeps the old copy. Sourcing it from
# ~/.bash_profile makes every Git Bash pick it up regardless.
$Posix  = '/' + $Dest.Substring(0,1).ToLower() + $Dest.Substring(2).Replace('\','/')
$BashRC = "$HOME\.bash_profile"
$Marker = '# added by strucrypt'
if (-not (Test-Path $BashRC) -or
    -not (Select-String -Path $BashRC -SimpleMatch $Marker -Quiet)) {
  [IO.File]::AppendAllText($BashRC, "`nexport PATH=`"`$PATH:$Posix`"  $Marker`n",
    (New-Object Text.UTF8Encoding $false))
}
```

**macOS** (`amd64` instead of `arm64` on Intel):

```sh
tar -xzf ~/Downloads/strucrypt_v0.2.0_darwin_arm64.tar.gz -C /tmp
sudo mv /tmp/strucrypt_*_darwin_*/strucrypt /usr/local/bin/
xattr -d com.apple.quarantine /usr/local/bin/strucrypt   # if Gatekeeper blocks it
```

**From source**: `go build -o strucrypt ./cmd/strucrypt`, then move it onto
your `PATH`.

Check with `strucrypt version`.

## Quick start

Set up a repo (first person to introduce strucrypt):

```sh
strucrypt init                 # generates a password — store it now
strucrypt add "secrets/*.pem"  # register what to encrypt
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

## Commands

| Command | What it does |
| --- | --- |
| `strucrypt init [--password-stdin]` | Bootstrap a repo, or join one with the shared password |
| `strucrypt add <glob>` | Register a whole-file encryption rule |
| `strucrypt version` | Print the build version |

`strucrypt clean` and `strucrypt smudge` exist for git to call; you never run
them yourself.

## Troubleshooting

### "strucrypt: command not found" from IntelliJ, but it works in a terminal

The usual symptom on Windows, and the reason `init` records an absolute
path. Staging a managed file fails with:

```
error: external filter 'strucrypt clean %f' failed 127
```

A process inherits its environment when it starts and keeps it. Adding a
directory to the user `PATH` therefore reaches only processes started
*afterwards* — an IDE that was already open keeps the old `PATH`, hands that
copy to its embedded terminal and to every `git` it launches, and git's
filter driver cannot resolve a bare `strucrypt`.

Fixes:

1. **Re-run `strucrypt init`** in the affected clone (it prompts for the
   shared password again). This rewrites `filter.strucrypt.clean` /
   `.smudge` in `.git/config` to the binary's absolute path, so `PATH`
   stops mattering for git. Clones set up by an older strucrypt keep the
   old bare-name registration until you do this — check with
   `git config --get filter.strucrypt.clean`.
2. **Fully restart the IDE** — *File → Exit*, not just closing the project
   window, which leaves the process running with the stale environment.

Note that `~/.bashrc` and `~/.bash_profile` do **not** help git here: git
runs filters through a non-interactive, non-login `sh -c`, which reads
neither. They only affect Git Bash prompts you type into.

### Git Bash can't find `strucrypt` even after a restart

Git Bash derives its `PATH` from the Windows `PATH` at launch. If the
install script's `~/.bash_profile` line is missing, add it by hand —
translating the Windows path to its POSIX form:

```sh
echo 'export PATH="$PATH:/c/Users/<you>/AppData/Local/Programs/strucrypt"' \
  >> ~/.bash_profile
```

### Secrets were committed in plaintext

Check that `git config --get filter.strucrypt.required` is `true`. When it
is not, git treats a filter that fails to run as a warning and stages the
file unchanged. Re-running `strucrypt init` restores it.
