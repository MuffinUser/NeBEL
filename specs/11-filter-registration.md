# Spec 11 — Filter registration path

How git is pointed at the strucrypt binary. See README § Install,
§ Troubleshooting.

## Rationale

Registering the filter as the bare name `strucrypt` makes every git
operation depend on the `PATH` of whatever process launched git. That
process is frequently not a fresh login shell. A Windows process inherits
its environment at start and keeps it, so an IDE that was open when
strucrypt was installed passes a stale `PATH` to its embedded terminal and
to its bundled git; the filter then fails with
`external filter 'strucrypt clean %f' failed 127`, while the same command
works in a newly opened terminal. Neither `~/.bashrc` nor `~/.bash_profile`
helps, because git invokes filters through a non-interactive, non-login
`sh -c`, which reads neither.

Recording an absolute path at `init` time removes `PATH` from git's side of
the problem entirely. `PATH` still matters for the user typing `strucrypt`,
which is an install-script concern, not a git one.

## Acceptance criteria

- **AC-11.1**: `init` registers `filter.strucrypt.clean` and `.smudge` as
  the **absolute path** of the running binary, never a bare name.
- **AC-11.2**: on Windows the recorded path uses forward slashes, and is
  double-quoted when it contains a space or any other character the shell
  would otherwise split on or interpret (`C:\Program Files\...`, a
  non-ASCII user name).
- **AC-11.3**: a backslash in a path is treated as a separator only on
  Windows — on Unix, where it is a legal filename character, it is escaped
  and preserved.
- **AC-11.4**: after `init`, a full `git add` / `git commit` / `git
  checkout` round trip succeeds with **no** strucrypt binary reachable on
  git's `PATH`.
- **AC-11.5**: re-running `init` on a clone carrying an older bare-name
  registration replaces it with the absolute path (the documented repair
  for clones set up by an earlier version). This refines spec 07 AC-7.9:
  re-running `init` stays safe and idempotent, but filter registration is
  refreshed rather than left untouched.
