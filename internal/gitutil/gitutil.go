// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

// Package gitutil shells out to the git binary for the handful of
// operations nebel needs: locating the repository root and reading or
// writing local (not committed) git config.
package gitutil

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// RepoRoot returns the absolute path to the top level of the current git
// working tree.
func RepoRoot() (string, error) {
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", fmt.Errorf("gitutil: not inside a git repository: %w", wrapExitErr(err))
	}
	return strings.TrimSpace(string(out)), nil
}

// ConfigGet reads a local (per-clone, not committed) git config value. The
// second return value is false if the key is not set — that is not an
// error, since "no local key registered" is a valid, expected state (spec
// 06 AC-6.6).
func ConfigGet(key string) (string, bool, error) {
	out, err := exec.Command("git", "config", "--local", "--get", key).Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			return "", false, nil
		}
		return "", false, fmt.Errorf("gitutil: git config --get %s: %w", key, wrapExitErr(err))
	}
	return strings.TrimSpace(string(out)), true, nil
}

// ConfigSet writes a local (per-clone, not committed) git config value.
func ConfigSet(key, value string) error {
	if err := exec.Command("git", "config", "--local", key, value).Run(); err != nil {
		return fmt.Errorf("gitutil: git config %s: %w", key, wrapExitErr(err))
	}
	return nil
}

// ConfigGetRegexp reads every local (per-clone, not committed) git config
// value whose key matches pattern (an extended regular expression, per
// `git config --get-regexp`). A nil, empty map is returned, not an error,
// when nothing matches.
func ConfigGetRegexp(pattern string) (map[string]string, error) {
	out, err := exec.Command("git", "config", "--local", "--get-regexp", pattern).Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			return map[string]string{}, nil
		}
		return nil, fmt.Errorf("gitutil: git config --get-regexp %s: %w", pattern, wrapExitErr(err))
	}

	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		if line == "" {
			continue
		}
		key, value, _ := strings.Cut(line, " ")
		values[key] = value
	}
	return values, nil
}

// Add stages paths (repo-relative) with `git add`. Used by `nebel rotate`
// to stage the config it just rewrote, and leaves committing to the
// operator.
func Add(repoRoot string, paths ...string) error {
	args := append([]string{"add", "--"}, paths...)
	cmd := exec.Command("git", args...)
	cmd.Dir = repoRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("gitutil: git add: %w: %s", wrapExitErr(err), strings.TrimSpace(string(out)))
	}
	return nil
}

// RenormalizeAll force-reencrypts every nebel-managed file/field under the
// config's *current* key version, regardless of what version each
// previously carried, and stages the result — the `git add --renormalize`
// escape hatch (spec 11 AC-11.10), run automatically by `nebel rotate` so
// existing content doesn't need a manual follow-up to actually move onto
// the version rotate just minted.
//
// This only ever needs the *current* version's key: clean always encrypts
// under it regardless of a file's prior tag (spec 06 AC-6.12), and rotate
// has just derived and registered that key locally before calling this —
// so, unlike CheckoutAll's smudge (which needs whichever version's key a
// value's own tag names), the `git add --renormalize` call itself is
// expected to always succeed.
//
// It can still be a no-op for a given path even so: a mode: value field,
// or a mode: file whole file, that's still sitting as ciphertext
// passthrough because this clone was never able to decrypt it in the
// first place (e.g. it names a version this clone hasn't fetched via
// `nebel init --version N`) looks the same to clean as any other
// already-encrypted value (AC-6.4) and is left untouched. The returned
// slice reflects only the paths that actually ended up staged with new
// content, so a caller reporting "N re-encrypted" doesn't overcount those.
func RenormalizeAll(repoRoot string) ([]string, error) {
	files, err := ManagedFiles(repoRoot)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, nil
	}

	args := append([]string{"add", "--renormalize", "--"}, files...)
	cmd := exec.Command("git", args...)
	cmd.Dir = repoRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("gitutil: git add --renormalize: %w: %s", wrapExitErr(err), strings.TrimSpace(string(out)))
	}

	diffArgs := append([]string{"diff", "--cached", "--name-only", "--"}, files...)
	diffCmd := exec.Command("git", diffArgs...)
	diffCmd.Dir = repoRoot
	out, err := diffCmd.Output()
	if err != nil {
		return nil, fmt.Errorf("gitutil: git diff --cached: %w", wrapExitErr(err))
	}
	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" {
		return nil, nil
	}
	return strings.Split(trimmed, "\n"), nil
}

// Show returns path's content as committed at commit (e.g. "HEAD" or a
// specific SHA), bypassing any clean/smudge filter — `git show` reads the
// raw blob directly.
func Show(repoRoot, commit, path string) ([]byte, error) {
	cmd := exec.Command("git", "show", commit+":"+path)
	cmd.Dir = repoRoot
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("gitutil: git show %s:%s: %w", commit, path, wrapExitErr(err))
	}
	return out, nil
}

// Log returns the hash of every commit that touched path, newest first. A
// nil, empty slice (not an error) means path has no history reachable from
// HEAD — either it was never committed, or (see IsShallow) this clone's
// history doesn't reach far enough back to see it.
func Log(repoRoot, path string) ([]string, error) {
	cmd := exec.Command("git", "log", "--format=%H", "--", path)
	cmd.Dir = repoRoot
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("gitutil: git log %s: %w", path, wrapExitErr(err))
	}
	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" {
		return nil, nil
	}
	return strings.Split(trimmed, "\n"), nil
}

// IsShallow reports whether repoRoot is a shallow clone (truncated
// history) — relevant when Log or a history walk built on it comes back
// empty or incomplete, since that can mean "never existed" or "exists,
// just not fetched" depending on this.
func IsShallow(repoRoot string) (bool, error) {
	cmd := exec.Command("git", "rev-parse", "--is-shallow-repository")
	cmd.Dir = repoRoot
	out, err := cmd.Output()
	if err != nil {
		return false, fmt.Errorf("gitutil: git rev-parse --is-shallow-repository: %w", wrapExitErr(err))
	}
	return strings.TrimSpace(string(out)) == "true", nil
}

// CheckoutFailure records why one managed file couldn't be re-smudged —
// git's own trimmed error output, which already carries nebel's specific
// message (AC-6.9's tamper error, say) rather than a cause CheckoutAll's
// caller would otherwise have to guess at. A missing key version is not
// one of these: spec 06 AC-6.11 has smudge pass that content through as
// ciphertext instead of failing, so CheckoutAll counts it as decrypted;
// cmd/nebel's scanUndecrypted re-inspects the working tree afterward to
// catch that gap for reporting.
type CheckoutFailure struct {
	Path   string
	Reason string
}

// CheckoutAll re-smudges every tracked file that the nebel filter
// manages — used after `nebel init` registers the filter, so files
// smudged as ciphertext passthrough before init ran are replaced with
// their decrypted content (spec 07 AC-7.8).
//
// Neither `git checkout -- .` nor `git checkout-index --force --all` is
// enough here: empirically, both skip re-running the smudge filter on a
// file whose working tree content git believes already matches the index,
// even with --force. Deleting the file first removes that shortcut — git
// has no choice but to recreate it from the index, through the filter.
//
// Files are checked out one at a time rather than in a single `git
// checkout HEAD -- <all paths>` call. A single call is all-or-nothing:
// empirically, one path whose smudge fails (AC-6.9's tamper detection —
// a missing key version, spec 06 AC-6.11, no longer fails here; it
// passes through instead) aborts the whole command, and — since every
// path was already removed above — leaves every managed file missing
// from the working tree, not just the one that failed. Checking out
// individually isolates that failure to just its own path, which
// CheckoutAll then falls back to restoring as raw ciphertext (via Show,
// which bypasses filters) so it at least matches the pre-CheckoutAll
// passthrough state instead of being left deleted, and reports git's own
// error for that path rather than assuming a cause.
//
// decrypted+len(failures) == total managed files; total == 0 means no
// managed files exist at all (e.g. .gitattributes was never committed).
func CheckoutAll(repoRoot string) (decrypted int, failures []CheckoutFailure, err error) {
	files, err := ManagedFiles(repoRoot)
	if err != nil {
		return 0, nil, err
	}
	if len(files) == 0 {
		return 0, nil, nil
	}

	for _, f := range files {
		if err := os.Remove(filepath.Join(repoRoot, f)); err != nil && !os.IsNotExist(err) {
			return 0, nil, fmt.Errorf("gitutil: removing %s before re-checkout: %w", f, err)
		}
	}

	for _, f := range files {
		cmd := exec.Command("git", "checkout", "HEAD", "--", f)
		cmd.Dir = repoRoot
		out, checkoutErr := cmd.CombinedOutput()
		if checkoutErr == nil {
			decrypted++
			continue
		}

		raw, showErr := Show(repoRoot, "HEAD", f)
		if showErr != nil {
			return decrypted, failures, fmt.Errorf("gitutil: restoring %s after failed checkout: %w", f, showErr)
		}
		if writeErr := os.WriteFile(filepath.Join(repoRoot, f), raw, 0o644); writeErr != nil {
			return decrypted, failures, fmt.Errorf("gitutil: restoring %s after failed checkout: %w", f, writeErr)
		}
		failures = append(failures, CheckoutFailure{Path: f, Reason: strings.TrimSpace(string(out))})
	}
	return decrypted, failures, nil
}

// ManagedFiles returns the repo-relative paths of every tracked file
// whose "filter" gitattribute is "nebel".
func ManagedFiles(repoRoot string) ([]string, error) {
	lsCmd := exec.Command("git", "ls-files")
	lsCmd.Dir = repoRoot
	lsOut, err := lsCmd.Output()
	if err != nil {
		return nil, fmt.Errorf("gitutil: git ls-files: %w", wrapExitErr(err))
	}
	tracked := strings.Split(strings.TrimSpace(string(lsOut)), "\n")
	if len(tracked) == 1 && tracked[0] == "" {
		return nil, nil
	}

	args := append([]string{"check-attr", "filter", "--"}, tracked...)
	attrCmd := exec.Command("git", args...)
	attrCmd.Dir = repoRoot
	attrOut, err := attrCmd.Output()
	if err != nil {
		return nil, fmt.Errorf("gitutil: git check-attr: %w", wrapExitErr(err))
	}

	var managed []string
	for _, line := range strings.Split(string(attrOut), "\n") {
		// Each line: "<path>: filter: <value>". The path itself may
		// contain ": " in theory; check-attr escapes with quotes in that
		// case, which this simple split does not handle — acceptable for
		// the MVP's file-selection use case.
		path, rest, ok := strings.Cut(line, ": filter: ")
		if !ok || rest == "unspecified" || rest != "nebel" {
			continue
		}
		managed = append(managed, path)
	}
	return managed, nil
}

// wrapExitErr surfaces stderr from an *exec.ExitError, since Output()
// alone reports only "exit status N".
func wrapExitErr(err error) error {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
		return fmt.Errorf("%s (%w)", strings.TrimSpace(string(exitErr.Stderr)), err)
	}
	return err
}
