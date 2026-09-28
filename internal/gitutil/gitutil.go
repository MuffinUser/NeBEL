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
func CheckoutAll(repoRoot string) (int, error) {
	files, err := filterManagedFiles(repoRoot)
	if err != nil {
		return 0, err
	}
	if len(files) == 0 {
		return 0, nil
	}

	for _, f := range files {
		if err := os.Remove(filepath.Join(repoRoot, f)); err != nil && !os.IsNotExist(err) {
			return 0, fmt.Errorf("gitutil: removing %s before re-checkout: %w", f, err)
		}
	}

	args := append([]string{"checkout", "HEAD", "--"}, files...)
	cmd := exec.Command("git", args...)
	cmd.Dir = repoRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		return 0, fmt.Errorf("gitutil: git checkout: %w: %s", wrapExitErr(err), strings.TrimSpace(string(out)))
	}
	return len(files), nil
}

// filterManagedFiles returns the repo-relative paths of every tracked file
// whose "filter" gitattribute is "nebel".
func filterManagedFiles(repoRoot string) ([]string, error) {
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
