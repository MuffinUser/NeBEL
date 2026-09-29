// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

// Package localkey stores derived AES-256-SIV keys locally (per-clone, not
// committed), so their presence or absence is exactly the "has this
// machine run `nebel init`" signal the clean/smudge filter needs for
// no-key passthrough (spec 06 AC-6.6).
//
// A machine may hold more than one key version at once (spec 11): every
// version it has ever derived via `nebel init` or `nebel rotate` stays
// cached, so it keeps being able to read content tagged with an older
// version after the project rotates.
//
// Keys sit in plaintext in a dedicated file inside the git directory (see
// keyFileName), never committed or pushed — the same trust boundary
// git-crypt and transcrypt rely on for the same purpose. A version
// registered before this file existed may still be found in the legacy
// location, local (not committed) git config (see readLegacyEntries); Get
// and All both still fall back to it, so an existing clone keeps working
// without needing to re-run `nebel init`. Set only ever writes to the new
// file.
package localkey

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/MuffinUser/nebel/internal/gitutil"
)

// configKeyPrefix is the local git config variable a version's key was
// stored under before this file existed (see readLegacyEntries) — still
// read, for backward compatibility, but no longer written. Git config
// variable names may not contain "." themselves (only section/subsection
// separators may), so later versions suffixed the number directly onto
// the name (key2, key3, ...) rather than adding another dot-separated
// segment; version 1 kept the unsuffixed name every clone created before
// key rotation existed already wrote and read.
const configKeyPrefix = "filter.nebel.key"

// keyFileName is the file, inside the git directory shared by every
// worktree of a clone (see gitCommonDir), that Set registers a key to.
//
// It replaces `git config --local <key> <value>` as of the 2026-09-29
// audit's P06 finding: that is a subprocess invocation, and its only way
// to set a value is to pass it as a literal argument — putting a
// ready-to-use derived decryption key directly into that process's
// argument list, readable by any other local user or process with
// sufficient privilege via /proc/<pid>/cmdline for as long as the
// subprocess runs. This is the same class of exposure
// cmd/nebel/password.go's ErrPasswordArgument already refuses for the
// shared password itself; the derived key is at least as sensitive, and
// wasn't getting the same protection. Writing this file directly with
// Go's os package instead never puts the key on any process's argument
// list. Its 0o600 permissions (see writeKeyFile) are also a direct answer
// to a related, separate suggestion in the same audit to harden local key
// storage beyond .git/config's ambient permissions.
const keyFileName = "nebel-keys"

// configKeyFor returns the legacy git config key a given version's key
// used to be stored under.
func configKeyFor(version int) string {
	if version == 1 {
		return configKeyPrefix
	}
	return fmt.Sprintf("%s%d", configKeyPrefix, version)
}

// gitCommonDir returns the git directory shared across every worktree of
// this clone, as opposed to a linked worktree's own private git dir.
// Local git config is shared there by default (splitting it per-worktree
// requires the rare extensions.worktreeConfig) — storing the key file
// alongside it keeps it visible to every worktree exactly like the config
// entries it replaces were.
func gitCommonDir() (string, error) {
	out, err := exec.Command("git", "rev-parse", "--git-common-dir").Output()
	if err != nil {
		return "", fmt.Errorf("localkey: git rev-parse --git-common-dir: %w", err)
	}
	dir := strings.TrimSpace(string(out))
	if !filepath.IsAbs(dir) {
		// git commonly reports this relative to the caller's working
		// directory (typically ".git") rather than as an absolute path.
		abs, err := filepath.Abs(dir)
		if err != nil {
			return "", fmt.Errorf("localkey: resolving git common dir %q: %w", dir, err)
		}
		dir = abs
	}
	return dir, nil
}

func keyFilePath() (string, error) {
	dir, err := gitCommonDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, keyFileName), nil
}

// readKeyFile parses the key file into version -> base64-encoded key. A
// missing file is not an error: it means Set has never been called on
// this clone, or every key it holds still lives only in the legacy
// git-config location (see readLegacyEntries).
func readKeyFile() (map[int]string, error) {
	path, err := keyFilePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[int]string{}, nil
		}
		return nil, fmt.Errorf("localkey: reading %s: %w", path, err)
	}

	entries := map[int]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		versionStr, encoded, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("localkey: malformed line in %s: %q", path, line)
		}
		version, err := strconv.Atoi(versionStr)
		if err != nil {
			return nil, fmt.Errorf("localkey: malformed version in %s: %q", path, line)
		}
		entries[version] = encoded
	}
	return entries, nil
}

// writeKeyFile serializes entries, one "version=base64key" line each in
// ascending version order (so the file diffs sensibly if ever inspected,
// though it is never committed), and writes them to the key file with
// 0o600 permissions — owner read/write only.
func writeKeyFile(entries map[int]string) error {
	path, err := keyFilePath()
	if err != nil {
		return err
	}

	versions := make([]int, 0, len(entries))
	for v := range entries {
		versions = append(versions, v)
	}
	sort.Ints(versions)

	var b strings.Builder
	for _, v := range versions {
		fmt.Fprintf(&b, "%d=%s\n", v, entries[v])
	}

	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		return fmt.Errorf("localkey: writing %s: %w", path, err)
	}
	return nil
}

// readLegacyEntries reads every key still sitting in the pre-P06-fix
// storage location: local (not committed) git config, keyed by the same
// version numbers readKeyFile would use. A clone that registered a
// version before this file existed keeps it there — Set never migrates
// or deletes it — so Get and All both consult this as a fallback.
func readLegacyEntries() (map[int]string, error) {
	raw, err := gitutil.ConfigGetRegexp(`^filter\.nebel\.key[0-9]*$`)
	if err != nil {
		return nil, fmt.Errorf("localkey: listing registered keys: %w", err)
	}

	entries := map[int]string{}
	for name, encoded := range raw {
		version := 1
		if suffix, ok := strings.CutPrefix(name, configKeyPrefix); ok && suffix != "" {
			version, err = strconv.Atoi(suffix)
			if err != nil {
				return nil, fmt.Errorf("localkey: unexpected local config key %q", name)
			}
		}
		entries[version] = encoded
	}
	return entries, nil
}

func decodeKey(encoded string, version int) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("localkey: decoding stored key for version %d: %w", version, err)
	}
	return key, nil
}

// Get returns the locally registered key for version. ok is false, with a
// nil error, when that version is not registered yet.
func Get(version int) (key []byte, ok bool, err error) {
	entries, err := readKeyFile()
	if err != nil {
		return nil, false, err
	}
	if encoded, found := entries[version]; found {
		key, err := decodeKey(encoded, version)
		return key, true, err
	}

	legacy, err := readLegacyEntries()
	if err != nil {
		return nil, false, err
	}
	if encoded, found := legacy[version]; found {
		key, err := decodeKey(encoded, version)
		return key, true, err
	}
	return nil, false, nil
}

// Set registers key locally as version's key, writing it to the key file
// (see keyFileName's doc comment for why, in place of git config). Existing
// versions are left untouched (spec 11 AC-11.5): a machine that rotates,
// or fetches an older version via `nebel init --version N`, keeps reading
// everything it could read before — including anything still sitting in
// the legacy git-config location (see readLegacyEntries), which this
// never migrates or removes.
func Set(version int, key []byte) error {
	entries, err := readKeyFile()
	if err != nil {
		return err
	}
	entries[version] = base64.StdEncoding.EncodeToString(key)
	return writeKeyFile(entries)
}

// All returns every version currently registered locally, keyed by version
// number — merging the key file with anything still left in the legacy
// git-config location (a version present in both, which Set can no longer
// produce going forward, resolves to the key file's copy). An empty,
// non-nil map means no `nebel init` has ever run on this clone (spec 06
// AC-6.6's no-key passthrough state).
func All() (map[int][]byte, error) {
	keyring := map[int][]byte{}

	fileEntries, err := readKeyFile()
	if err != nil {
		return nil, err
	}
	for version, encoded := range fileEntries {
		key, err := decodeKey(encoded, version)
		if err != nil {
			return nil, err
		}
		keyring[version] = key
	}

	legacy, err := readLegacyEntries()
	if err != nil {
		return nil, err
	}
	for version, encoded := range legacy {
		if _, already := keyring[version]; already {
			continue
		}
		key, err := decodeKey(encoded, version)
		if err != nil {
			return nil, err
		}
		keyring[version] = key
	}
	return keyring, nil
}
