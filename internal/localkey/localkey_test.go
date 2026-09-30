// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package localkey

import (
	"bytes"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func newTempRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	run("config", "user.email", "test@example.com")
	run("config", "user.name", "test")
	return dir
}

func chdir(t *testing.T, dir string) {
	t.Helper()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(orig) })
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
}

// Get on a clone that has never run `nebel init` reports no entry, not an
// error (spec 06 AC-6.6's no-key passthrough state).
func TestGetUnregistered(t *testing.T) {
	chdir(t, newTempRepo(t))

	if _, ok, err := Get(1); err != nil || ok {
		t.Fatalf("Get(1) on an empty keyring: ok=%v err=%v, want ok=false err=nil", ok, err)
	}
}

// Set/Get round-trips a key for a given version.
func TestSetGetRoundTrip(t *testing.T) {
	chdir(t, newTempRepo(t))

	key := bytes.Repeat([]byte{0x42}, 64)
	if err := Set(1, key); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, ok, err := Get(1)
	if err != nil || !ok {
		t.Fatalf("Get(1) after Set: ok=%v err=%v", ok, err)
	}
	if !bytes.Equal(got, key) {
		t.Errorf("Get(1) = %x, want %x", got, key)
	}
}

// Regression test for the 2026-09-29 audit's P06: Set must never put the
// key anywhere `git config` can reach, since writing it there is exactly
// what required exposing it as a subprocess argument in the first place.
// This directly proves the exposure path is closed: the base64 key must
// not appear anywhere in .git/config's raw file content after Set.
//
// The audit's actual concern — the key briefly appearing in a process's
// argument list, visible to another local user via /proc/<pid>/cmdline —
// isn't itself observable from a Go test, since the git subprocess that
// used to receive it exits before a test could inspect its argv. Proving
// the key no longer ends up as a plain git-config value at all is the
// most direct available proxy: getting it there is exactly what forced
// passing it as a `git config` argument to begin with, so its absence
// here means that argument was never made.
func TestSetNeverWritesToGitConfig(t *testing.T) {
	dir := newTempRepo(t)
	chdir(t, dir)

	key := bytes.Repeat([]byte{0x11}, 64)
	if err := Set(1, key); err != nil {
		t.Fatalf("Set: %v", err)
	}

	configPath := filepath.Join(dir, ".git", "config")
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("reading .git/config: %v", err)
	}
	encoded := base64.StdEncoding.EncodeToString(key)
	if strings.Contains(string(raw), encoded) {
		t.Errorf(".git/config contains the key after Set:\n%s", raw)
	}
	if strings.Contains(string(raw), "filter.nebel.key") {
		t.Errorf(".git/config contains a filter.nebel.key entry after Set:\n%s", raw)
	}
}

// The key file Set writes to must be readable only by its owner —
// tighter than .git/config's ambient permissions, and a direct answer to
// a related "harden local key storage" suggestion from the same audit.
func TestKeyFileHasOwnerOnlyPermissions(t *testing.T) {
	dir := newTempRepo(t)
	chdir(t, dir)

	if err := Set(1, bytes.Repeat([]byte{0x11}, 64)); err != nil {
		t.Fatalf("Set: %v", err)
	}

	info, err := os.Stat(filepath.Join(dir, ".git", keyFileName))
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file permissions = %o, want 0600", perm)
	}
}

// Backward compatibility: a version registered the old way, directly in
// local git config (as every clone did before this fix), must still be
// found by Get and All — an existing clone must keep working without
// needing to re-run `nebel init` just because this shipped.
func TestGetAndAllFallBackToLegacyGitConfig(t *testing.T) {
	dir := newTempRepo(t)
	chdir(t, dir)

	key := bytes.Repeat([]byte{0x22}, 64)
	cmd := exec.Command("git", "config", "--local", "filter.nebel.key", base64.StdEncoding.EncodeToString(key))
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git config: %v\n%s", err, out)
	}

	got, ok, err := Get(1)
	if err != nil || !ok {
		t.Fatalf("Get(1) for a legacy-registered key: ok=%v err=%v", ok, err)
	}
	if !bytes.Equal(got, key) {
		t.Errorf("Get(1) = %x, want %x", got, key)
	}

	all, err := All()
	if err != nil {
		t.Fatalf("All: %v", err)
	}
	if !bytes.Equal(all[1], key) {
		t.Errorf("All()[1] = %x, want %x", all[1], key)
	}
}

// Set never disturbs an existing version's entry (spec 11 AC-11.5): a
// machine that rotates, or fetches an older version, keeps reading
// everything it could read before.
func TestSetIsAdditiveAcrossVersions(t *testing.T) {
	chdir(t, newTempRepo(t))

	key1 := bytes.Repeat([]byte{0x01}, 64)
	key2 := bytes.Repeat([]byte{0x02}, 64)
	if err := Set(1, key1); err != nil {
		t.Fatalf("Set(1): %v", err)
	}
	if err := Set(2, key2); err != nil {
		t.Fatalf("Set(2): %v", err)
	}

	got1, ok, err := Get(1)
	if err != nil || !ok || !bytes.Equal(got1, key1) {
		t.Errorf("Get(1) after Set(2) = %x, ok=%v err=%v, want %x", got1, ok, err, key1)
	}
	got2, ok, err := Get(2)
	if err != nil || !ok || !bytes.Equal(got2, key2) {
		t.Errorf("Get(2) = %x, ok=%v err=%v, want %x", got2, ok, err, key2)
	}
}

// All returns an empty, non-nil map on a clone that has never run
// `nebel init` — the caller's signal for the empty-keyring passthrough
// state (spec 06 AC-6.6).
func TestAllEmpty(t *testing.T) {
	chdir(t, newTempRepo(t))

	got, err := All()
	if err != nil {
		t.Fatalf("All: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("All() on an empty keyring = %v, want empty", got)
	}
}

// All enumerates every registered version, regardless of how many have
// been added.
func TestAllEnumeratesEveryVersion(t *testing.T) {
	chdir(t, newTempRepo(t))

	keys := map[int][]byte{
		1: bytes.Repeat([]byte{0x01}, 64),
		2: bytes.Repeat([]byte{0x02}, 64),
		3: bytes.Repeat([]byte{0x03}, 64),
	}
	for version, key := range keys {
		if err := Set(version, key); err != nil {
			t.Fatalf("Set(%d): %v", version, err)
		}
	}

	got, err := All()
	if err != nil {
		t.Fatalf("All: %v", err)
	}
	if len(got) != len(keys) {
		t.Fatalf("All() returned %d versions, want %d: %v", len(got), len(keys), got)
	}
	for version, want := range keys {
		if !bytes.Equal(got[version], want) {
			t.Errorf("All()[%d] = %x, want %x", version, got[version], want)
		}
	}
}

// Regression test for the 2026-09-30 re-audit's R04: writeKeyFile must
// replace the key file atomically (temp file + rename) rather than
// truncating it in place, so a reader never observes a partially-written
// file, and no stray temp file is left behind on the success path.
func TestWriteKeyFileReplacesAtomicallyAndLeavesNoTempFile(t *testing.T) {
	dir := newTempRepo(t)
	chdir(t, dir)

	if err := Set(1, bytes.Repeat([]byte{0x11}, 64)); err != nil {
		t.Fatalf("Set(1): %v", err)
	}
	// Overwrite with a second Set, so writeKeyFile actually replaces
	// existing content rather than just creating the file for the first
	// time.
	if err := Set(2, bytes.Repeat([]byte{0x22}, 64)); err != nil {
		t.Fatalf("Set(2): %v", err)
	}

	gitDir := filepath.Join(dir, ".git")
	entries, err := os.ReadDir(gitDir)
	if err != nil {
		t.Fatalf("reading %s: %v", gitDir, err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("leftover temp file after Set: %s", e.Name())
		}
	}

	got, err := All()
	if err != nil {
		t.Fatalf("All: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("All() = %v, want exactly versions 1 and 2", got)
	}
	if !bytes.Equal(got[1], bytes.Repeat([]byte{0x11}, 64)) {
		t.Errorf("All()[1] = %x, want the version-1 key", got[1])
	}
	if !bytes.Equal(got[2], bytes.Repeat([]byte{0x22}, 64)) {
		t.Errorf("All()[2] = %x, want the version-2 key", got[2])
	}

	info, err := os.Stat(filepath.Join(gitDir, keyFileName))
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file permissions after replace = %o, want 0600", perm)
	}
}

// Regression test for R04: concurrent Set calls from goroutines within
// the same process must not lose an update to the read-modify-write
// sequence (readKeyFile, mutate, writeKeyFile) that Set performs.
func TestConcurrentSetDoesNotLoseUpdates(t *testing.T) {
	chdir(t, newTempRepo(t))

	const n = 20
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := bytes.Repeat([]byte{byte(i + 1)}, 64)
			errs[i] = Set(i+1, key)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("Set(%d): %v", i+1, err)
		}
	}

	got, err := All()
	if err != nil {
		t.Fatalf("All: %v", err)
	}
	if len(got) != n {
		t.Fatalf("All() has %d versions after %d concurrent Set calls, want %d: %v", len(got), n, n, got)
	}
	for i := 0; i < n; i++ {
		want := bytes.Repeat([]byte{byte(i + 1)}, 64)
		if !bytes.Equal(got[i+1], want) {
			t.Errorf("All()[%d] = %x, want %x", i+1, got[i+1], want)
		}
	}
}

// All must not pick up unrelated filter.nebel.* config (e.g.
// filter.nebel.required, registered by `nebel init` alongside the key).
func TestAllIgnoresUnrelatedFilterConfig(t *testing.T) {
	dir := newTempRepo(t)
	chdir(t, dir)

	if err := Set(1, bytes.Repeat([]byte{0x01}, 64)); err != nil {
		t.Fatalf("Set: %v", err)
	}
	cmd := exec.Command("git", "config", "--local", "filter.nebel.required", "true")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git config: %v\n%s", err, out)
	}
	cmd = exec.Command("git", "config", "--local", "filter.nebel.clean", "nebel clean %f")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git config: %v\n%s", err, out)
	}

	got, err := All()
	if err != nil {
		t.Fatalf("All: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("All() = %v, want exactly version 1", got)
	}
}
