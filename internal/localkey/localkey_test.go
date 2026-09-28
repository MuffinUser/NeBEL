// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package localkey

import (
	"bytes"
	"os"
	"os/exec"
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

// version 1 is stored under the unsuffixed "filter.nebel.key" name — the
// same one every clone created before key rotation existed already reads
// and writes — so an upgraded binary keeps recognizing a key an older
// binary registered.
func TestVersion1UsesLegacyConfigName(t *testing.T) {
	dir := newTempRepo(t)
	chdir(t, dir)

	key := bytes.Repeat([]byte{0x11}, 64)
	if err := Set(1, key); err != nil {
		t.Fatalf("Set: %v", err)
	}

	cmd := exec.Command("git", "config", "--local", "--get", "filter.nebel.key")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git config --get filter.nebel.key: %v", err)
	}
	if len(out) == 0 {
		t.Error("version 1's key was not stored under filter.nebel.key")
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
