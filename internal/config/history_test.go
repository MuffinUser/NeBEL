// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

func commitConfig(t *testing.T, dir, contents string) {
	t.Helper()
	path := filepath.Join(dir, FileName)
	if err := os.WriteFile(path, []byte(strings.TrimLeft(contents, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("add", "--", FileName)
	run("commit", "-q", "-m", "update "+FileName)
}

// AC-4.9: the config's own current version is found without touching git
// history at all — the fast path, and the only one that works for a
// version rotated locally but not yet committed.
func TestLookupVersionReturnsCurrentDirectly(t *testing.T) {
	current := &Config{
		KeyVersion: 3,
		Salt:       "current-salt",
		Canary:     "current-canary",
	}
	got, err := LookupVersion(t.TempDir(), current, 3)
	if err != nil {
		t.Fatalf("LookupVersion: %v", err)
	}
	if got.Salt != "current-salt" || got.Canary != "current-canary" {
		t.Errorf("LookupVersion(current) = %+v, want current's own salt/canary", got)
	}
}

// AC-4.9: an older version is found by walking .nebel.yaml's own commit
// history for the (unique) commit that introduced it.
func TestLookupVersionWalksHistory(t *testing.T) {
	dir := newTempRepo(t)
	commitConfig(t, dir, `
key_version: 1
salt: c2FsdC12ZXJzaW9uLW9uZS0tLS0=
canary: "ENC[AES256_SIV,key:1,data:aGVsbG8=]"
rules: []
`)
	commitConfig(t, dir, `
key_version: 2
salt: c2FsdC12ZXJzaW9uLXR3by0tLS0=
canary: "ENC[AES256_SIV,key:2,data:aGVsbG8=]"
rules: []
`)

	current := &Config{
		KeyVersion: 2,
		Salt:       "c2FsdC12ZXJzaW9uLXR3by0tLS0=",
		Canary:     `ENC[AES256_SIV,key:2,data:aGVsbG8=]`,
	}

	got, err := LookupVersion(dir, current, 1)
	if err != nil {
		t.Fatalf("LookupVersion(1): %v", err)
	}
	if got.Salt != "c2FsdC12ZXJzaW9uLW9uZS0tLS0=" {
		t.Errorf("LookupVersion(1).Salt = %q, want version 1's salt", got.Salt)
	}
	if got.Canary != `ENC[AES256_SIV,key:1,data:aGVsbG8=]` {
		t.Errorf("LookupVersion(1).Canary = %q, want version 1's canary", got.Canary)
	}
}

// AC-4.9: a version that never existed in the history is a clear error,
// not an empty/zero result.
func TestLookupVersionUnknownFails(t *testing.T) {
	dir := newTempRepo(t)
	commitConfig(t, dir, `
key_version: 1
salt: c2FsdC12ZXJzaW9uLW9uZS0tLS0=
canary: "ENC[AES256_SIV,key:1,data:aGVsbG8=]"
rules: []
`)
	current := &Config{KeyVersion: 1, Salt: "c2FsdC12ZXJzaW9uLW9uZS0tLS0=", Canary: `ENC[AES256_SIV,key:1,data:aGVsbG8=]`}

	if _, err := LookupVersion(dir, current, 99); err == nil {
		t.Fatal("LookupVersion(99): want an error, got nil")
	}
}
