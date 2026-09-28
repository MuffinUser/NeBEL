// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package gitutil

import (
	"os"
	"os/exec"
	"path/filepath"
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

func TestRepoRoot(t *testing.T) {
	dir := newTempRepo(t)
	nested := filepath.Join(dir, "a", "b")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}

	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(orig)

	if err := os.Chdir(nested); err != nil {
		t.Fatal(err)
	}

	root, err := RepoRoot()
	if err != nil {
		t.Fatalf("RepoRoot: %v", err)
	}
	// Resolve symlinks on both sides (macOS /tmp is a symlink to /private/tmp).
	wantResolved, _ := filepath.EvalSymlinks(dir)
	gotResolved, _ := filepath.EvalSymlinks(root)
	if gotResolved != wantResolved {
		t.Errorf("RepoRoot() = %q, want %q", root, dir)
	}
}

func TestRepoRootOutsideGit(t *testing.T) {
	dir := t.TempDir() // not a git repo
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(orig)
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	if _, err := RepoRoot(); err == nil {
		t.Error("RepoRoot() outside a git repository: want an error, got nil")
	}
}

func TestConfigGetSetRoundTrip(t *testing.T) {
	dir := newTempRepo(t)
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(orig)
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	if _, ok, err := ConfigGet("filter.strucrypt.key"); err != nil || ok {
		t.Fatalf("ConfigGet() on unset key: ok=%v err=%v, want ok=false err=nil", ok, err)
	}

	if err := ConfigSet("filter.strucrypt.key", "abc123"); err != nil {
		t.Fatalf("ConfigSet: %v", err)
	}

	got, ok, err := ConfigGet("filter.strucrypt.key")
	if err != nil || !ok {
		t.Fatalf("ConfigGet() after set: ok=%v err=%v, want ok=true err=nil", ok, err)
	}
	if got != "abc123" {
		t.Errorf("ConfigGet() = %q, want %q", got, "abc123")
	}
}
