// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package gitutil

import (
	"errors"
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

	if _, ok, err := ConfigGet("filter.nebel.key"); err != nil || ok {
		t.Fatalf("ConfigGet() on unset key: ok=%v err=%v, want ok=false err=nil", ok, err)
	}

	if err := ConfigSet("filter.nebel.key", "abc123"); err != nil {
		t.Fatalf("ConfigSet: %v", err)
	}

	got, ok, err := ConfigGet("filter.nebel.key")
	if err != nil || !ok {
		t.Fatalf("ConfigGet() after set: ok=%v err=%v, want ok=true err=nil", ok, err)
	}
	if got != "abc123" {
		t.Errorf("ConfigGet() = %q, want %q", got, "abc123")
	}
}

func TestConfigGetRegexp(t *testing.T) {
	dir := newTempRepo(t)
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(orig)
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	if got, err := ConfigGetRegexp(`^filter\.nebel\.key[0-9]*$`); err != nil || len(got) != 0 {
		t.Fatalf("ConfigGetRegexp() on unset keys: got=%v err=%v, want empty map, nil error", got, err)
	}

	if err := ConfigSet("filter.nebel.key", "v1"); err != nil {
		t.Fatalf("ConfigSet: %v", err)
	}
	if err := ConfigSet("filter.nebel.key2", "v2"); err != nil {
		t.Fatalf("ConfigSet: %v", err)
	}
	if err := ConfigSet("filter.nebel.required", "true"); err != nil {
		t.Fatalf("ConfigSet: %v", err)
	}

	got, err := ConfigGetRegexp(`^filter\.nebel\.key[0-9]*$`)
	if err != nil {
		t.Fatalf("ConfigGetRegexp: %v", err)
	}
	want := map[string]string{"filter.nebel.key": "v1", "filter.nebel.key2": "v2"}
	if len(got) != len(want) || got["filter.nebel.key"] != want["filter.nebel.key"] || got["filter.nebel.key2"] != want["filter.nebel.key2"] {
		t.Errorf("ConfigGetRegexp() = %v, want %v", got, want)
	}
}

func writeAndCommit(t *testing.T, dir, path, content string) {
	t.Helper()
	full := filepath.Join(dir, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("add", "--", path)
	run("commit", "-q", "-m", "commit "+path)
}

func TestShow(t *testing.T) {
	dir := newTempRepo(t)
	writeAndCommit(t, dir, "file.txt", "version one\n")
	writeAndCommit(t, dir, "file.txt", "version two\n")

	got, err := Show(dir, "HEAD", "file.txt")
	if err != nil {
		t.Fatalf("Show: %v", err)
	}
	if string(got) != "version two\n" {
		t.Errorf("Show(HEAD) = %q, want %q", got, "version two\n")
	}

	got, err = Show(dir, "HEAD~1", "file.txt")
	if err != nil {
		t.Fatalf("Show(HEAD~1): %v", err)
	}
	if string(got) != "version one\n" {
		t.Errorf("Show(HEAD~1) = %q, want %q", got, "version one\n")
	}
}

func TestLog(t *testing.T) {
	dir := newTempRepo(t)
	writeAndCommit(t, dir, "unrelated.txt", "x\n")
	writeAndCommit(t, dir, "file.txt", "v1\n")
	writeAndCommit(t, dir, "unrelated.txt", "y\n")
	writeAndCommit(t, dir, "file.txt", "v2\n")

	commits, err := Log(dir, "file.txt")
	if err != nil {
		t.Fatalf("Log: %v", err)
	}
	if len(commits) != 2 {
		t.Fatalf("Log(file.txt) returned %d commits, want 2: %v", len(commits), commits)
	}

	none, err := Log(dir, "never-existed.txt")
	if err != nil {
		t.Fatalf("Log: %v", err)
	}
	if len(none) != 0 {
		t.Errorf("Log(never-existed.txt) = %v, want empty", none)
	}
}

func TestIsShallowFalseForNormalClone(t *testing.T) {
	dir := newTempRepo(t)
	writeAndCommit(t, dir, "file.txt", "content\n")

	shallow, err := IsShallow(dir)
	if err != nil {
		t.Fatalf("IsShallow: %v", err)
	}
	if shallow {
		t.Error("IsShallow() = true for a normal, fully-fetched repo")
	}
}

// CheckoutAll must isolate one file's smudge failure to that file, rather
// than letting a single `git checkout` invocation over every managed path
// abort and leave all of them missing.
func TestCheckoutAllIsolatesPerFileSmudgeFailures(t *testing.T) {
	dir := newTempRepo(t)
	if err := os.WriteFile(filepath.Join(dir, ".gitattributes"), []byte("*.txt filter=nebel\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeAndCommit(t, dir, "good.txt", "good-plaintext\n")
	writeAndCommit(t, dir, "bad.txt", "bad-plaintext\n")

	scriptPath := filepath.Join(dir, "fail-for-bad.sh")
	script := "#!/bin/sh\nif [ \"$1\" = bad.txt ]; then echo needs-key-2 >&2; exit 1; fi\ncat\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("config", "filter.nebel.smudge", scriptPath+" %f")
	run("config", "filter.nebel.clean", "cat")
	run("config", "filter.nebel.required", "true")

	decrypted, failures, err := CheckoutAll(dir)
	if err != nil {
		t.Fatalf("CheckoutAll: %v", err)
	}
	if decrypted != 1 {
		t.Errorf("CheckoutAll decrypted = %d, want 1", decrypted)
	}
	if len(failures) != 1 {
		t.Fatalf("CheckoutAll failures = %v, want exactly one", failures)
	}
	if failures[0].Path != "bad.txt" {
		t.Errorf("failure path = %q, want %q", failures[0].Path, "bad.txt")
	}
	if !strings.Contains(failures[0].Reason, "needs-key-2") {
		t.Errorf("failure reason = %q, want it to carry the filter's own message", failures[0].Reason)
	}

	good, err := os.ReadFile(filepath.Join(dir, "good.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(good) != "good-plaintext\n" {
		t.Errorf("good.txt = %q, want %q", good, "good-plaintext\n")
	}

	// bad.txt's smudge failed: it must still be present, restored as the
	// raw committed blob, rather than left missing.
	bad, err := os.ReadFile(filepath.Join(dir, "bad.txt"))
	if err != nil {
		t.Fatalf("bad.txt was left missing after a failed smudge: %v", err)
	}
	if string(bad) != "bad-plaintext\n" {
		t.Errorf("bad.txt = %q, want the raw committed blob %q", bad, "bad-plaintext\n")
	}
}

// registerCatFilter wires the nebel filter to a no-op "cat" for both
// directions, enough for CheckoutAll's dirty-check to be exercised
// without needing a real clean/smudge transform.
func registerCatFilter(t *testing.T, dir string) {
	t.Helper()
	run := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("config", "filter.nebel.clean", "cat")
	run("config", "filter.nebel.smudge", "cat")
	run("config", "filter.nebel.required", "true")
}

// Regression test for the 2026-09-29 audit's P01: CheckoutAll's
// os.Remove-then-checkout has no backup step, and `git checkout HEAD --`
// restores from HEAD regardless of the index — so before this fix, a
// repeated `nebel init` (which calls CheckoutAll) silently discarded any
// local edit to a managed file, staged or not. Both must now be refused
// outright, with the local edit left completely untouched.
func TestCheckoutAllRefusesDirtyManagedFiles(t *testing.T) {
	for _, tt := range []struct {
		name  string
		stage bool
	}{
		{"unstaged edit", false},
		{"staged edit", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := newTempRepo(t)
			if err := os.WriteFile(filepath.Join(dir, ".gitattributes"), []byte("*.txt filter=nebel\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			writeAndCommit(t, dir, "secret.txt", "original\n")
			registerCatFilter(t, dir)

			const edited = "locally edited, not yet committed\n"
			path := filepath.Join(dir, "secret.txt")
			if err := os.WriteFile(path, []byte(edited), 0o644); err != nil {
				t.Fatal(err)
			}
			if tt.stage {
				cmd := exec.Command("git", "add", "--", "secret.txt")
				cmd.Dir = dir
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("git add: %v\n%s", err, out)
				}
			}

			_, _, err := CheckoutAll(dir)
			if !errors.Is(err, ErrDirtyManagedFiles) {
				t.Fatalf("CheckoutAll() error = %v, want %v", err, ErrDirtyManagedFiles)
			}

			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("secret.txt was removed despite CheckoutAll refusing: %v", err)
			}
			if string(got) != edited {
				t.Errorf("secret.txt = %q, want the local edit left untouched: %q", got, edited)
			}
		})
	}
}

// The ordinary case CheckoutAll exists for — no local changes at all, as
// right after `nebel init` on a fresh clone — must not be blocked by the
// new dirty check.
func TestCheckoutAllSucceedsWhenNothingIsDirty(t *testing.T) {
	dir := newTempRepo(t)
	if err := os.WriteFile(filepath.Join(dir, ".gitattributes"), []byte("*.txt filter=nebel\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeAndCommit(t, dir, "secret.txt", "original\n")
	registerCatFilter(t, dir)

	decrypted, failures, err := CheckoutAll(dir)
	if err != nil {
		t.Fatalf("CheckoutAll: %v", err)
	}
	if decrypted != 1 || len(failures) != 0 {
		t.Errorf("CheckoutAll() = decrypted=%d failures=%v, want decrypted=1, no failures", decrypted, failures)
	}
}
