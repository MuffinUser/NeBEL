// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Regression test for the 2026-09-29 audit's P07(1). `nebel add file
// "*.env"` writes the pattern into .nebel.yaml and .gitattributes, and git
// applies it at any depth. A file in a subdirectory used to reach the
// filter with no matching rule, so git add failed. A bare pattern now
// matches at any depth in .nebel.yaml as well, so the file is encrypted.
func TestAddFileBareGlobEncryptsFilesInSubdirectories(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	repo := newTestRepo(t, pathEnv)

	initWithPassword(t, repo, pathEnv, "test-password-123")
	runIn(t, repo, pathEnv, "nebel", "add", "file", "*.env")

	for name, plaintext := range map[string]string{
		"root.env":        "DB_PASSWORD=root-secret\n",
		"config/prod.env": "DB_PASSWORD=nested-secret\n",
	} {
		full := filepath.Join(repo, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(plaintext), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	runIn(t, repo, pathEnv, "git", "add", "--", "root.env", "config/prod.env")
	runIn(t, repo, pathEnv, "git", "commit", "-q", "-m", "add env files")

	for _, name := range []string{"root.env", "config/prod.env"} {
		stored := runIn(t, repo, pathEnv, "git", "show", "HEAD:"+name)
		if strings.Contains(stored, "secret") || !strings.HasPrefix(stored, "ENC[") {
			t.Errorf("%s's committed blob is not ciphertext: %q", name, stored)
		}
	}
}

// When .gitattributes sends a file through the filter but no rule in
// .nebel.yaml covers it (here a hand-written attributes line), clean must
// fail the git add instead of passing the content through as plaintext
// (filterop.ErrNoMatchingRule; filter.nebel.required is true).
func TestFilterWithoutMatchingRuleDoesNotCommitPlaintext(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	repo := newTestRepo(t, pathEnv)

	initWithPassword(t, repo, pathEnv, "test-password-123")
	runIn(t, repo, pathEnv, "nebel", "add", "file", "*.env")
	attrs := filepath.Join(repo, ".gitattributes")
	existing, err := os.ReadFile(attrs)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(attrs, append(existing, "*.secret filter=nebel\n"...), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "prod.secret"), []byte("super-secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := runInExpectingError(t, repo, pathEnv, "git", "add", "--", "prod.secret")
	if err == nil {
		t.Fatalf("git add prod.secret: want an error (no rule matches), got success:\n%s", out)
	}
	if !strings.Contains(out, "no rule") {
		t.Errorf("git add error output = %q, want it to mention the missing rule", out)
	}
	if status := runIn(t, repo, pathEnv, "git", "status", "--porcelain"); strings.Contains(status, "A  prod.secret") {
		t.Errorf("git status shows prod.secret staged despite the filter error:\n%s", status)
	}
}
