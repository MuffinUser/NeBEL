// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Regression test for the 2026-09-29 audit's P07(1): a bare glob like
// "*.env" (no leading "**/") matches recursively in .gitattributes syntax
// but, per doublestar's semantics, only at the depth it's written at (see
// config.Rule.Files's doc comment). `nebel add file` writes such a pattern
// unchanged into both files, so a file living in a subdirectory is one
// git invokes the filter for but that config.MatchRule does not recognize.
//
// Before the fix, Clean silently returned this content unchanged and
// `git commit` succeeded with the secret stored as plaintext. The filter
// must instead fail the commit outright (filterop.ErrNoMatchingRule),
// since filter.nebel.required is set to true.
func TestAddFileBareGlobDoesNotSilentlyCommitPlaintextInSubdirectory(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	repo := newTestRepo(t, pathEnv)

	initWithPassword(t, repo, pathEnv, "test-password-123")
	runIn(t, repo, pathEnv, "nebel", "add", "file", "*.env")

	configDir := filepath.Join(repo, "config")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	plaintext := "DB_PASSWORD=super-secret\n"
	envPath := filepath.Join(configDir, "prod.env")
	if err := os.WriteFile(envPath, []byte(plaintext), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := runInExpectingError(t, repo, pathEnv, "git", "add", "--", "config/prod.env")
	if err == nil {
		t.Fatalf("git add config/prod.env: want an error (glob/attribute mismatch), got success:\n%s", out)
	}
	if !strings.Contains(out, "no rule") && !strings.Contains(out, "ErrNoMatchingRule") && !strings.Contains(out, "filterop:") {
		t.Errorf("git add error output = %q, want it to mention the rule mismatch", out)
	}

	// Confirm the secret was never staged at all, plaintext or otherwise —
	// a failed clean must not leave a partial index entry behind.
	lsFiles := runIn(t, repo, pathEnv, "git", "status", "--porcelain")
	if strings.Contains(lsFiles, "A  config/prod.env") {
		t.Errorf("git status shows config/prod.env staged despite the filter error:\n%s", lsFiles)
	}

	// The root-level case (matching depth) must still work exactly as
	// before — this is a mismatch fix, not a semantics change.
	rootPlaintext := "DB_PASSWORD=another-secret\n"
	rootEnvPath := filepath.Join(repo, "root.env")
	if err := os.WriteFile(rootEnvPath, []byte(rootPlaintext), 0o644); err != nil {
		t.Fatal(err)
	}
	runIn(t, repo, pathEnv, "git", "add", "--", "root.env")
	runIn(t, repo, pathEnv, "git", "commit", "-q", "-m", "add root-level env file")

	stored := runIn(t, repo, pathEnv, "git", "show", "HEAD:root.env")
	if stored == rootPlaintext {
		t.Error("root-level file matching the same bare glob was committed as plaintext")
	}
	if !strings.HasPrefix(stored, "ENC[") {
		t.Errorf("root-level file's committed blob is not ciphertext: %q", stored)
	}
}
