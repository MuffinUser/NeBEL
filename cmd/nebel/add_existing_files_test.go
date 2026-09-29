// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// commitTrackedAndSettle writes content at repo-relative relPath, backdates
// its mtime well into the past, and commits it — reproducing a file that
// was already tracked and settled in git's index long before any nebel
// rule ever mentioned it.
//
// The backdating matters: without it, the file's mtime sits close enough
// to "now" that git's own protection against racy stat comparisons (a
// path whose mtime isn't safely older than the index's own mtime can't be
// trusted from cached stat info alone) forces a full content re-check on
// every subsequent git operation anyway — which would mask exactly the
// bug these tests exist to catch. Once a path's stat info is unambiguously
// old, git trusts it blindly and skips re-invoking any filter for that
// path — a new .gitattributes line notwithstanding — until something
// actually touches the file again.
func commitTrackedAndSettle(t *testing.T, repo, pathEnv, relPath string, content []byte) {
	t.Helper()
	full := filepath.Join(repo, relPath)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, content, 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := os.Chtimes(full, old, old); err != nil {
		t.Fatal(err)
	}
	runIn(t, repo, pathEnv, "git", "add", relPath)
	runIn(t, repo, pathEnv, "git", "commit", "-q", "-m", "commit "+relPath+" before any nebel rule exists")
}

// `add file` used to only register a rule: git's own index would keep
// treating an already-tracked, already-settled file as clean, and it
// would stay plaintext in the repository until something unrelated later
// edited it — contradicting the documented "no further step" promise.
func TestAddFileEncryptsAlreadyTrackedUnchangedFile(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	repo := newTestRepo(t, pathEnv)
	initWithPassword(t, repo, pathEnv, "test-password-123")

	plaintext := []byte("-----BEGIN KEY-----\ntotally-secret\n-----END KEY-----\n")
	commitTrackedAndSettle(t, repo, pathEnv, "secrets/prod.pem", plaintext)

	out := runIn(t, repo, pathEnv, "nebel", "add", "file", "secrets/*.pem")
	if !strings.Contains(out, "Encrypted and staged 1 file") {
		t.Errorf("add file did not report re-encrypting the already-tracked file:\n%s", out)
	}

	staged := runIn(t, repo, pathEnv, "git", "show", ":secrets/prod.pem")
	if !strings.HasPrefix(staged, "ENC[") {
		t.Fatalf("already-tracked file was not encrypted by `add file` alone (no manual git add/renormalize ran): got %q", staged)
	}

	// Re-running is a no-op: nothing left to re-encrypt.
	out = runIn(t, repo, pathEnv, "nebel", "add", "file", "secrets/*.pem")
	if strings.Contains(out, "Encrypted") {
		t.Errorf("re-running add file re-encrypted an already-converged file:\n%s", out)
	}

	runIn(t, repo, pathEnv, "git", "add", ".")
	runIn(t, repo, pathEnv, "git", "commit", "-q", "-m", "commit the rule and its ciphertext")
	onDisk, err := os.ReadFile(filepath.Join(repo, "secrets", "prod.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if string(onDisk) != string(plaintext) {
		t.Errorf("working tree changed unexpectedly: got %q, want %q", onDisk, plaintext)
	}
}

// A glob that doesn't yet match any tracked file is the common case for a
// brand new rule — `add file` must not error just because there's nothing
// to renormalize yet (a raw `git add --renormalize -- <glob>` does error
// in this case).
func TestAddFileWithNoExistingMatchesSucceeds(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	repo := newTestRepo(t, pathEnv)
	initWithPassword(t, repo, pathEnv, "test-password-123")

	out := runIn(t, repo, pathEnv, "nebel", "add", "file", "secrets/*.pem")
	if !strings.Contains(out, "Added rule") {
		t.Errorf("add file with no matching tracked files did not succeed:\n%s", out)
	}
}

// Same bug, mode: value: `add field` on a file that already exists,
// tracked and unchanged, must encrypt the named field immediately.
func TestAddFieldEncryptsAlreadyTrackedUnchangedFile(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	repo := newTestRepo(t, pathEnv)
	initWithPassword(t, repo, pathEnv, "test-password-123")

	commitTrackedAndSettle(t, repo, pathEnv, "config/staging.yaml", []byte(stagingYAML))

	out := runIn(t, repo, pathEnv, "nebel", "add", "field", "config/staging.yaml", "database.password")
	if !strings.Contains(out, "Encrypted and staged 1 file") {
		t.Errorf("add field did not report re-encrypting the already-tracked file:\n%s", out)
	}

	staged := runIn(t, repo, pathEnv, "git", "show", ":config/staging.yaml")
	if strings.Contains(staged, "s3cr3t") {
		t.Errorf("already-tracked file still has the plaintext secret staged:\n%s", staged)
	}
	if !strings.Contains(staged, "ENC[") {
		t.Errorf("field was not encrypted:\n%s", staged)
	}
}

// Appending a second field to a rule that already applies to an
// already-tracked, already-converged file must encrypt the newly added
// field too, without disturbing the field the rule already covered.
func TestAddFieldAppendEncryptsNewFieldOnAlreadyTrackedFile(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	repo := newTestRepo(t, pathEnv)
	initWithPassword(t, repo, pathEnv, "test-password-123")

	commitTrackedAndSettle(t, repo, pathEnv, "config/staging.yaml", []byte(stagingYAML))
	runIn(t, repo, pathEnv, "nebel", "add", "field", "config/staging.yaml", "database.password")
	runIn(t, repo, pathEnv, "git", "add", ".")
	runIn(t, repo, pathEnv, "git", "commit", "-q", "-m", "encrypt password field")

	out := runIn(t, repo, pathEnv, "nebel", "add", "field", "config/staging.yaml", "api.keys[0]")
	if !strings.Contains(out, "Encrypted and staged 1 file") {
		t.Errorf("appending a field to an existing rule did not re-encrypt the already-tracked file:\n%s", out)
	}

	staged := runIn(t, repo, pathEnv, "git", "show", ":config/staging.yaml")
	if strings.Contains(staged, "alpha") {
		t.Errorf("newly added field is still plaintext:\n%s", staged)
	}
	if strings.Contains(staged, "s3cr3t") {
		t.Errorf("previously encrypted field regressed to plaintext:\n%s", staged)
	}
	if strings.Count(staged, "ENC[") != 2 {
		t.Errorf("want exactly 2 encrypted fields staged, got:\n%s", staged)
	}
}

// A non-ASCII filename must not be silently dropped from renormalize's
// scope: git's default output quotes it as a C-style escaped string
// ("secrets/zug\303\244nge.pem" for an actual "ü"), which would never
// match the same path returned by cfg.MatchRule if that quoting weren't
// undone (gitutil's ls-files/ls-files -s calls use -z for exactly this
// reason).
func TestAddFileEncryptsAlreadyTrackedFileWithNonASCIIName(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	repo := newTestRepo(t, pathEnv)
	initWithPassword(t, repo, pathEnv, "test-password-123")

	plaintext := []byte("-----BEGIN KEY-----\ntotally-secret\n-----END KEY-----\n")
	commitTrackedAndSettle(t, repo, pathEnv, "secrets/zugänge.pem", plaintext)

	out := runIn(t, repo, pathEnv, "nebel", "add", "file", "secrets/*.pem")
	if !strings.Contains(out, "Encrypted and staged 1 file") {
		t.Errorf("add file did not report re-encrypting the already-tracked non-ASCII-named file:\n%s", out)
	}

	staged := runIn(t, repo, pathEnv, "git", "show", ":secrets/zugänge.pem")
	if !strings.HasPrefix(staged, "ENC[") {
		t.Fatalf("already-tracked non-ASCII-named file was not encrypted by `add file`: got %q", staged)
	}
}
