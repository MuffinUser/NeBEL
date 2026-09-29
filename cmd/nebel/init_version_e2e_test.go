// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The full recovery story spec 11 depends on: after a rotation, a fresh
// clone's plain `nebel init` (at the new current version) cannot decrypt
// content still tagged with the old version — that's expected, not an
// error. Smudge passes it through as ciphertext instead of failing (spec
// 06 AC-6.11), and `nebel init`'s own post-checkout scan (cmd/nebel's
// scanUndecrypted) reports it as still needing that version rather than
// counting it as decrypted. `nebel init --version N` (spec 07
// AC-7.14–7.16) with the old password then recovers it, without
// disturbing the key the clone already registered.
//
// `rotate` itself now refuses outright rather than ever leave a file it
// *can* reach still on the old version (AC-11.11,
// TestRotateRefusesWhenContentUndecryptable) — so the only way a clone
// still needs this recovery path is content rotate's own commit never
// picked up in the first place. Committing only the config bump, and
// leaving the index entry for the migrated secret reverted to what HEAD
// already had, models exactly that (e.g. a partial commit, or a merge
// that reverted the file back out).
func TestInitVersionRecoversContentFromBeforeRotation(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	origin, plaintext := setupEncryptedOrigin(t, pathEnv, "v1-password")

	out, err := runRotateWith(t, origin, pathEnv, []string{passwordEnv + "=v2-password"}, "")
	if err != nil {
		t.Fatalf("nebel rotate: %v\n%s", err, out)
	}
	runIn(t, origin, pathEnv, "git", "restore", "--staged", "secrets/prod.pem")
	runIn(t, origin, pathEnv, "git", "commit", "-q", "-m", "rotate encryption key")

	if committed := runIn(t, origin, pathEnv, "git", "show", "HEAD:secrets/prod.pem"); !strings.Contains(committed, "key:1,") {
		t.Fatalf("test setup did not leave secrets/prod.pem tagged version 1:\n%s", committed)
	}

	clone := cloneOf(t, pathEnv, origin)

	// A fresh clone joining at the new current version (2): the old
	// content, still tagged version 1, must stay as ciphertext rather than
	// being lost, and the command must still succeed and say so.
	out, err = runInitWith(t, clone, pathEnv, []string{passwordEnv + "=v2-password"}, "")
	if err != nil {
		t.Fatalf("nebel init (v2): %v\n%s", err, out)
	}
	if !strings.Contains(out, "secrets/prod.pem") || !strings.Contains(out, "needs key version 1") {
		t.Errorf("init output does not name the still-undecryptable file and why:\n%s", out)
	}
	if !strings.Contains(out, "nebel init --version 1") {
		t.Errorf("init output does not point at the fix:\n%s", out)
	}

	secretPath := filepath.Join(clone, "secrets", "prod.pem")
	stillEncrypted, err := os.ReadFile(secretPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(stillEncrypted), "ENC[") {
		t.Fatalf("after joining at v2, pre-rotation content was not left as ciphertext: %q", stillEncrypted)
	}
	if string(stillEncrypted) == plaintext {
		t.Fatal("joining at v2 alone decrypted version-1 content — should need version 1's key")
	}

	// Fetching version 1's key with its own password recovers it, without
	// an error and without needing to touch the v2 key already registered.
	out, err = runInitWith(t, clone, pathEnv, []string{passwordEnv + "=v1-password"}, "", "--version", "1")
	if err != nil {
		t.Fatalf("nebel init --version 1: %v\n%s", err, out)
	}

	recovered, err := os.ReadFile(secretPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(recovered) != plaintext {
		t.Errorf("after init --version 1, file = %q, want decrypted %q", recovered, plaintext)
	}

	// The v2 key registered earlier must still be there.
	if _, ok := registeredKeyValue(t, clone, pathEnv, 2); !ok {
		t.Error("init --version 1 disturbed the already-registered v2 key")
	}
}

// AC-7.16: an N that never existed in .nebel.yaml's history fails clearly
// and registers nothing for that version.
func TestInitVersionUnknownFails(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	origin, _ := setupEncryptedOrigin(t, pathEnv, "origin-password")
	clone := cloneOf(t, pathEnv, origin)
	initWithPassword(t, clone, pathEnv, "origin-password")

	out, err := runInitWith(t, clone, pathEnv, []string{passwordEnv + "=whatever"}, "", "--version", "99")
	if err == nil {
		t.Fatalf("nebel init --version 99: want an error, got success:\n%s", out)
	}
	if _, ok := registeredKeyValue(t, clone, pathEnv, 99); ok {
		t.Error("init --version 99 registered a key for a version that doesn't exist")
	}
}

// getLocalConfig is a thin wrapper for checking whether a local git config
// key is set, returning ok=false rather than failing the test when it
// isn't (unlike runInExpectingError, which callers use when only the
// error matters).
func getLocalConfig(t *testing.T, dir, pathEnv, key string) (string, bool, error) {
	t.Helper()
	out, err := runInExpectingError(t, dir, pathEnv, "git", "config", "--local", "--get", key)
	if err != nil {
		return "", false, nil
	}
	return strings.TrimSpace(out), true, nil
}
