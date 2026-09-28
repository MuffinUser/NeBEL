// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MuffinUser/nebel/internal/config"
)

// This is a regression test for the documented upgrade procedure in
// README.md's "Upgrading from a pre-rotation repository" section: a
// build from before key rotation existed wrote tags with no `key:` field
// at all (spec 03 AC-3.6 now requires one — a deliberate breaking change,
// see internal/tag's package doc). There is no in-tool migration, since
// the config's own canary — which every command checks first — fails to
// parse without a version. The fix is two hand-edits to .nebel.yaml plus
// a renormalize, not per-blob surgery: `git add --renormalize` re-cleans
// from whatever the *working tree* currently holds, which for an
// actively-used clone is always plaintext already, not the legacy
// ciphertext — so it produces the current (key-tagged) format from
// scratch rather than needing to touch any already-committed blob by
// hand.
func TestPreRotationRepoMigration(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	origin, plaintext := setupEncryptedOrigin(t, pathEnv, "origin-password")

	cfgPath := filepath.Join(origin, config.FileName)
	secretPath := filepath.Join(origin, "secrets", "prod.pem")

	originalCfg, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	originalBlob := runIn(t, origin, pathEnv, "git", "show", "HEAD:secrets/prod.pem")

	// Simulate a pre-rotation commit: strip every `key:` field this
	// build's own `nebel add` + `git commit` just wrote, reproducing what
	// a real repository created before rotation existed would have.
	// `-c filter.nebel.clean=cat` bypasses the (already fixed) filter for
	// this one commit, so it can actually commit the legacy shape instead
	// of failing the same way the real migration below demonstrates.
	legacyCfg := strings.ReplaceAll(string(originalCfg), "key_version: 1\n", "")
	legacyCfg = strings.ReplaceAll(legacyCfg, "key:1,", "")
	if err := os.WriteFile(cfgPath, []byte(legacyCfg), 0o644); err != nil {
		t.Fatal(err)
	}
	legacyBlob := strings.ReplaceAll(originalBlob, "key:1,", "")
	if err := os.WriteFile(secretPath, []byte(legacyBlob), 0o644); err != nil {
		t.Fatal(err)
	}
	runIn(t, origin, pathEnv, "git", "-c", "filter.nebel.clean=cat", "add", "-A")
	runIn(t, origin, pathEnv, "git", "-c", "filter.nebel.clean=cat", "commit", "-q", "-m", "simulate a pre-rotation repository")

	if committed := runIn(t, origin, pathEnv, "git", "show", "HEAD:secrets/prod.pem"); strings.Contains(committed, "key:1,") {
		t.Fatalf("test setup did not actually simulate a legacy (key-less) commit: %s", committed)
	}

	// Confirm the premise: with the config in its legacy shape, every
	// nebel command that touches the canary fails, matching the (already
	// tested) strict AC-3.6 behavior — there is no automatic recovery.
	if out, err := runInExpectingError(t, origin, pathEnv, "git", "add", "--renormalize", "--", "secrets/prod.pem"); err == nil {
		t.Fatalf("renormalize on the legacy config: want an error (confirming no automatic migration), got success:\n%s", out)
	}

	// The documented fix: this machine's working tree still holds the
	// decrypted plaintext (the ordinary state of an actively-used clone —
	// nothing here relied on ever having seen the legacy ciphertext), and
	// its operator hand-edits .nebel.yaml back to the current format.
	if err := os.WriteFile(secretPath, []byte(plaintext), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, originalCfg, 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := runInExpectingError(t, origin, pathEnv, "git", "add", "--renormalize", "--", ".")
	if err != nil {
		t.Fatalf("git add --renormalize after the documented fix: %v\n%s", err, out)
	}

	staged := runIn(t, origin, pathEnv, "git", "show", ":secrets/prod.pem")
	if staged != originalBlob {
		t.Errorf("renormalized blob does not match what a same-version, same-password repo would have produced:\n got  = %s\n want = %s", staged, originalBlob)
	}

	// README step 4: nothing old-format should remain staged.
	if leftover, err := runInExpectingError(t, origin, pathEnv, "git", "grep", "--cached", "-F", "ENC[AES256_SIV,data:"); err == nil {
		t.Errorf("old-format ciphertext survived the migration:\n%s", leftover)
	}
}

// The leftover check itself (README step 4) must actually catch the case
// it exists for: a file this machine never had decrypted, so renormalize
// silently left its legacy tag untouched (IsEncrypted already true) rather
// than re-encrypting it.
func TestMigrationLeftoverCheckCatchesUndecryptedFiles(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	origin, _ := setupEncryptedOrigin(t, pathEnv, "origin-password")

	cfgPath := filepath.Join(origin, config.FileName)
	secretPath := filepath.Join(origin, "secrets", "prod.pem")
	originalCfg, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	originalBlob := runIn(t, origin, pathEnv, "git", "show", "HEAD:secrets/prod.pem")

	legacyCfg := strings.ReplaceAll(string(originalCfg), "key_version: 1\n", "")
	legacyCfg = strings.ReplaceAll(legacyCfg, "key:1,", "")
	legacyBlob := strings.ReplaceAll(originalBlob, "key:1,", "")
	if err := os.WriteFile(cfgPath, []byte(legacyCfg), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secretPath, []byte(legacyBlob), 0o644); err != nil {
		t.Fatal(err)
	}
	runIn(t, origin, pathEnv, "git", "-c", "filter.nebel.clean=cat", "add", "-A")
	runIn(t, origin, pathEnv, "git", "-c", "filter.nebel.clean=cat", "commit", "-q", "-m", "simulate a pre-rotation repository")

	// Fix .nebel.yaml only — deliberately skip restoring the plaintext, as
	// if this machine never had secrets/prod.pem decrypted.
	if err := os.WriteFile(cfgPath, originalCfg, 0o644); err != nil {
		t.Fatal(err)
	}
	runIn(t, origin, pathEnv, "git", "add", "--renormalize", "--", ".")

	leftover, err := runInExpectingError(t, origin, pathEnv, "git", "grep", "--cached", "-F", "ENC[AES256_SIV,data:")
	if err != nil {
		t.Fatalf("leftover check found nothing, but secrets/prod.pem was never decrypted here: %v", err)
	}
	if !strings.Contains(leftover, "secrets/prod.pem") {
		t.Errorf("leftover check did not name the undecrypted file:\n%s", leftover)
	}
}
