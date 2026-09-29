// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MuffinUser/nebel/internal/siv"
	"github.com/MuffinUser/nebel/internal/tag"
)

// Regression test for an interaction between Package D (P01's dirty-check
// in gitutil.CheckoutAll) and Package F (P05's type-authenticated value
// tags), found during review rather than by the original audit:
// DirtyFiles compares by running the clean filter (that's what `git diff
// HEAD` against a filtered path does), and a legacy (pre-AC-3.10) value
// tag re-encrypts to different bytes the moment anything cleans it again
// — the AAD it's produced under changed — even when the secret itself was
// never touched. That makes a repeated `nebel init` refuse with
// ErrDirtyManagedFiles for a file the user never edited, until the legacy
// tag is upgraded and *committed* (renormalizing alone updates the index,
// not HEAD, so `git diff HEAD` still sees the old committed form either
// way — confirmed here, not merely asserted).
func TestInitRefusesOnLegacyValueTagUntilRenormalizedAndCommitted(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	repo := setupValueRepo(t, pathEnv)
	runIn(t, repo, pathEnv, "nebel", "add", "field", "config/staging.yaml", "database.password")
	runIn(t, repo, pathEnv, "git", "add", ".")
	runIn(t, repo, pathEnv, "git", "commit", "-q", "-m", "encrypt database.password")

	committed := runIn(t, repo, pathEnv, "git", "show", "HEAD:config/staging.yaml")
	if !strings.Contains(committed, "AES256_SIV_TB,") {
		t.Fatalf("test setup did not produce a type-bound tag:\n%s", committed)
	}

	// Downgrade the committed tag to the legacy (pre-AC-3.10) form,
	// re-encrypting the real secret under the legacy (type-unbound) AAD
	// with this repo's actual registered key — reproducing exactly what a
	// pre-Package-F build would have committed, not a synthetic stand-in.
	keyB64, ok := registeredKeyValue(t, repo, pathEnv, 1)
	if !ok {
		t.Fatal("no key registered for version 1")
	}
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		t.Fatalf("decoding registered key: %v", err)
	}
	legacyAAD := siv.AAD(siv.ModeValue, "config/staging.yaml", "database.password")
	ciphertext, err := siv.Encrypt(key, []byte("s3cr3t"), legacyAAD)
	if err != nil {
		t.Fatalf("siv.Encrypt: %v", err)
	}
	legacyTag := fmt.Sprintf("ENC[%s,key:1,data:%s,type:str]", tag.AlgoAES256SIV, base64.StdEncoding.EncodeToString(ciphertext))
	legacyBlob := strings.Replace(stagingYAML, `password: "s3cr3t"`, `password: "`+legacyTag+`"`, 1)

	cfgPath := filepath.Join(repo, "config", "staging.yaml")
	if err := os.WriteFile(cfgPath, []byte(legacyBlob), 0o644); err != nil {
		t.Fatal(err)
	}
	// -c filter.nebel.clean=cat: commit the legacy blob's bytes exactly as
	// written, the same technique TestPreRotationRepoMigration uses to
	// simulate a commit predating a tag-format fix.
	runIn(t, repo, pathEnv, "git", "-c", "filter.nebel.clean=cat", "add", "-A")
	runIn(t, repo, pathEnv, "git", "-c", "filter.nebel.clean=cat", "commit", "-q", "-m", "simulate a pre-AC-3.10 commit")

	// First init after the simulated legacy commit: the working tree
	// currently holds that same legacy-tagged text verbatim (nothing
	// cleaned it yet), so it's not "dirty" relative to HEAD — this must
	// still succeed, and it's what actually decrypts the field into the
	// working tree for the first time.
	initWithPassword(t, repo, pathEnv, "value-mode-password")
	onDisk, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(onDisk), `password: "s3cr3t"`) {
		t.Fatalf("first init did not decrypt the legacy tag:\n%s", onDisk)
	}

	// Second init, simulating "run nebel init again" with no edits in
	// between: the working tree is now plaintext, and re-cleaning it
	// produces a fresh type-bound tag that differs from HEAD's still-legacy
	// one — DirtyFiles sees that as a real difference and refuses, exactly
	// the interaction this test is about.
	out, err := runInitWithExpectingError(t, repo, pathEnv, "value-mode-password")
	if err == nil {
		t.Fatalf("second init: want ErrDirtyManagedFiles (legacy tag re-encrypts differently), got success:\n%s", out)
	}
	if !strings.Contains(out, "renormalize") {
		t.Errorf("init error does not point at the documented fix:\n%s", out)
	}

	// The fix as actually documented: renormalize AND commit. Renormalize
	// alone only updates the index, not HEAD — `git diff HEAD` (what
	// DirtyFiles runs) would still see the old committed form either way,
	// which this confirms rather than assumes.
	runIn(t, repo, pathEnv, "git", "add", "--renormalize", "--", "config/staging.yaml")
	if _, err := runInitWithExpectingError(t, repo, pathEnv, "value-mode-password"); err == nil {
		t.Fatal("init after renormalizing but before committing: want it to still refuse, got success")
	}
	runIn(t, repo, pathEnv, "git", "commit", "-q", "-m", "upgrade database.password to a type-bound tag")

	initWithPassword(t, repo, pathEnv, "value-mode-password")
	afterUpgrade, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(afterUpgrade), `password: "s3cr3t"`) {
		t.Errorf("init after the documented fix did not leave the field decrypted:\n%s", afterUpgrade)
	}
}

// runInitWithExpectingError runs `nebel init` with password, expecting it
// to fail, and returns its combined output for inspecting the error text.
func runInitWithExpectingError(t *testing.T, dir, pathEnv, password string) (string, error) {
	t.Helper()
	return runInitWith(t, dir, pathEnv, []string{passwordEnv + "=" + password}, "")
}
