// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package filterop

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/MuffinUser/nebel/internal/config"
	"github.com/MuffinUser/nebel/internal/kdf"
)

// The files under testdata/v1 are a frozen repository, captured from a real
// `nebel init` + `nebel add` + `git commit` run: .nebel.yaml is the
// committed config (salt and canary included), and each file under secrets/
// is the ENC[...] blob git stored, byte for byte.
//
// They exist to catch the one class of bug no round-trip test can see: a
// change that is self-consistent — encrypt and decrypt still agree with each
// other — but no longer agrees with what earlier versions wrote. Anything
// that feeds the plaintext (Argon2id costs, the HKDF info string, the AAD
// encoding, the tag format, the base64 alphabet) would break every secret
// already committed in a user's repository.
//
// Do not regenerate these fixtures to make a failing test pass. A failure
// here means this build cannot read files an earlier build wrote, and the
// answer is either to revert the format change or to ship a migration.
//
// Exception already taken: spec 11 (key rotation) made the tag's `key:`
// field mandatory (spec 03 AC-3.6) — a deliberate breaking format change,
// since every tag written before rotation existed had no `key:` field at
// all and no version to fall back to. These fixtures were bumped forward
// to the new format (`key_version: 1` added to .nebel.yaml, `key:1,`
// spliced into each stored blob's tag) with the same salt/password, so the
// underlying ciphertext bytes are untouched — only the tag wrapper changed.
// There is no fully automatic migration for a real pre-rotation
// repository: its canary is checked (and fails to parse) before any
// command runs at all. See README.md's "Upgrading from a pre-rotation
// repository" for the fix — two hand-edits to .nebel.yaml, then
// `git add --renormalize` (which then works fine, since it re-cleans from
// the working tree's already-decrypted plaintext, not the legacy blob).
const goldenPassword = "correct horse battery staple"

// goldenPlaintexts maps each fixture's repo-relative path — which is also
// its rule-matching key and part of its AAD — to the content it must decrypt
// back to.
func goldenPlaintexts() map[string][]byte {
	everyByte := make([]byte, 256)
	for i := range everyByte {
		everyByte[i] = byte(i)
	}
	return map[string][]byte{
		"secrets/prod.pem": []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n" +
			"b3BlbnNzaC1rZXktdjEAAAAABG5vbmU=\n" +
			"-----END OPENSSH PRIVATE KEY-----\n"),
		"secrets/every-byte.pem": everyByte,
	}
}

// loadGoldenRepo loads the frozen config and re-derives its key from the
// fixed password, exactly as `nebel init` does on a fresh clone.
func loadGoldenRepo(t *testing.T) (*config.Config, Keyring) {
	t.Helper()

	cfg, err := config.Load(filepath.Join("testdata", "v1", config.FileName))
	if err != nil {
		t.Fatalf("loading frozen config: %v", err)
	}
	salt, err := cfg.SaltBytes()
	if err != nil {
		t.Fatalf("decoding frozen salt: %v", err)
	}
	key, err := kdf.Derive(goldenPassword, salt)
	if err != nil {
		t.Fatalf("deriving key from frozen salt: %v", err)
	}
	// The canary is the first thing a joining clone checks, so a key
	// derivation change surfaces here rather than as a decrypt failure.
	if err := cfg.VerifyCanary(key); err != nil {
		t.Fatalf("frozen canary no longer verifies under the derived key: %v", err)
	}
	return cfg, Keyring{cfg.CurrentVersion(): key}
}

func readGoldenFile(t *testing.T, repoPath string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "v1", filepath.FromSlash(repoPath)))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	return data
}

// Smudging a blob written by an earlier version must still yield the
// original plaintext: this is the checkout path a user hits on every clone
// of a repository whose secrets predate the current build.
func TestSmudgeGoldenFixture(t *testing.T) {
	cfg, keyring := loadGoldenRepo(t)

	for repoPath, want := range goldenPlaintexts() {
		t.Run(repoPath, func(t *testing.T) {
			got, _, err := Smudge(cfg, keyring, repoPath, readGoldenFile(t, repoPath))
			if err != nil {
				t.Fatalf("committed secrets no longer decrypt: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("decrypted content changed:\n got  = %x\n want = %x", got, want)
			}
		})
	}
}

// The reverse direction: cleaning the known plaintext must reproduce the
// frozen blob exactly. Encryption is deterministic, so re-staging an
// unchanged secret with a newer build has to leave git's object store
// untouched — otherwise every user's next commit rewrites every secret.
func TestCleanReproducesGoldenFixture(t *testing.T) {
	cfg, keyring := loadGoldenRepo(t)

	for repoPath, plaintext := range goldenPlaintexts() {
		t.Run(repoPath, func(t *testing.T) {
			got, err := Clean(cfg, keyring, repoPath, plaintext)
			if err != nil {
				t.Fatalf("Clean: %v", err)
			}
			if want := readGoldenFile(t, repoPath); !bytes.Equal(got, want) {
				t.Errorf("stored blob format changed:\n got  = %s\n want = %s", got, want)
			}
		})
	}
}

// A fixture must not decrypt under a different file's path: the AAD binding
// is what stops a committed blob from being copy-pasted to another location,
// and it is the part of the format most easily broken by accident.
func TestGoldenFixtureStaysBoundToItsPath(t *testing.T) {
	cfg, keyring := loadGoldenRepo(t)

	blob := readGoldenFile(t, "secrets/prod.pem")
	plaintext, _, err := Smudge(cfg, keyring, "secrets/every-byte.pem", blob)
	if err == nil {
		t.Fatalf("blob decrypted under another file's path, got %q", plaintext)
	}
	if plaintext != nil {
		t.Errorf("Smudge() returned plaintext %q alongside an error", plaintext)
	}
}

// goldenLineRules are the mode: value rules for the .env and .properties
// fixtures. They are added in code rather than to the frozen .nebel.yaml,
// whose bytes predate per-value mode for these formats.
func goldenLineRules() []config.Rule {
	return []config.Rule{
		{Files: "config/*.env", Mode: config.ModeValue, Encrypt: []string{"DATABASE_PASSWORD", "API_TOKEN", "GREETING"}},
		{Files: "config/*.properties", Mode: config.ModeValue, Encrypt: []string{"database.password", "api.token"}},
	}
}

// goldenLinePlaintexts are the working-tree contents of the line-format
// fixtures. Which bytes form a value's "raw literal" (spec 05 § Line-based
// formats) is as much part of the stored format as the AAD encoding: a
// change to span boundaries is self-consistent but re-encrypts every
// committed value (spec 06 AC-6.14). The values cover a quoted literal
// with an escape, an inline comment, a \uXXXX escape and trailing
// whitespace, and all three .env quote bindings (AC-6.16).
func goldenLinePlaintexts() map[string][]byte {
	return map[string][]byte{
		"config/prod.env": []byte("# frozen fixture\n" +
			"APP_NAME=nebel\n" +
			"export DATABASE_PASSWORD=\"p@ss \\\"word\\\"\"   # rotate quarterly\n" +
			"API_TOKEN=tok_live#1\n" +
			"GREETING='say \"hi\" $USER'\n"),
		"config/app.properties": []byte("# frozen fixture\n" +
			"database.url=jdbc:postgresql://db/app\n" +
			"database.password = caf\\u00e9 s3cr3t  \n" +
			"api.token:tok_live\n"),
	}
}

// AC-6.14: committed .env and .properties values written by this build
// must keep decrypting, and re-cleaning their plaintext must reproduce the
// stored bytes exactly.
func TestLineFormatGoldenFixtures(t *testing.T) {
	cfg, keyring := loadGoldenRepo(t)
	cfg.Rules = append(cfg.Rules, goldenLineRules()...)

	for repoPath, plaintext := range goldenLinePlaintexts() {
		t.Run(repoPath, func(t *testing.T) {
			stored := readGoldenFile(t, repoPath)
			got, _, err := Smudge(cfg, keyring, repoPath, stored)
			if err != nil {
				t.Fatalf("committed values no longer decrypt: %v", err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Errorf("decrypted content changed:\n got  = %q\n want = %q", got, plaintext)
			}
			cleaned, err := Clean(cfg, keyring, repoPath, plaintext)
			if err != nil {
				t.Fatalf("Clean: %v", err)
			}
			if !bytes.Equal(cleaned, stored) {
				t.Errorf("stored format changed:\n got  = %s\n want = %s", cleaned, stored)
			}
		})
	}
}
