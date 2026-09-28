// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package filterop

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/MuffinUser/nebel/internal/config"
	"github.com/MuffinUser/nebel/internal/tag"
)

var v2Key = bytes.Repeat([]byte{0x77}, 64)

func configAtVersion(version int) *config.Config {
	return &config.Config{
		KeyVersion: version,
		Rules:      []config.Rule{{Files: "secrets/*.pem", Mode: config.ModeFile}},
	}
}

// AC-6.12: clean always targets the config's current key version,
// regardless of what version an already-encrypted value previously
// carried. This is the mechanism `nebel rotate` (spec 11) relies on to
// eagerly re-encrypt everything it can onto the version it just minted,
// and the same mechanism that converges anything left over the next time
// it's naturally edited.
func TestCleanRewritesUnderCurrentVersion(t *testing.T) {
	plaintext := []byte("-----BEGIN KEY-----")

	v1Cleaned, err := Clean(configAtVersion(1), Keyring{1: testKey}, "secrets/prod.pem", plaintext)
	if err != nil {
		t.Fatalf("clean under v1: %v", err)
	}
	parsed, err := tag.Parse(string(v1Cleaned))
	if err != nil {
		t.Fatalf("parsing v1 tag: %v", err)
	}
	if parsed.Version != 1 {
		t.Fatalf("Version = %d, want 1", parsed.Version)
	}

	// The field is re-cleaned from plaintext under version 2 (as happens
	// when a file is edited and staged after `nebel rotate`): the emitted
	// tag must name the new current version, not the one it had before.
	v2Cleaned, err := Clean(configAtVersion(2), Keyring{1: testKey, 2: v2Key}, "secrets/prod.pem", plaintext)
	if err != nil {
		t.Fatalf("clean under v2: %v", err)
	}
	parsed, err = tag.Parse(string(v2Cleaned))
	if err != nil {
		t.Fatalf("parsing v2 tag: %v", err)
	}
	if parsed.Version != 2 {
		t.Errorf("Version = %d, want 2", parsed.Version)
	}
}

// AC-6.13: smudge selects the key matching each value's own tag-declared
// version, not the config's current version — a keyring holding several
// versions can decrypt a file whose fields span all of them.
func TestSmudgeSelectsKeyByTagVersion(t *testing.T) {
	plaintext := []byte("-----BEGIN KEY-----")
	v1Cleaned, err := Clean(configAtVersion(1), Keyring{1: testKey}, "secrets/prod.pem", plaintext)
	if err != nil {
		t.Fatalf("clean under v1: %v", err)
	}

	keyring := Keyring{1: testKey, 2: v2Key}
	// The config's *current* version is 2, but the value is still tagged
	// version 1 (it hasn't been edited since rotation) — smudge must still
	// pick key 1 to decrypt it.
	got, err := Smudge(configAtVersion(2), keyring, "secrets/prod.pem", v1Cleaned)
	if err != nil {
		t.Fatalf("Smudge: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("Smudge() = %q, want %q", got, plaintext)
	}
}

// AC-6.11: a value tagged with a version the local keyring doesn't hold
// fails with a clear error naming the missing version — never a silent
// passthrough (that's only the empty-keyring case, AC-6.6) and never a
// guess.
func TestSmudgeUnknownVersionFails(t *testing.T) {
	plaintext := []byte("-----BEGIN KEY-----")
	cleaned, err := Clean(configAtVersion(1), Keyring{1: testKey}, "secrets/prod.pem", plaintext)
	if err != nil {
		t.Fatalf("clean: %v", err)
	}

	// This clone only ever ran `nebel init` for version 2 — it never
	// derived version 1's key.
	_, err = Smudge(configAtVersion(2), Keyring{2: v2Key}, "secrets/prod.pem", cleaned)
	if !errors.Is(err, ErrKeyVersionMissing) {
		t.Fatalf("Smudge() error = %v, want %v", err, ErrKeyVersionMissing)
	}
	if !strings.Contains(err.Error(), "version 1") {
		t.Errorf("error does not name the missing version: %v", err)
	}
}

// The per-value counterpart of TestSmudgeUnknownVersionFails: a field whose
// tag names a version the keyring lacks fails the same way, distinctly per
// field.
func TestSmudgeValuesUnknownVersionFails(t *testing.T) {
	cfg := &config.Config{KeyVersion: 1, Rules: []config.Rule{
		{Files: "config/*.yaml", Mode: config.ModeValue, Encrypt: []string{"database.password"}},
	}}
	cleaned, err := Clean(cfg, Keyring{1: testKey}, "config/staging.yaml", []byte(valueDoc))
	if err != nil {
		t.Fatalf("Clean: %v", err)
	}

	_, err = Smudge(cfg, Keyring{}, "config/staging.yaml", cleaned)
	if !errors.Is(err, ErrKeyVersionMissing) {
		t.Fatalf("Smudge() error = %v, want %v", err, ErrKeyVersionMissing)
	}
}

// Clean itself needs the current version's key to encrypt with; a keyring
// missing it is reported rather than silently doing nothing.
func TestCleanMissingCurrentVersionFails(t *testing.T) {
	_, err := Clean(configAtVersion(2), Keyring{1: testKey}, "secrets/prod.pem", []byte("plaintext"))
	if !errors.Is(err, ErrKeyVersionMissing) {
		t.Fatalf("Clean() error = %v, want %v", err, ErrKeyVersionMissing)
	}
}
