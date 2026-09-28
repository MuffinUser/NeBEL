// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package filterop

import (
	"bytes"
	"testing"

	"github.com/MarwinMoellers/nebel/internal/config"
	"github.com/MarwinMoellers/nebel/internal/tag"
)

var testKey = bytes.Repeat([]byte{0x42}, 64)

func testConfig() *config.Config {
	return &config.Config{Rules: []config.Rule{
		{Files: "secrets/*.pem", Mode: config.ModeFile},
	}}
}

// AC-6.1: clean on a mode: file rule wraps the whole input in one ENC[...] tag.
func TestCleanWholeFile(t *testing.T) {
	got, err := Clean(testConfig(), testKey, "secrets/prod.pem", []byte("-----BEGIN KEY-----"))
	if err != nil {
		t.Fatalf("Clean: %v", err)
	}
	if !tag.IsEncrypted(got) {
		t.Errorf("Clean() output is not tagged: %q", got)
	}
}

// AC-6.3: running clean twice on the same input, with the same key,
// produces byte-identical output both times.
func TestCleanIsIdempotent(t *testing.T) {
	input := []byte("-----BEGIN KEY-----")
	first, err := Clean(testConfig(), testKey, "secrets/prod.pem", input)
	if err != nil {
		t.Fatalf("first clean: %v", err)
	}
	second, err := Clean(testConfig(), testKey, "secrets/prod.pem", input)
	if err != nil {
		t.Fatalf("second clean: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Errorf("clean output differs between runs:\n first  = %q\n second = %q", first, second)
	}
}

// AC-6.4: clean run on input that is already a well-formed ENC[...] tag
// leaves it unchanged rather than double-encrypting.
func TestCleanSkipsAlreadyEncrypted(t *testing.T) {
	already := tag.Encode([]byte("some-ciphertext"))
	got, err := Clean(testConfig(), testKey, "secrets/prod.pem", []byte(already))
	if err != nil {
		t.Fatalf("Clean: %v", err)
	}
	if string(got) != already {
		t.Errorf("Clean() modified an already-encrypted value:\n got  = %q\n want = %q", got, already)
	}
}

// AC-6.5: smudge(clean(input)) == input byte-for-byte, for whole-file mode.
func TestRoundTrip(t *testing.T) {
	inputs := [][]byte{
		[]byte("-----BEGIN KEY-----\nsecret\n-----END KEY-----\n"),
		{},
		bytes.Repeat([]byte{0xAB, 0xCD}, 1000),
	}
	for _, input := range inputs {
		cleaned, err := Clean(testConfig(), testKey, "secrets/prod.pem", input)
		if err != nil {
			t.Fatalf("Clean: %v", err)
		}
		smudged, err := Smudge(testConfig(), testKey, "secrets/prod.pem", cleaned)
		if err != nil {
			t.Fatalf("Smudge: %v", err)
		}
		if !bytes.Equal(smudged, input) {
			t.Errorf("round-trip mismatch:\n got  = %x\n want = %x", smudged, input)
		}
	}
}

// A file that matches no rule passes through unchanged on both operations.
func TestUnmatchedFilePassesThrough(t *testing.T) {
	input := []byte("plain content")
	cleaned, err := Clean(testConfig(), testKey, "README.md", input)
	if err != nil {
		t.Fatalf("Clean: %v", err)
	}
	if !bytes.Equal(cleaned, input) {
		t.Errorf("Clean() on an unmatched file changed the content: %q", cleaned)
	}

	smudged, err := Smudge(testConfig(), testKey, "README.md", input)
	if err != nil {
		t.Fatalf("Smudge: %v", err)
	}
	if !bytes.Equal(smudged, input) {
		t.Errorf("Smudge() on an unmatched file changed the content: %q", smudged)
	}
}

// AC-6.7: smudge on a value that isn't a well-formed ENC[...] tag (e.g. a
// file not yet migrated through clean) passes it through unchanged.
func TestSmudgeTolerantOfPlaintext(t *testing.T) {
	input := []byte("still plaintext, filter never registered when this was staged")
	got, err := Smudge(testConfig(), testKey, "secrets/prod.pem", input)
	if err != nil {
		t.Fatalf("Smudge: %v", err)
	}
	if !bytes.Equal(got, input) {
		t.Errorf("Smudge() changed untagged input: %q", got)
	}
}

// AC-6.9: smudge on a well-formed but tampered ENC[...] tag fails with a
// clear error rather than emitting corrupted plaintext.
func TestSmudgeSurfacesTampering(t *testing.T) {
	cleaned, err := Clean(testConfig(), testKey, "secrets/prod.pem", []byte("-----BEGIN KEY-----"))
	if err != nil {
		t.Fatalf("Clean: %v", err)
	}
	tampered := bytes.Clone(cleaned)
	// Flip a bit inside the base64 data field, past "ENC[AES256_SIV,data:".
	flipIdx := len("ENC[AES256_SIV,data:") + 2
	tampered[flipIdx] ^= 1

	plaintext, err := Smudge(testConfig(), testKey, "secrets/prod.pem", tampered)
	if err == nil {
		t.Fatalf("Smudge() on tampered ciphertext: want an error, got plaintext %q", plaintext)
	}
	if plaintext != nil {
		t.Errorf("Smudge() returned plaintext %q alongside an error", plaintext)
	}
}

// Decrypting a matched, tagged value under the wrong key surfaces an error
// instead of silently smudging garbage into the working tree.
func TestSmudgeWrongKey(t *testing.T) {
	cleaned, err := Clean(testConfig(), testKey, "secrets/prod.pem", []byte("-----BEGIN KEY-----"))
	if err != nil {
		t.Fatalf("Clean: %v", err)
	}
	wrongKey := bytes.Repeat([]byte{0x99}, 64)
	if _, err := Smudge(testConfig(), wrongKey, "secrets/prod.pem", cleaned); err == nil {
		t.Error("Smudge() with the wrong key: want an error, got nil")
	}
}
