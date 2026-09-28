// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package siv

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
)

// testKey is a fixed, valid 64-byte key for tests that are not about key size.
var testKey = bytes.Repeat([]byte{0xA5}, KeySize)

func fileAAD(path string) []byte { return AAD(ModeFile, path, "") }

// AC-2.1: the same key, plaintext and aad produce byte-identical ciphertext.
func TestEncryptIsDeterministic(t *testing.T) {
	aad := fileAAD("secrets/db.env")

	first, err := Encrypt(testKey, []byte("hunter2"), aad)
	if err != nil {
		t.Fatalf("first encrypt: %v", err)
	}
	second, err := Encrypt(testKey, []byte("hunter2"), aad)
	if err != nil {
		t.Fatalf("second encrypt: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Errorf("ciphertext differs between runs:\n first  = %x\n second = %x", first, second)
	}
}

// AC-2.2: the same key and plaintext under different aad produce different
// ciphertext, so equal secrets in different locations do not look equal.
func TestAADBindsCiphertextToLocation(t *testing.T) {
	tests := []struct {
		name string
		a, b []byte
	}{
		{"different file", fileAAD("secrets/db.env"), fileAAD("secrets/api.env")},
		{"different field", AAD(ModeValue, "app.yaml", "db.password"), AAD(ModeValue, "app.yaml", "api.token")},
		{"different mode", AAD(ModeFile, "app.yaml", ""), AAD(ModeValue, "app.yaml", "")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			first, err := Encrypt(testKey, []byte("hunter2"), tt.a)
			if err != nil {
				t.Fatalf("encrypt with first aad: %v", err)
			}
			second, err := Encrypt(testKey, []byte("hunter2"), tt.b)
			if err != nil {
				t.Fatalf("encrypt with second aad: %v", err)
			}
			if bytes.Equal(first, second) {
				t.Errorf("different aad produced identical ciphertext: %x", first)
			}
		})
	}
}

// AC-2.3: a ciphertext does not decrypt under aad it was not sealed with, so
// it cannot be copy-pasted to another location.
func TestDecryptRejectsWrongAAD(t *testing.T) {
	ciphertext, err := Encrypt(testKey, []byte("hunter2"), fileAAD("secrets/db.env"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	plaintext, err := Decrypt(testKey, ciphertext, fileAAD("secrets/api.env"))
	if !errors.Is(err, ErrAuth) {
		t.Errorf("Decrypt() error = %v, want %v", err, ErrAuth)
	}
	if plaintext != nil {
		t.Errorf("Decrypt() returned plaintext %q alongside an error", plaintext)
	}
}

// AC-2.4: encrypt/decrypt round-trips across the input shapes the filter sees.
func TestRoundTrip(t *testing.T) {
	multiKB := make([]byte, 8192)
	if _, err := rand.Read(multiKB); err != nil {
		t.Fatalf("generating multi-KB input: %v", err)
	}

	allBytes := make([]byte, 256)
	for i := range allBytes {
		allBytes[i] = byte(i)
	}

	tests := []struct {
		name      string
		plaintext []byte
	}{
		{"empty", []byte{}},
		{"nil", nil},
		{"short string", []byte("hunter2")},
		{"multi-KB blob", multiKB},
		{"every byte value", allBytes},
		{"embedded NUL and newline", []byte("a\x00b\nc\r\n")},
		{"invalid UTF-8", []byte{0xFF, 0xFE, 0xFD}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aad := fileAAD("secrets/db.env")

			ciphertext, err := Encrypt(testKey, tt.plaintext, aad)
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			got, err := Decrypt(testKey, ciphertext, aad)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if !bytes.Equal(got, tt.plaintext) {
				t.Errorf("round-trip mismatch:\n got  = %x\n want = %x", got, tt.plaintext)
			}
		})
	}
}

// AC-2.5: a wrong key is an authentication failure, never a plausible plaintext.
func TestDecryptRejectsWrongKey(t *testing.T) {
	aad := fileAAD("secrets/db.env")
	ciphertext, err := Encrypt(testKey, []byte("hunter2"), aad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	wrongKey := bytes.Repeat([]byte{0x5A}, KeySize)
	plaintext, err := Decrypt(wrongKey, ciphertext, aad)
	if !errors.Is(err, ErrAuth) {
		t.Errorf("Decrypt() error = %v, want %v", err, ErrAuth)
	}
	if plaintext != nil {
		t.Errorf("Decrypt() returned plaintext %q alongside an error", plaintext)
	}
}

// AC-2.6: flipping any single bit of a stored ciphertext is detected.
func TestDecryptDetectsTampering(t *testing.T) {
	aad := fileAAD("secrets/db.env")
	ciphertext, err := Encrypt(testKey, []byte("hunter2"), aad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	for i := range ciphertext {
		for bit := range 8 {
			tampered := bytes.Clone(ciphertext)
			tampered[i] ^= 1 << bit

			if _, err := Decrypt(testKey, tampered, aad); !errors.Is(err, ErrAuth) {
				t.Errorf("flipping byte %d bit %d: error = %v, want %v", i, bit, err, ErrAuth)
			}
		}
	}
}

// AC-2.7: a key that is not 512 bits is rejected up front, on both operations.
func TestRejectsWrongKeySize(t *testing.T) {
	sizes := []int{0, 1, 16, 32, 48, 63, 65, 128}

	for _, size := range sizes {
		key := bytes.Repeat([]byte{0xA5}, size)

		if _, err := Encrypt(key, []byte("hunter2"), nil); !errors.Is(err, ErrKeySize) {
			t.Errorf("Encrypt() with %d-byte key: error = %v, want %v", size, err, ErrKeySize)
		}
		if _, err := Decrypt(key, make([]byte, 32), nil); !errors.Is(err, ErrKeySize) {
			t.Errorf("Decrypt() with %d-byte key: error = %v, want %v", size, err, ErrKeySize)
		}
	}

	if _, err := Encrypt(nil, []byte("hunter2"), nil); !errors.Is(err, ErrKeySize) {
		t.Errorf("Encrypt() with nil key: error = %v, want %v", err, ErrKeySize)
	}
}

// The length prefixes exist so that no two distinct locations can collide into
// the same associated data; without them "a/b" + "c" and "a" + "/bc" would.
func TestAADIsUnambiguous(t *testing.T) {
	seen := map[string]string{}

	triples := []struct{ mode, file, field string }{
		{"file", "a/b", "c"},
		{"file", "a", "/bc"},
		{"file", "a/bc", ""},
		{"file", "", "a/bc"},
		{"value", "a/b", "c"},
		{"filea", "/b", "c"},
	}

	for _, tr := range triples {
		key := string(AAD(Mode(tr.mode), tr.file, tr.field))
		label := tr.mode + "|" + tr.file + "|" + tr.field
		if prev, collides := seen[label]; collides {
			t.Fatalf("duplicate test input %q", prev)
		}
		for otherKey, otherLabel := range seen {
			if otherKey == key {
				t.Errorf("distinct locations share associated data: %q and %q", label, otherLabel)
			}
		}
		seen[key] = label
	}
}

// Ciphertext is the on-disk format: if it changes, previously committed
// secrets stop decrypting. This vector pins the AES-SIV output layout and the
// AAD encoding across versions.
func TestEncryptGoldenVector(t *testing.T) {
	const want = "0f5552ceed73fc2501060339e28d55c4018223c1cac55e"

	key, err := hex.DecodeString(
		"1a4a0135a348d509ea1e901d39708b53c095d26dfd16e0dff5590f54be6ce04d" +
			"84bbbc73c8eb0140cc781f46b70a1992c754425f9053bab6846b10bcbaf3b47e")
	if err != nil {
		t.Fatalf("decoding key: %v", err)
	}

	ciphertext, err := Encrypt(key, []byte("hunter2"), AAD(ModeFile, "secrets/db.env", ""))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if got := hex.EncodeToString(ciphertext); got != want {
		t.Errorf("ciphertext format changed, committed secrets would break:\n got  = %s\n want = %s", got, want)
	}
}

// Truncated or malformed ciphertext reaches Decrypt whenever a committed
// ENC[...] blob is hand-edited or partially written. It must be reported as a
// checkable error, never a panic that would abort the surrounding git command.
func TestDecryptRejectsMalformedCiphertext(t *testing.T) {
	// Ciphertext is a 16-byte tag followed by the encrypted plaintext, so
	// anything below 17 bytes cannot be a sealed non-empty message.
	for _, size := range []int{0, 1, 15, 16, 17} {
		if _, err := Decrypt(testKey, make([]byte, size), fileAAD("secrets/db.env")); !errors.Is(err, ErrAuth) {
			t.Errorf("Decrypt() with %d-byte ciphertext: error = %v, want %v", size, err, ErrAuth)
		}
	}

	if _, err := Decrypt(testKey, nil, fileAAD("secrets/db.env")); !errors.Is(err, ErrAuth) {
		t.Errorf("Decrypt() with nil ciphertext: error = %v, want %v", err, ErrAuth)
	}
}
