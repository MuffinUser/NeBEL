// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package kdf

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

// testSalt is a fixed, valid salt for tests that are not about salt handling.
var testSalt = []byte("nebel-test-salt-0123456789ab")

// AC-1.1: the same password and salt derive byte-identical key material.
func TestDeriveIsDeterministic(t *testing.T) {
	first, err := Derive("correct horse battery staple", testSalt)
	if err != nil {
		t.Fatalf("first derive: %v", err)
	}
	second, err := Derive("correct horse battery staple", testSalt)
	if err != nil {
		t.Fatalf("second derive: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Errorf("derived key material differs between runs:\n first  = %x\n second = %x", first, second)
	}
}

// AC-1.2: the same password with different salts derives different key material.
func TestDeriveDiffersBySalt(t *testing.T) {
	otherSalt := []byte("nebel-test-salt-ba9876543210")

	first, err := Derive("correct horse battery staple", testSalt)
	if err != nil {
		t.Fatalf("derive with testSalt: %v", err)
	}
	second, err := Derive("correct horse battery staple", otherSalt)
	if err != nil {
		t.Fatalf("derive with otherSalt: %v", err)
	}
	if bytes.Equal(first, second) {
		t.Errorf("different salts derived identical key material: %x", first)
	}
}

// AC-1.3: the same salt with different passwords derives different key material.
func TestDeriveDiffersByPassword(t *testing.T) {
	first, err := Derive("correct horse battery staple", testSalt)
	if err != nil {
		t.Fatalf("derive with first password: %v", err)
	}
	second, err := Derive("correct horse battery stapler", testSalt)
	if err != nil {
		t.Fatalf("derive with second password: %v", err)
	}
	if bytes.Equal(first, second) {
		t.Errorf("different passwords derived identical key material: %x", first)
	}
}

// AC-1.4: Argon2id costs are fixed constants. Changing any of them silently
// invalidates the key material of every existing repository, so the values are
// pinned here deliberately: update this test only alongside a migration path.
func TestArgon2ParametersAreFixed(t *testing.T) {
	if argon2Time != 3 {
		t.Errorf("argon2Time = %d, want 3", argon2Time)
	}
	if argon2Memory != 64*1024 {
		t.Errorf("argon2Memory = %d KiB, want %d KiB", argon2Memory, 64*1024)
	}
	if argon2Threads != 4 {
		t.Errorf("argon2Threads = %d, want 4", argon2Threads)
	}
	if argon2OutLen != 32 {
		t.Errorf("argon2OutLen = %d, want 32", argon2OutLen)
	}
}

// AC-1.5: HKDF expansion yields exactly the 512 bits AES-256-SIV requires.
func TestDeriveKeyLength(t *testing.T) {
	key, err := Derive("correct horse battery staple", testSalt)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if len(key) != KeySize {
		t.Errorf("len(key) = %d, want %d", len(key), KeySize)
	}
	if KeySize != 64 {
		t.Errorf("KeySize = %d, want 64 (two 256-bit AES-SIV subkeys)", KeySize)
	}
}

// AC-1.6: a freshly generated salt is long enough and unpredictable.
func TestNewSalt(t *testing.T) {
	salt := NewSalt()
	if len(salt) < 16 {
		t.Errorf("len(NewSalt()) = %d, want at least 16", len(salt))
	}
	if len(salt) != SaltSize {
		t.Errorf("len(NewSalt()) = %d, want SaltSize (%d)", len(salt), SaltSize)
	}
	if bytes.Equal(salt, NewSalt()) {
		t.Errorf("two generated salts are identical: %x", salt)
	}
	if bytes.Equal(salt, make([]byte, len(salt))) {
		t.Error("generated salt is all zero bytes")
	}
}

// AC-1.7: invalid input is rejected with a checkable error, never a weak key.
func TestDeriveRejectsBadInput(t *testing.T) {
	tests := []struct {
		name     string
		password string
		salt     []byte
		want     error
	}{
		{"empty password", "", testSalt, ErrEmptyPassword},
		{"nil salt", "correct horse battery staple", nil, ErrSaltTooShort},
		{"short salt", "correct horse battery staple", []byte("123456789012345"), ErrSaltTooShort},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := Derive(tt.password, tt.salt)
			if !errors.Is(err, tt.want) {
				t.Errorf("Derive() error = %v, want %v", err, tt.want)
			}
			if key != nil {
				t.Errorf("Derive() returned key material %x alongside an error", key)
			}
		})
	}
}

// Derived key material is part of the on-disk format: if it changes, every
// existing repository becomes undecryptable. This vector pins the whole
// pipeline (Argon2id costs, HKDF info string, output length) across versions.
func TestDeriveGoldenVector(t *testing.T) {
	const want = "b39b492077374b9d760309478d32fcb93c50733b2dd1f7e09f186ff222831ee0" +
		"d90292a5b15f453739a1d8897ac199e8fa74302cc8dfb371eebfa923c5c1d918"

	key, err := Derive("correct horse battery staple", testSalt)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if got := hex.EncodeToString(key); got != want {
		t.Errorf("key derivation changed, existing repositories would break:\n got  = %s\n want = %s", got, want)
	}
}
