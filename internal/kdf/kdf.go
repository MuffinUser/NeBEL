// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

// Package kdf derives AES-256-SIV key material from a human password and a
// non-secret salt that is committed to the repository.
package kdf

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	// KeySize is the derived key length in bytes. AES-SIV splits the key into
	// two 256-bit subkeys internally (RFC 5297), so AES-256-SIV needs 512 bits.
	KeySize = 64

	// SaltSize is the length of a freshly generated salt.
	SaltSize = 16

	// MinSaltSize is the shortest salt Derive accepts. Salts reach Derive from
	// a committed config file, so the length is validated rather than trusted.
	MinSaltSize = 16
)

// Argon2id cost parameters, fixed in code for v1.
//
// Values are RFC 9106 section 4's second recommended option (t=3, m=64 MiB,
// p=4), intended for memory-constrained environments. They land in the
// interactive range (~100ms on a current dev laptop) and stay within the
// memory a CI container can be assumed to have, while exceeding every OWASP
// Argon2id minimum.
//
// Changing any of these values changes every derived key: existing
// repositories become undecryptable, because v1 has no format field recording
// which costs a given repository was created with.
const (
	argon2Time    = 3
	argon2Memory  = 64 * 1024 // KiB
	argon2Threads = 4
	argon2OutLen  = 32
)

// hkdfInfo domain-separates this expansion from any other use of the same
// Argon2id output. Changing it changes every derived key.
const hkdfInfo = "nebel v1 aes-256-siv key"

var (
	// ErrEmptyPassword is returned when Derive is given an empty password.
	ErrEmptyPassword = errors.New("kdf: password must not be empty")

	// ErrSaltTooShort is returned when Derive is given a salt shorter than
	// MinSaltSize.
	ErrSaltTooShort = errors.New("kdf: salt too short")
)

// NewSalt returns a fresh salt from the system CSPRNG.
//
// The salt is not secret. It is stored alongside the encryption rules in the
// committed config so that every clone derives identical key material from the
// same password.
func NewSalt() []byte {
	salt := make([]byte, SaltSize)
	// crypto/rand.Read never returns an error; it crashes the process if the
	// system CSPRNG fails.
	rand.Read(salt)
	return salt
}

// Derive turns a password and salt into KeySize bytes of AES-256-SIV key
// material. It is deterministic: the same password and salt always yield the
// same key, on any machine.
func Derive(password string, salt []byte) ([]byte, error) {
	if password == "" {
		return nil, ErrEmptyPassword
	}
	if len(salt) < MinSaltSize {
		return nil, fmt.Errorf("%w: got %d bytes, need at least %d", ErrSaltTooShort, len(salt), MinSaltSize)
	}

	master := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2OutLen)

	// Expand without Extract: Argon2id output is already uniformly random,
	// which is the precondition HKDF-Expand requires (RFC 5869 section 3.3).
	key, err := hkdf.Expand(sha256.New, master, hkdfInfo, KeySize)
	if err != nil {
		return nil, fmt.Errorf("kdf: expanding key material: %w", err)
	}
	return key, nil
}
