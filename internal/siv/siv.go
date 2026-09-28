// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

// Package siv provides deterministic authenticated encryption (AES-256-SIV,
// RFC 5297) bound to the location the ciphertext is stored in.
//
// Encryption is deterministic by design: re-encrypting unchanged content
// reproduces byte-identical ciphertext, so a clean filter run over an
// unmodified file produces no git diff.
package siv

import (
	"encoding/binary"
	"errors"
	"fmt"

	tinksiv "github.com/tink-crypto/tink-go/v2/daead/subtle"
)

// KeySize is the required key length in bytes. RFC 5297 AES-256-SIV uses two
// 256-bit subkeys, derived from this single 512-bit key.
const KeySize = 64

// Mode is the encryption granularity a rule applies to a file.
type Mode string

const (
	// ModeFile encrypts a whole file as one blob.
	ModeFile Mode = "file"

	// ModeValue encrypts selected values within a structured file.
	ModeValue Mode = "value"
)

var (
	// ErrKeySize is returned when a key is not KeySize bytes long.
	ErrKeySize = errors.New("siv: invalid key size")

	// ErrAuth is returned when a ciphertext fails authentication: a wrong key,
	// mismatched associated data, or tampered bytes are indistinguishable and
	// all report this error.
	ErrAuth = errors.New("siv: authentication failed")
)

// AAD builds the associated data binding a ciphertext to one location.
//
// Without this binding, two fields holding the same secret would encrypt to
// identical ciphertext, and a ciphertext could be copy-pasted between fields
// and still decrypt. Components are length-prefixed, so no two distinct
// (mode, filePath, fieldPath) triples can produce the same bytes.
//
// filePath is repo-relative. fieldPath is empty for ModeFile.
func AAD(mode Mode, filePath, fieldPath string) []byte {
	var aad []byte
	for _, part := range []string{string(mode), filePath, fieldPath} {
		aad = binary.AppendUvarint(aad, uint64(len(part)))
		aad = append(aad, part...)
	}
	return aad
}

// Encrypt deterministically encrypts plaintext under key, authenticating aad.
func Encrypt(key, plaintext, aad []byte) ([]byte, error) {
	a, err := newAESSIV(key)
	if err != nil {
		return nil, err
	}
	ciphertext, err := a.EncryptDeterministically(plaintext, aad)
	if err != nil {
		return nil, fmt.Errorf("siv: encrypt: %w", err)
	}
	return ciphertext, nil
}

// Decrypt reverses Encrypt. It returns ErrAuth, and never a partially
// recovered or wrong-but-plausible plaintext, if authentication fails.
func Decrypt(key, ciphertext, aad []byte) ([]byte, error) {
	a, err := newAESSIV(key)
	if err != nil {
		return nil, err
	}
	plaintext, err := a.DecryptDeterministically(ciphertext, aad)
	if err != nil {
		return nil, ErrAuth
	}
	return plaintext, nil
}

func newAESSIV(key []byte) (*tinksiv.AESSIV, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("%w: got %d bytes, need %d", ErrKeySize, len(key), KeySize)
	}
	return tinksiv.NewAESSIV(key)
}
