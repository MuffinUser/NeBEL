// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package config

import (
	"fmt"

	"github.com/MuffinUser/nebel/internal/siv"
	"github.com/MuffinUser/nebel/internal/tag"
)

// CanaryPlaintext and CanaryAAD are the fixed constants the canary is
// encrypted over (spec 04 AC-4.8), so a candidate password can be verified
// against the committed config without any real secret existing yet.
const (
	CanaryPlaintext = "nebel-ok"
	CanaryAAD       = "nebel-canary"
)

// NewCanary encrypts CanaryPlaintext under key, tagging it with version, for
// storing as Config.Canary (spec 11).
func NewCanary(key []byte, version int) (string, error) {
	ciphertext, err := siv.Encrypt(key, []byte(CanaryPlaintext), []byte(CanaryAAD))
	if err != nil {
		return "", fmt.Errorf("config: encrypting canary: %w", err)
	}
	return tag.Encode(ciphertext, version), nil
}

// VerifyCanary reports whether key correctly decrypts c.Canary back to
// CanaryPlaintext. A non-nil error means the password is wrong or the
// config's canary is corrupt — both are reported identically, since
// distinguishing them isn't actionable for the caller.
func (c *Config) VerifyCanary(key []byte) error {
	parsed, err := tag.Parse(c.Canary)
	if err != nil {
		return fmt.Errorf("config: canary tag is malformed: %w", err)
	}
	plaintext, err := siv.Decrypt(key, parsed.Ciphertext, []byte(CanaryAAD))
	if err != nil {
		return fmt.Errorf("config: wrong password")
	}
	if string(plaintext) != CanaryPlaintext {
		return fmt.Errorf("config: canary mismatch")
	}
	return nil
}
