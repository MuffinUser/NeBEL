// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

// Package localkey stores the derived AES-256-SIV key in local (per-clone,
// not committed) git config, so its presence or absence is exactly the
// "has this machine run `nebel init`" signal the clean/smudge filter
// needs for no-key passthrough (spec 06 AC-6.6).
//
// The key sits in plaintext in .git/config on disk. That file is never
// committed or pushed, which is the same trust boundary git-crypt and
// transcrypt rely on for the same purpose.
package localkey

import (
	"encoding/base64"
	"fmt"

	"github.com/MuffinUser/nebel/internal/gitutil"
)

const configKey = "filter.nebel.key"

// Get returns the locally registered key. ok is false, with a nil error,
// when no key is registered yet.
func Get() (key []byte, ok bool, err error) {
	encoded, ok, err := gitutil.ConfigGet(configKey)
	if err != nil || !ok {
		return nil, ok, err
	}
	key, err = base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, false, fmt.Errorf("localkey: decoding stored key: %w", err)
	}
	return key, true, nil
}

// Set registers key locally.
func Set(key []byte) error {
	return gitutil.ConfigSet(configKey, base64.StdEncoding.EncodeToString(key))
}
