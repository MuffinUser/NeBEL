// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

// Package localkey stores derived AES-256-SIV keys in local (per-clone, not
// committed) git config, so their presence or absence is exactly the "has
// this machine run `nebel init`" signal the clean/smudge filter needs for
// no-key passthrough (spec 06 AC-6.6).
//
// A machine may hold more than one key version at once (spec 11): every
// version it has ever derived via `nebel init` or `nebel rotate` stays
// cached, so it keeps being able to read content tagged with an older
// version after the project rotates.
//
// Keys sit in plaintext in .git/config on disk. That file is never
// committed or pushed, which is the same trust boundary git-crypt and
// transcrypt rely on for the same purpose.
package localkey

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/MuffinUser/nebel/internal/gitutil"
)

// configKeyPrefix is the local git config variable every version's key is
// stored under. Git config variable names may not contain "." themselves
// (only section/subsection separators may), so later versions suffix the
// number directly onto the name (key2, key3, ...) rather than adding
// another dot-separated segment.
const configKeyPrefix = "filter.nebel.key"

// configKeyFor returns the git config key a given version's derived key is
// stored under. Version 1 keeps the unsuffixed name every clone created
// before key rotation existed already writes and reads — so an upgraded
// binary keeps recognizing a key an older binary registered.
func configKeyFor(version int) string {
	if version == 1 {
		return configKeyPrefix
	}
	return fmt.Sprintf("%s%d", configKeyPrefix, version)
}

// Get returns the locally registered key for version. ok is false, with a
// nil error, when that version is not registered yet.
func Get(version int) (key []byte, ok bool, err error) {
	encoded, ok, err := gitutil.ConfigGet(configKeyFor(version))
	if err != nil || !ok {
		return nil, ok, err
	}
	key, err = base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, false, fmt.Errorf("localkey: decoding stored key for version %d: %w", version, err)
	}
	return key, true, nil
}

// Set registers key locally as version's key. Existing versions are left
// untouched (spec 11 AC-11.5): a machine that rotates, or fetches an older
// version via `nebel init --version N`, keeps reading everything it could
// read before.
func Set(version int, key []byte) error {
	return gitutil.ConfigSet(configKeyFor(version), base64.StdEncoding.EncodeToString(key))
}

// All returns every version currently registered locally, keyed by version
// number. An empty, non-nil map means no `nebel init` has ever run on this
// clone (spec 06 AC-6.6's no-key passthrough state).
func All() (map[int][]byte, error) {
	entries, err := gitutil.ConfigGetRegexp(`^filter\.nebel\.key[0-9]*$`)
	if err != nil {
		return nil, fmt.Errorf("localkey: listing registered keys: %w", err)
	}

	keyring := map[int][]byte{}
	for name, encoded := range entries {
		version := 1
		if suffix, ok := strings.CutPrefix(name, configKeyPrefix); ok && suffix != "" {
			version, err = strconv.Atoi(suffix)
			if err != nil {
				return nil, fmt.Errorf("localkey: unexpected local config key %q", name)
			}
		}
		key, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("localkey: decoding stored key for version %d: %w", version, err)
		}
		keyring[version] = key
	}
	return keyring, nil
}
