// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package config

import (
	"fmt"

	"github.com/MuffinUser/nebel/internal/gitutil"
	"github.com/goccy/go-yaml"
)

// HistoricalKey is the salt and canary a given key version was created
// with — everything needed to derive and verify that version's key, the
// same way the committed config does for the current version.
type HistoricalKey struct {
	Salt   string
	Canary string
}

// LookupVersion finds the salt and canary a key version was created with
// (spec 04 AC-4.9), for `nebel init --version N` (spec 07 AC-7.14) to fetch
// a version older than current's own.
//
// current is checked first — the fast path, and the only one that works
// for a version rotated locally but not yet committed. Anything else means
// walking .nebel.yaml's own git history for the (unique) commit that
// introduced version.
func LookupVersion(root string, current *Config, version int) (HistoricalKey, error) {
	if current.CurrentVersion() == version {
		return HistoricalKey{Salt: current.Salt, Canary: current.Canary}, nil
	}

	commits, err := gitutil.Log(root, FileName)
	if err != nil {
		return HistoricalKey{}, err
	}

	for _, commit := range commits {
		data, err := gitutil.Show(root, commit, FileName)
		if err != nil {
			// The path existed at some commits and not others in
			// unusual histories (e.g. FileName itself was renamed into
			// place) — skip rather than fail the whole walk over one
			// commit that doesn't have it.
			continue
		}
		var hist Config
		if err := yaml.Unmarshal(data, &hist); err != nil {
			continue
		}
		if hist.CurrentVersion() == version {
			return HistoricalKey{Salt: hist.Salt, Canary: hist.Canary}, nil
		}
	}

	if shallow, shallowErr := gitutil.IsShallow(root); shallowErr == nil && shallow {
		return HistoricalKey{}, fmt.Errorf("config: key version %d not found in %s's history, and this is a shallow clone — fetch full history (e.g. `git fetch --unshallow`) and try again", version, FileName)
	}
	return HistoricalKey{}, fmt.Errorf("config: key version %d not found in %s's history", version, FileName)
}
