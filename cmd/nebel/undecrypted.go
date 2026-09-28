// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/MuffinUser/nebel/internal/config"
	"github.com/MuffinUser/nebel/internal/format"
	"github.com/MuffinUser/nebel/internal/gitutil"
	"github.com/MuffinUser/nebel/internal/tag"
)

// stuckContent names one managed whole file (mode: file, Field == "") or
// configured field (mode: value) whose current working-tree content is
// still an ENC[...] tag — this clone's local keyring doesn't hold
// whatever version produced it. Version is -1 when the content couldn't
// even be read, or the tag itself doesn't parse; describe distinguishes
// the two.
type stuckContent struct {
	Path    string
	Field   string
	Version int
	ReadErr error
}

// describe renders one stuckContent's problem on its own, without the
// path or field — callers prefix those themselves, since rotate's
// refusal error and init's per-file report want different layouts.
func (s stuckContent) describe() string {
	if s.ReadErr != nil {
		return fmt.Sprintf("could not be read: %v", s.ReadErr)
	}
	if s.Version < 0 {
		return "malformed tag"
	}
	return fmt.Sprintf("needs key version %d", s.Version)
}

// scanUndecrypted walks every managed path (gitutil.ManagedFiles) and
// reports each whole file or field whose current working-tree content is
// still an ENC[...] tag. Two callers rely on this:
//
//   - `nebel rotate` (checkFullyDecryptable), to refuse eagerly
//     re-encrypting a repo it can't fully reach rather than silently
//     stranding part of it on an old version (spec 11 AC-11.11).
//   - `nebel init` / `nebel init --version N` (reportCheckoutResult), to
//     report which files a re-checkout left still encrypted — smudge
//     passes those through rather than erroring (spec 06 AC-6.11), so
//     gitutil.CheckoutAll's own exit-code-based accounting no longer
//     catches them.
func scanUndecrypted(root string, cfg *config.Config) ([]stuckContent, error) {
	files, err := gitutil.ManagedFiles(root)
	if err != nil {
		return nil, err
	}

	var found []stuckContent
	for _, f := range files {
		rule, ok := cfg.MatchRule(f)
		if !ok {
			continue
		}
		content, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			found = append(found, stuckContent{Path: f, Version: -1, ReadErr: err})
			continue
		}

		if rule.Mode != config.ModeValue {
			if tag.IsEncrypted(content) {
				found = append(found, stuckContent{Path: f, Version: tagVersion(content)})
			}
			continue
		}

		handler, err := format.For(f)
		if err != nil {
			return nil, fmt.Errorf("checking %s: %w", f, err)
		}
		for _, field := range rule.Encrypt {
			span, err := handler.Locate(content, field)
			if err != nil {
				return nil, fmt.Errorf("checking %s: %w", f, err)
			}
			if tag.IsEncrypted([]byte(span.Value)) {
				found = append(found, stuckContent{Path: f, Field: field, Version: tagVersion([]byte(span.Value))})
			}
		}
	}
	return found, nil
}

// fixHint names the command that registers the key a stuck path needs:
// `nebel init` with the new password when it's the config's *current*
// version — the routine case right after someone else's `nebel rotate`,
// where this clone just hasn't rejoined with the new password yet —
// otherwise `nebel init --version N`, since this clone caught up to
// current but never fetched that specific older version.
func fixHint(cfg *config.Config, version int) string {
	if version == cfg.CurrentVersion() {
		return "run `nebel init` with the new password"
	}
	return fmt.Sprintf("run `nebel init --version %d`", version)
}

// tagVersion parses raw as an ENC[...] tag and returns the version it
// names, or -1 if it doesn't even parse.
func tagVersion(raw []byte) int {
	parsed, err := tag.Parse(string(raw))
	if err != nil {
		return -1
	}
	return parsed.Version
}
