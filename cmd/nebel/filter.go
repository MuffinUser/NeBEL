// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/MuffinUser/nebel/internal/config"
	"github.com/MuffinUser/nebel/internal/filterop"
	"github.com/MuffinUser/nebel/internal/gitutil"
	"github.com/MuffinUser/nebel/internal/localkey"
)

func runClean(args []string) error {
	return runFilter(args, "clean", filterop.Clean)
}

func runSmudge(args []string) error {
	return runFilter(args, "smudge", func(cfg *config.Config, keyring filterop.Keyring, filePath string, input []byte) ([]byte, error) {
		output, skipped, err := filterop.Smudge(cfg, keyring, filePath, input)
		for _, s := range skipped {
			warnSkipped(cfg, filePath, s)
		}
		return output, err
	})
}

// warnSkipped reports one filterop.Skipped to stderr — visible directly
// on the terminal for whatever git operation (pull, checkout, merge)
// triggered the smudge, since filter stderr passes straight through.
// Stdout is reserved for the transformed content the git filter protocol
// expects, so this can never go there.
func warnSkipped(cfg *config.Config, filePath string, s filterop.Skipped) {
	fix := fixHint(cfg, s.Version)
	if s.Version == cfg.CurrentVersion() {
		fix = "was the key rotated? " + fix
	}
	if s.Field == "" {
		fmt.Fprintf(os.Stderr, "warning: nebel: %s needs key version %d — left encrypted; %s\n", filePath, s.Version, fix)
		return
	}
	fmt.Fprintf(os.Stderr, "warning: nebel: %s at %s needs key version %d — left encrypted; %s\n", filePath, s.Field, s.Version, fix)
}

type filterFunc func(cfg *config.Config, keyring filterop.Keyring, filePath string, input []byte) ([]byte, error)

// runFilter is the shared clean/smudge entry point git invokes as
// `nebel clean %f` / `nebel smudge %f`, with file content on stdin
// and the transformed content expected on stdout.
//
// Two cases pass input through unchanged without error: an *empty* local
// keyring (nobody has run `nebel init` on this clone yet, AC-6.6), and —
// smudge only — a well-formed tag naming a version the keyring doesn't
// hold (AC-6.11), which instead prints a warning (see warnSkipped) rather
// than aborting. Every other failure (bad config, tampered ciphertext,
// wrong key, clean with no key for content that still needs encrypting)
// is reported and aborts the git operation, since git.config
// filter.nebel.required is set to true at registration.
func runFilter(args []string, name string, fn filterFunc) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: nebel %s <path>", name)
	}
	filePath := args[0]

	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("reading stdin: %w", err)
	}

	keyring, err := localkey.All()
	if err != nil {
		return fmt.Errorf("reading local keyring: %w", err)
	}
	if len(keyring) == 0 {
		// No key registered on this clone: pass through unchanged. This is
		// the designed state for a fresh clone before `nebel init` runs.
		_, err := os.Stdout.Write(input)
		return err
	}

	root, err := gitutil.RepoRoot()
	if err != nil {
		return err
	}
	cfg, err := config.Load(filepath.Join(root, config.FileName))
	if err != nil {
		return err
	}

	// AC-6.10: if this clone holds a key for the config's current version,
	// it must actually be the right key. A mismatch here means local
	// corruption or a keyring entry that was never validated — unlike a
	// missing *other* version (AC-6.11), which is routine after rotation.
	if key, ok := keyring[cfg.CurrentVersion()]; ok {
		if err := cfg.VerifyCanary(key); err != nil {
			return fmt.Errorf("local key for version %d does not match this repo's canary — run `nebel init`: %w", cfg.CurrentVersion(), err)
		}
	}

	output, err := fn(cfg, filterop.Keyring(keyring), filePath, input)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(output)
	return err
}
