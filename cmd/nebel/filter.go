// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/MarwinMoellers/nebel/internal/config"
	"github.com/MarwinMoellers/nebel/internal/filterop"
	"github.com/MarwinMoellers/nebel/internal/gitutil"
	"github.com/MarwinMoellers/nebel/internal/localkey"
)

func runClean(args []string) error {
	return runFilter(args, "clean", filterop.Clean)
}

func runSmudge(args []string) error {
	return runFilter(args, "smudge", filterop.Smudge)
}

type filterFunc func(cfg *config.Config, key []byte, filePath string, input []byte) ([]byte, error)

// runFilter is the shared clean/smudge entry point git invokes as
// `nebel clean %f` / `nebel smudge %f`, with file content on stdin
// and the transformed content expected on stdout.
//
// Per spec 06 AC-6.6, the only case that passes input through unchanged
// without error is "no local key registered" (nobody has run `nebel
// init` on this clone yet) — every other failure (bad config, tampered
// ciphertext, wrong key) is reported and aborts the git operation, since
// git.config filter.nebel.required is set to true at registration.
func runFilter(args []string, name string, fn filterFunc) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: nebel %s <path>", name)
	}
	filePath := args[0]

	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("reading stdin: %w", err)
	}

	key, ok, err := localkey.Get()
	if err != nil {
		return fmt.Errorf("reading local key: %w", err)
	}
	if !ok {
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

	output, err := fn(cfg, key, filePath, input)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(output)
	return err
}
