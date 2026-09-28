// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/term"

	"github.com/MarwinMoellers/nebel/internal/format"
	"github.com/MarwinMoellers/nebel/internal/tag"
)

// previewWidth is where a displayed value is truncated. Values are shown
// so the user can tell which field is which; they are already plaintext on
// this machine, so showing them reveals nothing new, but a long key or
// certificate would otherwise flood the screen.
const previewWidth = 48

// pickFields lists the document's scalars and returns the ones the user
// selects. It is the alternative to hand-writing dot notation for a
// deeply nested key, which is easy to get subtly wrong.
func pickFields(handler format.Handler, source []byte, target string, existing map[string]bool) ([]string, error) {
	leaves, err := handler.Leaves(source)
	if err != nil {
		return nil, err
	}

	// Values that are already tagged, or already configured, can't be
	// selected again — offering them would invite a confusing no-op.
	var choices []format.Leaf
	for _, leaf := range leaves {
		if !existing[leaf.Path] && !tag.IsEncrypted([]byte(leaf.Value)) {
			choices = append(choices, leaf)
		}
	}
	if len(choices) == 0 {
		return nil, fmt.Errorf("%s has no unencrypted values left to add", target)
	}

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, fmt.Errorf("no terminal to choose on: pass the paths as arguments, e.g. nebel add field %s %s", target, choices[0].Path)
	}

	fmt.Printf("Values in %s:\n\n", target)
	for i, leaf := range choices {
		fmt.Printf("  %2d) %-40s %s\n", i+1, leaf.Path, preview(leaf))
	}
	fmt.Print("\nEncrypt which? (numbers, e.g. \"1 3\"; \"all\"; empty to cancel): ")

	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return nil, fmt.Errorf("reading selection: %w", err)
	}
	return parseSelection(line, choices)
}

// parseSelection turns the answer into paths. Out-of-range or non-numeric
// input is refused rather than skipped: silently ignoring part of a
// selection would leave a field the user believed they had protected.
func parseSelection(line string, choices []format.Leaf) ([]string, error) {
	answer := strings.TrimSpace(line)
	if answer == "" {
		return nil, fmt.Errorf("nothing selected")
	}
	if strings.EqualFold(answer, "all") {
		paths := make([]string, len(choices))
		for i, leaf := range choices {
			paths[i] = leaf.Path
		}
		return paths, nil
	}

	var paths []string
	for _, field := range strings.FieldsFunc(answer, func(r rune) bool { return r == ' ' || r == ',' || r == '\t' }) {
		n, err := strconv.Atoi(field)
		if err != nil || n < 1 || n > len(choices) {
			return nil, fmt.Errorf("%q is not one of the offered numbers (1-%d)", field, len(choices))
		}
		paths = append(paths, choices[n-1].Path)
	}
	return paths, nil
}

// preview renders a value for the chooser, shortened if it is long.
//
// Truncation counts runes, not bytes: slicing a UTF-8 value at a byte
// offset can cut a character in half and print a replacement glyph.
func preview(leaf format.Leaf) string {
	value := strings.ReplaceAll(leaf.Value, "\n", "\\n")
	if runes := []rune(value); len(runes) > previewWidth {
		value = string(runes[:previewWidth-1]) + "…"
	}
	if leaf.Type == tag.TypeStr {
		return fmt.Sprintf("%q", value)
	}
	return value
}
