// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/MarwinMoellers/strucrypt/internal/format"
	"github.com/MarwinMoellers/strucrypt/internal/tag"
)

var pickChoices = []format.Leaf{
	{Path: "database.host", Value: "db.internal", Type: tag.TypeStr},
	{Path: "database.password", Value: "s3cr3t", Type: tag.TypeStr},
	{Path: "database.port", Value: "5432", Type: tag.TypeInt},
}

func TestParseSelection(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{"single", "2\n", []string{"database.password"}},
		{"space separated", "1 3\n", []string{"database.host", "database.port"}},
		{"comma separated", "1,3\n", []string{"database.host", "database.port"}},
		{"all", "all\n", []string{"database.host", "database.password", "database.port"}},
		{"all is case-insensitive", "ALL\n", []string{"database.host", "database.password", "database.port"}},
		{"surrounding whitespace", "  2  \n", []string{"database.password"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSelection(tt.input, pickChoices)
			if err != nil {
				t.Fatalf("parseSelection(%q): %v", tt.input, err)
			}
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Errorf("parseSelection(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// Junk in a selection is refused outright. Skipping the parts that didn't
// parse would leave the user believing they had protected a field they
// hadn't.
func TestParseSelectionRejectsBadInput(t *testing.T) {
	for _, input := range []string{"\n", "  \n", "0\n", "4\n", "-1\n", "two\n", "1 x\n", "1-3\n"} {
		if got, err := parseSelection(input, pickChoices); err == nil {
			t.Errorf("parseSelection(%q) = %v, want an error", input, got)
		}
	}
}

// A long value is shortened so one certificate doesn't flood the chooser.
func TestPreviewTruncates(t *testing.T) {
	long := format.Leaf{Path: "api.token", Value: strings.Repeat("x", 200), Type: tag.TypeStr}
	got := preview(long)
	if n := utf8.RuneCountInString(got); n > previewWidth+2 {
		t.Errorf("preview is %d characters, want at most %d", n, previewWidth+2)
	}
	if !strings.Contains(got, "…") {
		t.Errorf("a truncated preview should say so: %s", got)
	}

	// Non-strings are shown bare, so 5432 doesn't look like "5432".
	if got := preview(format.Leaf{Path: "p", Value: "5432", Type: tag.TypeInt}); got != "5432" {
		t.Errorf("preview of an int = %s, want 5432", got)
	}

	// Truncating multi-byte text must not cut a character in half.
	wide := preview(format.Leaf{Path: "p", Value: strings.Repeat("ü", 200), Type: tag.TypeStr})
	if !utf8.ValidString(wide) {
		t.Errorf("truncation produced invalid UTF-8: %q", wide)
	}
}
