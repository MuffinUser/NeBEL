// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import "testing"

// Regression test for the 2026-09-29 audit's P07 sub-issue 2: a glob
// written unescaped into a .gitattributes line breaks on the characters
// that syntax gives special meaning to, leaving the intended file with no
// effective filter assignment even though the add command reports success.
func TestEscapeGitattributesPattern(t *testing.T) {
	tests := []struct {
		name string
		glob string
		want string
	}{
		{"no special characters", "secrets/*.pem", "secrets/*.pem"},
		{"embedded space", "My File.env", `My\ File.env`},
		{"multiple spaces", "a b c.env", `a\ b\ c.env`},
		{"leading hash", "#backup.env", `\#backup.env`},
		{"leading bang", "!important.env", `\!important.env`},
		{"glob metacharacters untouched", "**/*.env", "**/*.env"},
		{"bracket class untouched", "secrets/[ab].pem", "secrets/[ab].pem"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := escapeGitattributesPattern(tt.glob); got != tt.want {
				t.Errorf("escapeGitattributesPattern(%q) = %q, want %q", tt.glob, got, tt.want)
			}
		})
	}
}
