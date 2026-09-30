// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

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
		{"embedded space", "My File.env", `"My File.env"`},
		{"multiple spaces", "a b c.env", `"a b c.env"`},
		{"leading hash", "#backup.env", `\#backup.env`},
		{"leading bang", "!important.env", `\!important.env`},
		{"leading bang with embedded space", "!important file.env", `"\\!important file.env"`},
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

// TestEscapeGitattributesPatternResolvesInGit is the integration-level
// counterpart TestEscapeGitattributesPattern doesn't provide (audit
// 2026-09-30, R01): that test only checks the helper's string output, not
// that git's own attribute parser actually resolves "filter=nebel" for the
// path the pattern was meant to match. This asks git directly, via
// `check-attr`, for each produced pattern.
func TestEscapeGitattributesPatternResolvesInGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	tests := []struct {
		name string
		glob string
		path string
	}{
		{"no special characters", "secrets/*.pem", "secrets/prod.pem"},
		{"embedded space", "My File.env", "My File.env"},
		{"multiple spaces", "a b c.env", "a b c.env"},
		{"leading hash", "#backup.env", "#backup.env"},
		{"leading bang", "!important.env", "!important.env"},
		{"leading bang with embedded space", "!important file.env", "!important file.env"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// A real repo root, not just a bare attributes file: a
			// pattern containing '/' (like "secrets/*.pem") is anchored
			// to the .gitattributes file's directory, and check-attr
			// resolves the queried path relative to its own working
			// directory — both need to agree with how nebel actually
			// writes and later matches against .gitattributes at the
			// repo root, or this test would fail for reasons that have
			// nothing to do with escapeGitattributesPattern itself.
			dir := t.TempDir()
			if out, err := exec.Command("git", "-C", dir, "init", "-q").CombinedOutput(); err != nil {
				t.Fatalf("git init: %v\n%s", err, out)
			}
			line := escapeGitattributesPattern(tt.glob) + " filter=nebel\n"
			attrsPath := filepath.Join(dir, ".gitattributes")
			if err := os.WriteFile(attrsPath, []byte(line), 0o644); err != nil {
				t.Fatalf("writing attributes file: %v", err)
			}

			cmd := exec.Command("git", "check-attr", "filter", "--", tt.path)
			cmd.Dir = dir
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("git check-attr: %v\n%s", err, out)
			}
			if got := strings.TrimSpace(string(out)); !strings.HasSuffix(got, "filter: nebel") {
				t.Errorf("line %q: git check-attr for %q = %q, want it to resolve filter: nebel", line, tt.path, got)
			}
		})
	}
}
