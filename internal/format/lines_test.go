// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package format

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// AC-5.15, AC-5.16: lines carry real offsets into the source, terminators
// excluded, a BOM is skipped, and a lone "\r" ends a line only when asked.
func TestSplitLines(t *testing.T) {
	for _, tt := range []struct {
		name   string
		src    string
		loneCR bool
		want   []string
	}{
		{"LF", "a\nb\n", false, []string{"a", "b"}},
		{"CRLF", "a\r\nb\r\n", false, []string{"a", "b"}},
		{"mixed", "a\r\nb\nc", false, []string{"a", "b", "c"}},
		{"no trailing newline", "a\nb", false, []string{"a", "b"}},
		{"empty lines kept", "a\n\nb\n", false, []string{"a", "", "b"}},
		{"BOM skipped", "\xEF\xBB\xBFa\nb", false, []string{"a", "b"}},
		{"lone CR kept in content", "a\rb\n", false, []string{"a\rb"}},
		{"lone CR ends a line", "a\rb\n", true, []string{"a", "b"}},
		{"CRLF with loneCR is one break", "a\r\nb", true, []string{"a", "b"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			src := []byte(tt.src)
			var got []string
			for _, ln := range splitLines(src, tt.loneCR) {
				got = append(got, string(src[ln.start:ln.end]))
			}
			if fmt.Sprintf("%q", got) != fmt.Sprintf("%q", tt.want) {
				t.Errorf("splitLines(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func TestOddTrailingBackslashes(t *testing.T) {
	for in, want := range map[string]bool{``: false, `a`: false, `a\`: true, `a\\`: false, `a\\\`: true} {
		if got := oddTrailingBackslashes([]byte(in)); got != want {
			t.Errorf("oddTrailingBackslashes(%q) = %v, want %v", in, got, want)
		}
	}
}

// Shared bookkeeping for both line formats: a duplicate, a multi-line
// value and a key-only line each refuse to locate, and Leaves omits them.
func TestLocateEntryRefusals(t *testing.T) {
	entries := []entry{
		{key: "ok", line: 1, span: Span{Value: "v"}},
		{key: "dup", line: 2},
		{key: "dup", line: 5},
		{key: "multi", line: 3, multiline: true},
		{key: "bare", line: 4, noSeparator: true},
	}
	for key, want := range map[string]error{"dup": ErrDuplicateKey, "multi": ErrMultiline, "bare": ErrMalformed, "missing": ErrNotFound} {
		if _, err := locateEntry(entries, key); !errors.Is(err, want) {
			t.Errorf("locateEntry(%q) = %v, want %v", key, err, want)
		}
	}
	if _, err := locateEntry(entries, "dup"); !strings.Contains(err.Error(), "lines 2, 5") {
		t.Errorf("duplicate error should name both lines: %v", err)
	}

	leaves := entryLeaves(entries)
	if len(leaves) != 1 || leaves[0].Path != "ok" {
		t.Errorf("entryLeaves() = %+v, want only \"ok\"", leaves)
	}
}
