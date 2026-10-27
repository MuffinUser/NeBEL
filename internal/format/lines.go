// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package format

import (
	"bytes"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/MuffinUser/nebel/internal/tag"
)

// valueContext is the syntax a line-based value sits in. It decides which
// decrypted literals can be written back verbatim (CheckLiteral).
type valueContext int

const (
	ctxNone valueContext = iota
	// ctxEnvBare is an unquoted .env value directly after "=".
	ctxEnvBare
	// ctxEnvBareSpaced is an unquoted .env value with whitespace before
	// it, where a leading "#" would start a comment.
	ctxEnvBareSpaced
	ctxEnvSingle
	ctxEnvDouble
	// ctxProperties is a .properties value after an "=" or ":" separator.
	ctxProperties
	// ctxPropertiesBlankSep is a .properties value after a whitespace-only
	// separator, where a leading "=" or ":" would be read as the separator.
	ctxPropertiesBlankSep
)

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// physLine is one physical line: its content is src[start:end], without
// the terminator, and the next line begins at next.
type physLine struct {
	start, end, next int
}

// splitLines splits src into physical lines with offsets into src itself,
// so spans located on them splice over the real bytes. A leading UTF-8
// BOM is skipped (AC-5.18). "\n" and "\r\n" end a line; with loneCR, a
// bare "\r" does too, as in java.util.Properties (AC-5.17). Without it, a
// bare "\r" stays in the line's content for the caller to reject.
func splitLines(src []byte, loneCR bool) []physLine {
	pos := 0
	if bytes.HasPrefix(src, utf8BOM) {
		pos = len(utf8BOM)
	}

	var lines []physLine
	for pos < len(src) {
		end := pos
		for end < len(src) && !lineBreakAt(src, end, loneCR) {
			end++
		}
		next := end
		if next < len(src) {
			if src[next] == '\r' && next+1 < len(src) && src[next+1] == '\n' {
				next += 2
			} else {
				next++
			}
		}
		lines = append(lines, physLine{start: pos, end: end, next: next})
		pos = next
	}
	return lines
}

func lineBreakAt(src []byte, i int, loneCR bool) bool {
	switch src[i] {
	case '\n':
		return true
	case '\r':
		return loneCR || (i+1 < len(src) && src[i+1] == '\n')
	}
	return false
}

// entry is one key/value entry found by a line-based tokenizer.
type entry struct {
	// key is the key as the application reads it, in the spelling the
	// picker offers.
	key string
	// keys are the spellings a configured key matches this entry under.
	// Usually just key; a .properties key read from non-UTF-8 bytes has
	// one per charset Java might read the file in.
	keys []string
	// aliases are every identity the application might read this entry
	// under. Two entries sharing one are the same key at runtime, so the
	// last one would win, and either is a duplicate of the other (AC-5.19).
	aliases []string
	// line is the 1-based physical line the entry starts on.
	line int
	// span is the value's location. Meaningful only when the entry is
	// locatable (not multiline, hidden or refused).
	span Span
	// multiline marks a value continued onto later lines (AC-5.20).
	multiline bool
	// hiddenIn is, for a KEY=value line inside another entry's multi-line
	// quoted value, the line that value starts on; 0 otherwise. A reader
	// that doesn't support multi-line quotes takes the line for an entry,
	// so it counts as a duplicate but is never located (AC-5.20).
	hiddenIn int
	// refuse, if set, is why this entry can't be encrypted in place, e.g.
	// a .properties line holding only a key (AC-5.33).
	refuse error
}

// locateEntry finds the one entry for key. Duplicates, multi-line values
// and refused entries are rejected rather than resolved to a guess, since
// each would leave the value the application actually reads unprotected
// or the file unparseable after clean.
func locateEntry(entries []entry, key string) (Span, error) {
	var found []int
	for i, e := range entries {
		if slices.Contains(e.keys, key) {
			found = append(found, i)
		}
	}
	if len(found) == 0 {
		return Span{}, fmt.Errorf("%w: %q", ErrNotFound, key)
	}

	if same := sameKey(entries, found); len(same) > 1 {
		lines := make([]string, len(same))
		spellings := []string{}
		for i, e := range same {
			lines[i] = fmt.Sprint(e.line)
			if !slices.Contains(spellings, e.key) {
				spellings = append(spellings, e.key)
			}
		}
		msg := fmt.Sprintf("%q on lines %s", key, strings.Join(lines, ", "))
		if len(spellings) > 1 {
			msg += fmt.Sprintf(" (spelled %s, which the application can read as one key)", quoteAll(spellings))
		}
		return Span{}, fmt.Errorf("%w: %s", ErrDuplicateKey, msg)
	}

	e := entries[found[0]]
	switch {
	case e.hiddenIn > 0:
		return Span{}, fmt.Errorf("%w: %q on line %d is inside the quoted value starting on line %d", ErrMultiline, key, e.line, e.hiddenIn)
	case e.multiline:
		return Span{}, fmt.Errorf("%w: %q on line %d", ErrMultiline, key, e.line)
	case e.refuse != nil:
		return Span{}, e.refuse
	}
	return e.span, nil
}

// sameKey returns, in source order, every entry sharing an alias with one
// of the entries at seeds, the seeds included.
func sameKey(entries []entry, seeds []int) []entry {
	aliases := map[string]bool{}
	for _, i := range seeds {
		for _, a := range entries[i].aliases {
			aliases[a] = true
		}
	}
	var same []entry
	for _, e := range entries {
		if slices.ContainsFunc(e.aliases, func(a string) bool { return aliases[a] }) {
			same = append(same, e)
		}
	}
	return same
}

// entryLeaves lists the entries locateEntry would accept, in source order
// (AC-5.24): offering any other would hand the user a key that can only
// fail.
func entryLeaves(entries []entry) []Leaf {
	count := map[string]int{}
	for _, e := range entries {
		for _, a := range e.aliases {
			count[a]++
		}
	}

	var leaves []Leaf
	for _, e := range entries {
		duplicated := slices.ContainsFunc(e.aliases, func(a string) bool { return count[a] > 1 })
		if duplicated || e.multiline || e.hiddenIn > 0 || e.refuse != nil {
			continue
		}
		leaves = append(leaves, Leaf{Path: e.key, Value: e.span.Value, Type: e.span.Type})
	}
	return leaves
}

func quoteAll(ss []string) string {
	q := make([]string, len(ss))
	for i, s := range ss {
		q[i] = strconv.Quote(s)
	}
	return strings.Join(q, ", ")
}

func malformed(line int, format string, args ...any) error {
	return fmt.Errorf("%w: line %d: %s", ErrMalformed, line, fmt.Sprintf(format, args...))
}

// oddTrailingBackslashes reports whether b ends in an odd number of
// backslashes, i.e. whether its last backslash escapes what follows.
func oddTrailingBackslashes(b []byte) bool {
	n := 0
	for i := len(b) - 1; i >= 0 && b[i] == '\\'; i-- {
		n++
	}
	return n%2 == 1
}

// lineTypeRoundTrip is RoundTrip for the line-based formats, whose values
// are always strings (spec 03, type preservation doesn't apply).
func lineTypeRoundTrip(t tag.Type) error {
	if t != tag.TypeStr {
		return fmt.Errorf("line-based formats only hold strings, not %s", t)
	}
	return nil
}

func checkNoLineBreak(value string) error {
	if strings.ContainsAny(value, "\r\n") {
		return fmt.Errorf("%w: it contains a line break", ErrLiteralContext)
	}
	return nil
}
