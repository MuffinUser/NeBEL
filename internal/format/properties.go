// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package format

import (
	"fmt"
	"strconv"
	"unicode/utf8"

	"github.com/MuffinUser/nebel/internal/tag"
)

// propertiesHandler locates values in Java .properties files, following
// java.util.Properties.load's line syntax (spec 05 § .properties).
//
// Keys are matched as Java reads them, escapes resolved, so `my\ key` is
// found by "my key". Values are the raw literal, escapes untouched: the
// file is treated as bytes, so whether it is ISO-8859-1 or UTF-8 never
// matters.
type propertiesHandler struct{}

func (propertiesHandler) Locate(src []byte, path string) (Span, error) {
	entries, err := scanProperties(src)
	if err != nil {
		return Span{}, err
	}
	return locateEntry(entries, path)
}

func (propertiesHandler) Leaves(src []byte) ([]Leaf, error) {
	entries, err := scanProperties(src)
	if err != nil {
		return nil, err
	}
	return entryLeaves(entries), nil
}

// Render returns value verbatim (AC-5.23).
func (propertiesHandler) Render(value string, _ tag.Type) (string, error) { return value, nil }

// RoundTrip accepts only strings, as for .env.
func (propertiesHandler) RoundTrip(_ string, t tag.Type) error { return lineTypeRoundTrip(t) }

// CheckLiteral rejects a value Java would read back differently where its
// tag now sits (AC-5.25).
func (propertiesHandler) CheckLiteral(span Span, value string) error {
	if err := checkNoLineBreak(value); err != nil {
		return err
	}
	if value == "" {
		return nil
	}
	if isPropertiesSpace(value[0]) {
		return fmt.Errorf("%w: leading whitespace would be dropped", ErrLiteralContext)
	}
	if oddTrailingBackslashes([]byte(value)) {
		return fmt.Errorf("%w: a trailing backslash would continue the line", ErrLiteralContext)
	}
	if span.ctx == ctxPropertiesBlankSep && (value[0] == '=' || value[0] == ':') {
		return fmt.Errorf("%w: a leading %q would be read as the separator", ErrLiteralContext, value[0])
	}
	return nil
}

// scanProperties tokenizes a .properties file. Lines end at "\n", "\r" or
// "\r\n". A line whose first non-whitespace character is '#' or '!' is a
// comment and never continues. Any other line ending in an odd number of
// backslashes continues onto the next one; such an entry is recorded for
// duplicate detection but marked multiline (AC-5.13, AC-5.20).
func scanProperties(src []byte) ([]entry, error) {
	lines := splitLines(src, true)

	var entries []entry
	for i := 0; i < len(lines); i++ {
		ln, n := lines[i], i+1
		p := skipPropertiesSpace(src, ln.start, ln.end)
		if p == ln.end || src[p] == '#' || src[p] == '!' {
			continue
		}

		// A final line ending in a backslash has nothing to continue
		// onto, but its value still ends in an escape smudge couldn't
		// write back, so it counts as multiline too.
		j := i
		for oddTrailingBackslashes(src[lines[j].start:lines[j].end]) && j+1 < len(lines) {
			j++
		}
		multiline := j > i || oddTrailingBackslashes(src[lines[j].start:lines[j].end])

		text, offset := src[p:ln.end], p
		if multiline {
			text, offset = joinContinuation(src, lines[i:j+1], p), -1
		}

		keyEnd, valueStart, explicit := splitPropertiesEntry(text)
		key, err := unescapeProperties(text[:keyEnd])
		if err != nil {
			return nil, malformed(n, "%v", err)
		}

		e := entry{key: key, line: n, multiline: multiline, noSeparator: keyEnd == len(text)}
		if offset >= 0 {
			ctx := ctxProperties
			if !explicit {
				ctx = ctxPropertiesBlankSep
			}
			start, end := offset+valueStart, ln.end
			e.span = Span{Start: start, End: end, Value: string(src[start:end]), Type: tag.TypeStr, ctx: ctx}
		}
		entries = append(entries, e)
		i = j
	}
	return entries, nil
}

// joinContinuation builds a continued entry's logical text the way Java
// does: each line's trailing backslash is dropped and the next line's
// leading whitespace is skipped. Only used to read the key, since a
// multiline value is never located.
func joinContinuation(src []byte, lines []physLine, first int) []byte {
	var text []byte
	for k, ln := range lines {
		start := ln.start
		if k == 0 {
			start = first
		} else {
			start = skipPropertiesSpace(src, start, ln.end)
		}
		part := src[start:ln.end]
		if oddTrailingBackslashes(part) {
			part = part[:len(part)-1]
		}
		text = append(text, part...)
	}
	return text
}

// splitPropertiesEntry finds where the key ends and the value starts. The
// key runs to the first unescaped '=', ':' or whitespace. The separator
// is optional whitespace, at most one '=' or ':', then more whitespace;
// explicit reports whether it held an '=' or ':'. The value runs to the
// end of the line, trailing whitespace included, as in Java.
func splitPropertiesEntry(text []byte) (keyEnd, valueStart int, explicit bool) {
	for keyEnd < len(text) {
		c := text[keyEnd]
		if c == '\\' {
			keyEnd += 2
			continue
		}
		if c == '=' || c == ':' || isPropertiesSpace(c) {
			break
		}
		keyEnd++
	}
	if keyEnd > len(text) {
		keyEnd = len(text)
	}

	valueStart = skipPropertiesSpace(text, keyEnd, len(text))
	if valueStart < len(text) && (text[valueStart] == '=' || text[valueStart] == ':') {
		explicit = true
		valueStart = skipPropertiesSpace(text, valueStart+1, len(text))
	}
	return keyEnd, valueStart, explicit
}

// unescapeProperties resolves a key's escapes as Java does: \t \n \r \f,
// \uXXXX, and a backslash before any other character yields that
// character (AC-5.31).
func unescapeProperties(raw []byte) (string, error) {
	out := make([]byte, 0, len(raw))
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			out = append(out, raw[i])
			continue
		}
		i++
		if i == len(raw) {
			break
		}
		switch c := raw[i]; c {
		case 't':
			out = append(out, '\t')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 'f':
			out = append(out, '\f')
		case 'u':
			if i+5 > len(raw) {
				return "", fmt.Errorf("malformed \\uXXXX escape in key %q", raw)
			}
			code, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
			if err != nil {
				return "", fmt.Errorf("malformed \\uXXXX escape in key %q", raw)
			}
			out = utf8.AppendRune(out, rune(code))
			i += 4
		default:
			out = append(out, c)
		}
	}
	return string(out), nil
}

func isPropertiesSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\f' }

func skipPropertiesSpace(src []byte, from, to int) int {
	for from < to && isPropertiesSpace(src[from]) {
		from++
	}
	return from
}
