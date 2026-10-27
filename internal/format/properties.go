// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package format

import (
	"fmt"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/MuffinUser/nebel/internal/tag"
)

// propertiesHandler locates values in Java .properties files, following
// java.util.Properties.load's line syntax (spec 05 § .properties).
//
// Keys are matched as Java reads them, escapes resolved, so `my\ key` is
// found by "my key". Values are the raw literal, escapes untouched, so the
// file's charset doesn't matter for them. It does for keys:
// Properties.load(InputStream) reads ISO-8859-1, a Reader-based load
// usually UTF-8, so a key with non-ASCII bytes is read under both
// (propertiesKey).
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
		e, err := propertiesKey(text[:keyEnd])
		if err != nil {
			return nil, malformed(n, "%v", err)
		}
		e.line, e.multiline = n, multiline
		if keyEnd == len(text) {
			e.refuse = malformed(n, "%q has no separator; write %q to encrypt it", e.key, e.key+"=")
		}
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

// propertiesKey reads a raw key as Java would: in a UTF-8 file (when the
// bytes are valid UTF-8) and in an ISO-8859-1 one. ASCII keys, escapes
// included, read the same either way. A configured key matches either
// spelling, and each is an alias under its charset, so `p\u00e4ss` and a
// raw ISO-8859-1 "päss" are duplicates (AC-5.19).
func propertiesKey(raw []byte) (entry, error) {
	latin1 := make([]rune, len(raw))
	for i, b := range raw {
		latin1[i] = rune(b)
	}
	key, err := unescapeProperties(latin1)
	if err != nil {
		return entry{}, err
	}
	e := entry{key: key, keys: []string{key}, aliases: []string{"latin1:" + key}}
	if utf8.Valid(raw) {
		utf8Key, err := unescapeProperties([]rune(string(raw)))
		if err != nil {
			return entry{}, err
		}
		e.key = utf8Key
		e.aliases = append(e.aliases, "utf8:"+utf8Key)
		if utf8Key != key {
			e.keys = []string{utf8Key, key}
		}
	}
	return e, nil
}

// unescapeProperties resolves a key's escapes as Java does: \t \n \r \f,
// \uXXXX, and a backslash before any other character yields that
// character (AC-5.31). Java strings are UTF-16, so two \uXXXX escapes
// forming a surrogate pair are one character; a lone surrogate is kept
// as its own code point (WTF-8) rather than U+FFFD, so two different
// ones don't read as the same key.
func unescapeProperties(raw []rune) (string, error) {
	var units []uint16
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			units = utf16.AppendRune(units, raw[i])
			continue
		}
		i++
		if i == len(raw) {
			break
		}
		switch c := raw[i]; c {
		case 't':
			units = append(units, '\t')
		case 'n':
			units = append(units, '\n')
		case 'r':
			units = append(units, '\r')
		case 'f':
			units = append(units, '\f')
		case 'u':
			if i+5 > len(raw) {
				return "", fmt.Errorf("malformed \\uXXXX escape in key %q", string(raw))
			}
			code, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
			if err != nil {
				return "", fmt.Errorf("malformed \\uXXXX escape in key %q", string(raw))
			}
			units = append(units, uint16(code))
			i += 4
		default:
			units = utf16.AppendRune(units, c)
		}
	}
	return decodeUTF16(units), nil
}

// decodeUTF16 is utf16.Decode, except that a lone surrogate is encoded as
// itself instead of being replaced by U+FFFD.
func decodeUTF16(units []uint16) string {
	var out []byte
	for i := 0; i < len(units); i++ {
		u := rune(units[i])
		if utf16.IsSurrogate(u) && i+1 < len(units) {
			if r := utf16.DecodeRune(u, rune(units[i+1])); r != utf8.RuneError {
				out = utf8.AppendRune(out, r)
				i++
				continue
			}
		}
		if utf16.IsSurrogate(u) {
			out = append(out, byte(0xE0|u>>12), byte(0x80|(u>>6)&0x3F), byte(0x80|u&0x3F))
			continue
		}
		out = utf8.AppendRune(out, u)
	}
	return string(out)
}

func isPropertiesSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\f' }

func skipPropertiesSpace(src []byte, from, to int) int {
	for from < to && isPropertiesSpace(src[from]) {
		from++
	}
	return from
}
