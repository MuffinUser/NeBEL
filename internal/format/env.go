// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package format

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/MuffinUser/nebel/internal/tag"
)

// envHandler locates values in dotenv files (spec 05 § .env).
//
// Paths are literal keys. What gets encrypted is the raw literal between
// the value's quotes, if any: quotes stay in the file, escapes are left
// alone, and smudge writes the literal back verbatim. Re-rendering would
// mean picking a quoting style, and in dotenv dialects the style changes
// meaning (docker-compose interpolates "$x" but not '$x').
type envHandler struct{}

func (envHandler) Locate(src []byte, path string) (Span, error) {
	entries, err := scanEnv(src)
	if err != nil {
		return Span{}, err
	}
	return locateEntry(entries, path)
}

func (envHandler) Leaves(src []byte) ([]Leaf, error) {
	entries, err := scanEnv(src)
	if err != nil {
		return nil, err
	}
	return entryLeaves(entries), nil
}

// Render returns value verbatim: quotes live outside the span (AC-5.23).
// It never fails; CheckLiteral is what rejects a value that doesn't fit.
func (envHandler) Render(value string, _ tag.Type) (string, error) { return value, nil }

// RoundTrip accepts only strings: a .env value has no other type, so a
// tag claiming one was never produced by clean.
func (envHandler) RoundTrip(_ string, t tag.Type) error { return lineTypeRoundTrip(t) }

// CheckLiteral rejects a value that would read back differently in the
// quoting its tag now sits in (AC-5.25).
func (envHandler) CheckLiteral(span Span, value string) error {
	if err := checkNoLineBreak(value); err != nil {
		return err
	}
	switch span.ctx {
	case ctxEnvDouble:
		for i := 0; i < len(value); i++ {
			switch value[i] {
			case '\\':
				i++
			case '"':
				return fmt.Errorf("%w: unescaped '\"' inside double quotes", ErrLiteralContext)
			}
		}
		if oddTrailingBackslashes([]byte(value)) {
			return fmt.Errorf("%w: a trailing backslash would escape the closing quote", ErrLiteralContext)
		}
	case ctxEnvSingle:
		if strings.ContainsRune(value, '\'') {
			return fmt.Errorf("%w: \"'\" inside single quotes", ErrLiteralContext)
		}
	case ctxEnvBare, ctxEnvBareSpaced:
		if value == "" {
			return nil
		}
		if value[0] == '\'' || value[0] == '"' {
			return fmt.Errorf("%w: an unquoted value can't start with a quote", ErrLiteralContext)
		}
		if strings.TrimLeft(value, " \t") != value || strings.TrimRight(value, " \t") != value {
			return fmt.Errorf("%w: an unquoted value can't start or end with whitespace", ErrLiteralContext)
		}
		if span.ctx == ctxEnvBareSpaced && value[0] == '#' {
			return fmt.Errorf("%w: an unquoted value after whitespace can't start with '#'", ErrLiteralContext)
		}
		for i := 1; i < len(value); i++ {
			if value[i] == '#' && isBlank(value[i-1]) {
				return fmt.Errorf("%w: ' #' in an unquoted value starts a comment", ErrLiteralContext)
			}
		}
	}
	return nil
}

// scanEnv tokenizes a dotenv file. Grammar, per line:
//
//	blank    := WS*
//	comment  := WS* "#" ANY*
//	entry    := WS* ["export" WS+] KEY WS* "=" WS* VALUE WS* ["#" ANY*]
//	KEY      := one or more chars, none whitespace or "="
//	VALUE    := unquoted | "'" ANY* "'" | '"' ("\" ANY | not-'"')* '"'
//	unquoted := to end of line, stopping before WS+ "#"; trailing WS excluded
//
// A quoted value may close on a later line; that entry is marked
// multiline, and KEY= lines inside it are recorded only as hidden
// entries for duplicate detection (AC-5.20).
// Anything else fails closed with ErrMalformed (AC-5.21).
func scanEnv(src []byte) ([]entry, error) {
	lines := splitLines(src, false)
	for i, ln := range lines {
		if bytes.IndexByte(src[ln.start:ln.end], '\r') >= 0 {
			return nil, malformed(i+1, "stray carriage return")
		}
	}

	var entries []entry
	for i := 0; i < len(lines); i++ {
		ln, n := lines[i], i+1
		p := skipBlanks(src, ln.start, ln.end)
		if p == ln.end || src[p] == '#' {
			continue
		}

		key, eq, err := envKey(src, p, ln.end)
		if err != nil {
			return nil, malformed(n, "%v", err)
		}
		v := skipBlanks(src, eq, ln.end)

		e := envEntry(key, n)
		if v < ln.end && (src[v] == '\'' || src[v] == '"') {
			quote := src[v]
			closing := findClosingQuote(src, v+1, quote)
			if closing < 0 {
				return nil, malformed(n, "unterminated %c quote", quote)
			}
			j := i
			for closing >= lines[j].end {
				j++
			}
			if r := skipBlanks(src, closing+1, lines[j].end); r < lines[j].end && src[r] != '#' {
				return nil, malformed(j+1, "unexpected text after the closing quote")
			}
			ctx := ctxEnvDouble
			if quote == '\'' {
				ctx = ctxEnvSingle
			}
			e.multiline = j > i
			e.span = Span{Start: v + 1, End: closing, Value: string(src[v+1 : closing]), Type: tag.TypeStr, ctx: ctx}
			// Whitespace inside the quotes is part of the value, so
			// around a tag it would make the tag unreadable, as in
			// .properties (AC-5.34).
			if trimmed := strings.Trim(e.span.Value, " \t"); trimmed != e.span.Value && tag.LooksEncrypted([]byte(trimmed)) {
				e.refuse = malformed(n, "whitespace around the ENC[...] tag of %q inside its quotes; remove it", key)
			}
			entries = append(entries, e)
			// Lines inside the quotes aren't entries here, but a reader
			// without multi-line quotes takes a KEY= line for one, and
			// a secret there would win over the encrypted one (AC-5.20).
			for k := i + 1; k <= j; k++ {
				p := skipBlanks(src, lines[k].start, lines[k].end)
				if key, _, err := envKey(src, p, lines[k].end); err == nil {
					hidden := envEntry(key, k+1)
					hidden.hiddenIn = n
					entries = append(entries, hidden)
				}
			}
			i = j
			continue
		}

		end := v
		for end < ln.end && !(src[end] == '#' && end > eq && isBlank(src[end-1])) {
			end++
		}
		for end > v && isBlank(src[end-1]) {
			end--
		}
		start, ctx := v, ctxEnvBare
		if v > eq {
			ctx = ctxEnvBareSpaced
		}
		if end == v {
			// An empty value sits directly after "=", so in
			// `KEY= # note` the tag lands before the whitespace and
			// the comment stays a comment (AC-5.22).
			start, end, ctx = eq, eq, ctxEnvBare
		}
		e.span = Span{Start: start, End: end, Value: string(src[start:end]), Type: tag.TypeStr, ctx: ctx}
		entries = append(entries, e)
	}
	return entries, nil
}

// envKey reads `["export" WS+] KEY WS* "="` starting at p and returns
// the key and the offset just past the "=".
func envKey(src []byte, p, end int) (string, int, error) {
	// "export" is a prefix only when whitespace follows it, so
	// "export=foo" stays an entry keyed "export" (AC-5.26).
	if rest := src[p:end]; bytes.HasPrefix(rest, []byte("export")) && len(rest) > 6 && isBlank(rest[6]) {
		p = skipBlanks(src, p+6, end)
	}

	k := p
	for k < end && !isBlank(src[k]) && src[k] != '=' {
		k++
	}
	if k == p {
		return "", 0, errors.New("expected KEY=value")
	}
	key := string(src[p:k])
	q := skipBlanks(src, k, end)
	if q == end || src[q] != '=' {
		return "", 0, fmt.Errorf("expected \"=\" after %q", key)
	}
	return key, q + 1, nil
}

// envEntry starts the entry for key on line n. Environment variable names
// are case-insensitive on Windows, so "SECRET" and "secret" share an
// alias: loaded there, the later one silently replaces the earlier
// (AC-5.19).
func envEntry(key string, n int) entry {
	return entry{key: key, keys: []string{key}, aliases: []string{"env:" + strings.ToUpper(key)}, line: n}
}

// findClosingQuote returns the offset of the quote closing a value that
// opened just before from, or -1. Inside double quotes a backslash
// escapes the next byte; single quotes have no escapes.
func findClosingQuote(src []byte, from int, quote byte) int {
	for i := from; i < len(src); i++ {
		switch {
		case quote == '"' && src[i] == '\\':
			i++
		case src[i] == quote:
			return i
		}
	}
	return -1
}

func isBlank(c byte) bool { return c == ' ' || c == '\t' }

func skipBlanks(src []byte, from, to int) int {
	for from < to && isBlank(src[from]) {
		from++
	}
	return from
}
