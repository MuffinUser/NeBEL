// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package format

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"

	"github.com/MuffinUser/nebel/internal/tag"
)

var (
	// ErrNotFound is returned when a configured path does not exist in the
	// file. Silently skipping it would leave a secret in plaintext while
	// reporting success (spec 05 AC-5.2).
	ErrNotFound = errors.New("format: path not found")

	// ErrUnsupportedFormat is returned for a file extension no handler
	// claims.
	ErrUnsupportedFormat = errors.New("format: unsupported file format")

	// ErrNotScalar is returned when a path resolves to a mapping or
	// sequence rather than a single value.
	ErrNotScalar = errors.New("format: path does not resolve to a scalar")

	// ErrAmbiguousPath is returned when a configured path selects more
	// than one distinct location in the same document. Two ways this
	// happens: a literal key containing a dot collides with the
	// equivalent nested path — dot notation can't tell "a.b" the flat key
	// from "a" containing "b" apart, and a dot inside a key can't be
	// escaped (ParsePath's doc comment) — or an outright duplicate key at
	// the same nesting level (JSON's streaming decoder does not reject
	// these the way go-yaml's parser does). Locate's traversal can only
	// ever resolve to one of them; picking one silently, as earlier
	// versions did, could protect the wrong (or only one) of several
	// values while reporting success — the same silent-failure concern
	// ErrNotFound already guards for a path that resolves to nothing.
	ErrAmbiguousPath = errors.New("format: path is ambiguous")
)

// checkUnambiguous reports ErrAmbiguousPath if path selects more than one
// leaf in src (see ErrAmbiguousPath), by cross-checking against h.Leaves,
// which — unlike a targeted descent — visits every literal key in the
// document and so surfaces a collision a single-path lookup never would.
func checkUnambiguous(h Handler, src []byte, path string) error {
	leaves, err := h.Leaves(src)
	if err != nil {
		return err
	}
	matches := 0
	for _, leaf := range leaves {
		if leaf.Path == path {
			matches++
		}
	}
	if matches > 1 {
		return fmt.Errorf("%w: %q matches %d different values", ErrAmbiguousPath, path, matches)
	}
	return nil
}

// Span is one located scalar: where it sits in the source, and what it is.
type Span struct {
	// Start and End bound the scalar as written, including any quotes, so
	// splicing a replacement over [Start:End) leaves the rest untouched.
	Start, End int

	// Value is the scalar's decoded content: quotes removed, escapes
	// resolved. This is what gets encrypted, so that the same secret
	// encrypts identically however it happened to be quoted.
	Value string

	// Type is the scalar's native type, recorded in the tag so decryption
	// can restore it.
	Type tag.Type
}

// Handler locates and renders scalars for one file format.
type Handler interface {
	// Locate returns the span of the scalar at path.
	Locate(src []byte, path string) (Span, error)

	// Leaves lists every scalar in the document, in source order, with
	// the dot-path that selects it. It is what `nebel add field`
	// offers to pick from, so a user never has to hand-write a path.
	Leaves(src []byte) ([]Leaf, error)

	// Render returns the literal source text for a value of type t —
	// quoting it if the format requires quotes for that type. An error
	// means value cannot be safely rendered in this format at all — see
	// yamlHandler.Render's doc comment for the one case that applies today
	// (audit 2026-09-29, P10).
	Render(value string, t tag.Type) (string, error)

	// RoundTrip reports an error unless rendering value as t, then
	// reading that rendered text back via Locate, recovers exactly value
	// and t again. This is what validTypeLiteral (internal/filterop)
	// uses to decide whether a historical, type-flipped legacy value tag
	// (see internal/tag's doc comment on AlgoAES256SIV's unauthenticated
	// type field) is safe to render: a value accepted by Go's own
	// strconv parsers is not necessarily one this format's own parser
	// would read back the same way — strconv.ParseFloat accepts "NaN",
	// which is not a value either JSON or this package's YAML handler
	// recognizes as a float, and strconv.ParseBool accepts "1", which
	// both formats read back as an int rather than a bool. Checking
	// round-trip fidelity against each format's own parser catches both
	// without needing a hand-maintained catalogue of every way a format's
	// accepted literals are stricter than Go's (audit 2026-09-30,
	// reanalysis 4.4). A value Clean or Smudge actually produced always
	// round-trips, by construction, so this never rejects legitimate
	// content.
	RoundTrip(value string, t tag.Type) error
}

// Leaf is one scalar in a document, addressable by Path.
type Leaf struct {
	// Path is the dot-notation path that selects this scalar.
	Path string

	// Value is the scalar's decoded content, and Type its native type.
	Value string
	Type  tag.Type
}

// For returns the handler for a file path, chosen by extension.
func For(filePath string) (Handler, error) {
	switch filepath.Ext(filePath) {
	case ".yaml", ".yml":
		return yamlHandler{}, nil
	case ".json":
		return jsonHandler{}, nil
	}
	return nil, fmt.Errorf("%w: %s", ErrUnsupportedFormat, filePath)
}

// Edit replaces the bytes of one span with new literal text.
type Edit struct {
	Span Span
	Text string
}

// Splice applies edits to src and returns the result. Everything outside
// the edited spans is copied verbatim (AC-5.1): the untouched bytes are
// carried across, never re-rendered.
func Splice(src []byte, edits []Edit) ([]byte, error) {
	ordered := append([]Edit(nil), edits...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Span.Start < ordered[j].Span.Start })

	out := make([]byte, 0, len(src))
	prev := 0
	for _, e := range ordered {
		if e.Span.Start < prev || e.Span.End > len(src) || e.Span.Start > e.Span.End {
			// Two configured paths resolving to overlapping bytes would
			// make the result depend on apply order; refuse instead.
			return nil, fmt.Errorf("format: edit span [%d:%d) overlaps another edit or falls outside the file", e.Span.Start, e.Span.End)
		}
		out = append(out, src[prev:e.Span.Start]...)
		out = append(out, e.Text...)
		prev = e.Span.End
	}
	return append(out, src[prev:]...), nil
}

// joinPath appends one step to a dot-path, using bracket syntax for
// sequence indices: "api" + "keys" + 0 renders as "api.keys[0]".
func joinPath(parent, key string) string {
	if parent == "" {
		return key
	}
	return parent + "." + key
}

func indexPath(parent string, i int) string {
	return fmt.Sprintf("%s[%d]", parent, i)
}
