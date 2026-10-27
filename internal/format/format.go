// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package format

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

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

	// ErrDuplicateKey is returned when a configured key occurs more than
	// once in a .env or .properties file. Both formats let the last
	// occurrence win at runtime, so encrypting any single one could leave
	// the effective value in plaintext (spec 05 AC-5.19).
	ErrDuplicateKey = errors.New("format: key occurs more than once")

	// ErrMultiline is returned when a configured key's value spans more
	// than one line, which line-based formats don't encrypt (AC-5.20).
	ErrMultiline = errors.New("format: value spans several lines; use mode: file for it")

	// ErrMalformed is returned for a line a line-based handler can't
	// parse. Skipping it instead could hide a key (AC-5.21).
	ErrMalformed = errors.New("format: malformed line")

	// ErrLiteralContext is returned when a decrypted value can't be
	// written back where its tag now sits, e.g. because the quotes around
	// the tag changed after it was encrypted (AC-5.25).
	ErrLiteralContext = errors.New("format: decrypted value does not fit its surrounding quotes")
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

	// Value is what gets encrypted. For YAML and JSON it is the scalar's
	// decoded content (quotes removed, escapes resolved), so the same
	// secret encrypts identically however it happened to be quoted. For
	// .env and .properties it is the raw literal between the value's
	// delimiters, escapes untouched; the quotes stay in the file outside
	// the span (spec 05 § Line-based formats).
	Value string

	// Type is the scalar's native type, recorded in the tag so decryption
	// can restore it.
	Type tag.Type

	// ctx is the quoting a line-based value sits in, for CheckLiteral.
	// Zero for YAML and JSON, whose Render escapes whatever it is given.
	ctx valueContext
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

	// CheckLiteral reports whether a decrypted value can be spliced over
	// span unchanged. Line-based formats render verbatim, and their
	// quotes aren't covered by the ciphertext's authentication, so a
	// value can come back into a context it was never valid in (spec 05
	// AC-5.25). YAML and JSON always accept: Render escapes for them.
	CheckLiteral(span Span, value string) error
}

// Leaf is one scalar in a document, addressable by Path.
type Leaf struct {
	// Path is the dot-notation path that selects this scalar.
	Path string

	// Value is the scalar's decoded content, and Type its native type.
	Value string
	Type  tag.Type
}

// Kind names a supported file format.
type Kind string

const (
	KindYAML       Kind = "yaml"
	KindJSON       Kind = "json"
	KindEnv        Kind = "env"
	KindProperties Kind = "properties"
)

// LineBased reports whether k addresses values by literal key rather than
// by dot-path: .env and .properties have no nesting, so a dot in a key is
// just a character.
func (k Kind) LineBased() bool {
	return k == KindEnv || k == KindProperties
}

// Detect returns the format of a file from its base name (spec 05
// AC-5.16). A known extension wins; otherwise ".env" and ".env.*" are
// dotenv files, since ".env.local"'s extension is ".local". name may also
// be a glob's last segment ("*.env", ".env.*"), which is how config
// validation picks a key syntax before any file is matched.
func Detect(name string) (Kind, bool) {
	switch filepath.Ext(name) {
	case ".yaml", ".yml":
		return KindYAML, true
	case ".json":
		return KindJSON, true
	case ".properties":
		return KindProperties, true
	case ".env":
		return KindEnv, true
	}
	if name == ".env" || strings.HasPrefix(name, ".env.") {
		return KindEnv, true
	}
	return "", false
}

// For returns the handler for a file path, chosen by its base name.
func For(filePath string) (Handler, error) {
	kind, _ := Detect(filepath.Base(filePath))
	switch kind {
	case KindYAML:
		return yamlHandler{}, nil
	case KindJSON:
		return jsonHandler{}, nil
	case KindEnv:
		return envHandler{}, nil
	case KindProperties:
		return propertiesHandler{}, nil
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
