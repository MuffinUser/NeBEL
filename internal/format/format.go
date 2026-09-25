package format

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"

	"github.com/MarwinMoellers/strucrypt/internal/tag"
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
)

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
	// the dot-path that selects it. It is what `strucrypt add field`
	// offers to pick from, so a user never has to hand-write a path.
	Leaves(src []byte) ([]Leaf, error)

	// Render returns the literal source text for a value of type t —
	// quoting it if the format requires quotes for that type.
	Render(value string, t tag.Type) string
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
