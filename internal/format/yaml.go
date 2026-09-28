// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package format

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
	"github.com/goccy/go-yaml/token"

	"github.com/MuffinUser/nebel/internal/tag"
)

type yamlHandler struct{}

// Locate walks the YAML AST to the node at path and returns the byte span
// its scalar occupies in the source, quotes included.
//
// go-yaml's own Line/Column tracking (which yamlSpan's byte-offset math
// depends on) miscounts against raw "\r\n" — a real-world case, since
// Windows checking out a repo with core.autocrlf on reintroduces "\r"
// into the working tree that clean never put there. Parsing is done
// against a CRLF-normalized copy instead, with a crlfMap translating the
// resulting span back to real offsets in src, so Locate still splices
// over the actual bytes on disk. When src has no "\r\n" at all, the map
// is the identity and this is exactly the original behavior.
func (yamlHandler) Locate(src []byte, path string) (Span, error) {
	steps, err := ParsePath(path)
	if err != nil {
		return Span{}, err
	}

	m := newCRLFMap(src)

	file, err := parser.ParseBytes(m.norm, parser.ParseComments)
	if err != nil {
		return Span{}, fmt.Errorf("format: parsing YAML: %w", err)
	}
	if len(file.Docs) == 0 || file.Docs[0].Body == nil {
		return Span{}, fmt.Errorf("%w: %q (document is empty)", ErrNotFound, path)
	}

	node := file.Docs[0].Body
	for i, step := range steps {
		node, err = yamlStep(node, step)
		if err != nil {
			// Name the deepest component that did resolve, so a typo in a
			// long path points at the step that broke rather than the
			// whole string.
			if failed := strings.Join(pathPrefix(steps, i+1), ""); failed != path {
				return Span{}, fmt.Errorf("%w: %q (no %q)", ErrNotFound, path, failed)
			}
			return Span{}, fmt.Errorf("%w: %q", ErrNotFound, path)
		}
	}

	scalar, ok := node.(ast.ScalarNode)
	if !ok {
		return Span{}, fmt.Errorf("%w: %q is a %s", ErrNotScalar, path, node.Type())
	}
	return yamlSpan(src, m, scalar.GetToken(), path)
}

// crlfMap translates byte offsets computed against a CRLF-normalized copy
// of a source buffer (every "\r\n" replaced by "\n") back to offsets in
// the original buffer.
type crlfMap struct {
	// norm is what the YAML parser actually sees: src unchanged if it had
	// no "\r\n" at all, otherwise a copy with every one collapsed to "\n".
	norm []byte
	// orig[i] is the offset in src that norm[i] came from. Absent (nil)
	// when norm == src, in which case every offset already matches as-is.
	orig []int
	// srcLen lets a normalized offset one past the last byte (a span
	// ending at EOF) map to the true end of src, since orig has no entry
	// there to look up.
	srcLen int
}

func newCRLFMap(src []byte) crlfMap {
	if !bytes.Contains(src, []byte("\r\n")) {
		return crlfMap{norm: src}
	}
	norm := make([]byte, 0, len(src))
	orig := make([]int, 0, len(src))
	for i := 0; i < len(src); i++ {
		if src[i] == '\r' && i+1 < len(src) && src[i+1] == '\n' {
			continue
		}
		norm = append(norm, src[i])
		orig = append(orig, i)
	}
	return crlfMap{norm: norm, orig: orig, srcLen: len(src)}
}

// toSrc translates an *inclusive* byte offset in m.norm — the first byte
// of a span — to the corresponding offset in the original source.
func (m crlfMap) toSrc(normOffset int) int {
	if m.orig == nil {
		return normOffset
	}
	if normOffset >= len(m.orig) {
		return m.srcLen
	}
	return m.orig[normOffset]
}

// toSrcEnd translates an *exclusive* end offset in m.norm — one past the
// last byte of a span — to the corresponding offset in the original
// source. This is not simply toSrc(normOffset): that would give the
// original position of whatever norm byte comes *next*, which, if a "\r"
// was dropped right there, overshoots past it. Mapping the last actually
// included byte (normOffset-1) and adding one keeps the span's original
// end exactly where that byte ends, with any dropped "\r" immediately
// after it correctly left out.
func (m crlfMap) toSrcEnd(normOffset int) int {
	if m.orig == nil {
		return normOffset
	}
	if normOffset <= 0 {
		return 0
	}
	if normOffset-1 >= len(m.orig) {
		return m.srcLen
	}
	return m.orig[normOffset-1] + 1
}

// yamlSpan converts a scalar token into a source byte range.
//
// The byte range comes from the token's Line and Column, not its
// Position.Offset: Offset is measured against the token's Origin, which
// includes leading trivia for some token kinds and not others, so it
// disagrees with the source by a byte or two depending on how the scalar
// was written. Line and Column consistently point at the first character
// of the value itself, quotes included — but they're computed against
// m.norm (what the parser actually saw), so the resulting offsets are
// translated through m before they mean anything in src.
//
// The computed span is verified against the token's own Origin text before
// being returned. Splicing a tag over the wrong bytes would corrupt the
// file and, for the clean filter, commit a mangled secret — so a span that
// doesn't match what the lexer saw is an error, not something to paper
// over. In CRLF mode the check is against literal with every "\n" grown
// back into "\r\n": that's a no-op for the ordinary single-line-scalar
// case (nothing to replace), and correctly accounts for a multi-line
// block scalar's internal line breaks otherwise.
func yamlSpan(src []byte, m crlfMap, tk *token.Token, path string) (Span, error) {
	literal := scalarText(tk.Origin)
	normStart := lineOffset(m.norm, tk.Position.Line) + tk.Position.Column - 1
	normEnd := normStart + len(literal)

	if normStart < 0 || normEnd > len(m.norm) {
		return Span{}, fmt.Errorf("format: %q: scalar at line %d column %d is outside the source", path, tk.Position.Line, tk.Position.Column)
	}

	start, end := m.toSrc(normStart), m.toSrcEnd(normEnd)
	want := literal
	if m.orig != nil {
		want = strings.ReplaceAll(literal, "\n", "\r\n")
	}
	if start < 0 || end > len(src) || end < start {
		return Span{}, fmt.Errorf("format: %q: scalar at line %d column %d is outside the source", path, tk.Position.Line, tk.Position.Column)
	}
	if got := string(src[start:end]); got != want {
		return Span{}, fmt.Errorf("format: %q: located %q at line %d column %d but the lexer read %q", path, got, tk.Position.Line, tk.Position.Column, literal)
	}

	return Span{
		Start: start,
		End:   end,
		Value: tk.Value,
		Type:  yamlType(tk),
	}, nil
}

// scalarText strips the trivia the lexer folds into a token's Origin: the
// surrounding whitespace, and any comment that follows the value on the
// same line.
func scalarText(origin string) string {
	text := strings.TrimSpace(origin)
	if hash := strings.Index(text, " #"); hash >= 0 {
		text = strings.TrimRight(text[:hash], " \t")
	}
	return text
}

// lineOffset returns the byte offset where 1-based line n starts.
func lineOffset(src []byte, n int) int {
	offset := 0
	for line := 1; line < n; line++ {
		next := bytes.IndexByte(src[offset:], '\n')
		if next < 0 {
			return len(src)
		}
		offset += next + 1
	}
	return offset
}

func yamlType(tk *token.Token) tag.Type {
	switch tk.Type {
	case token.IntegerType:
		return tag.TypeInt
	case token.FloatType:
		return tag.TypeFloat
	case token.BoolType:
		return tag.TypeBool
	default:
		return tag.TypeStr
	}
}

func yamlStep(node ast.Node, step Step) (ast.Node, error) {
	if step.IsIndex() {
		seq, ok := node.(*ast.SequenceNode)
		if !ok || step.Index >= len(seq.Values) {
			return nil, ErrNotFound
		}
		return seq.Values[step.Index], nil
	}

	mapping, ok := node.(*ast.MappingNode)
	if !ok {
		if single, isPair := node.(*ast.MappingValueNode); isPair {
			mapping = &ast.MappingNode{Values: []*ast.MappingValueNode{single}}
		} else {
			return nil, ErrNotFound
		}
	}
	for _, pair := range mapping.Values {
		if pair.Key.GetToken().Value == step.Key {
			return pair.Value, nil
		}
	}
	return nil, ErrNotFound
}

// Render writes value as YAML source text.
//
// Known limitation (spec 05 AC-5.6): strings are always emitted
// double-quoted, whatever style they had before encryption. The original
// style isn't recorded in the tag, and double quotes are the one style
// that is safe in both block and flow context — an ENC[...] tag contains
// "[", "]" and "," and would otherwise terminate a flow sequence early.
// Since the ciphertext is derived from the value and not its styling, a
// re-quoted scalar still produces an identical blob and so no git diff.
func (yamlHandler) Render(value string, t tag.Type) string {
	switch t {
	case tag.TypeInt, tag.TypeFloat, tag.TypeBool:
		return value
	default:
		return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value) + `"`
	}
}

// pathPrefix renders the first n steps of a path for error messages.
func pathPrefix(steps []Step, n int) []string {
	var parts []string
	for _, step := range steps[:n] {
		switch {
		case step.IsIndex():
			parts = append(parts, fmt.Sprintf("[%d]", step.Index))
		case len(parts) == 0:
			parts = append(parts, step.Key)
		default:
			parts = append(parts, "."+step.Key)
		}
	}
	return parts
}

// Leaves walks the document collecting every scalar and the path that
// selects it.
func (yamlHandler) Leaves(src []byte) ([]Leaf, error) {
	file, err := parser.ParseBytes(src, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("format: parsing YAML: %w", err)
	}
	if len(file.Docs) == 0 || file.Docs[0].Body == nil {
		return nil, nil
	}

	var leaves []Leaf
	var walk func(node ast.Node, path string)
	walk = func(node ast.Node, path string) {
		switch n := node.(type) {
		case *ast.MappingNode:
			for _, pair := range n.Values {
				walk(pair.Value, joinPath(path, pair.Key.GetToken().Value))
			}
		case *ast.MappingValueNode:
			walk(n.Value, joinPath(path, n.Key.GetToken().Value))
		case *ast.SequenceNode:
			for i, item := range n.Values {
				walk(item, indexPath(path, i))
			}
		case ast.ScalarNode:
			// A scalar at the document root has no path to address it by.
			if path != "" {
				tk := n.GetToken()
				leaves = append(leaves, Leaf{Path: path, Value: tk.Value, Type: yamlType(tk)})
			}
		}
	}
	walk(file.Docs[0].Body, "")
	return leaves, nil
}
