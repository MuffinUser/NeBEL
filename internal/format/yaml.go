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
func (yamlHandler) Locate(src []byte, path string) (Span, error) {
	steps, err := ParsePath(path)
	if err != nil {
		return Span{}, err
	}

	file, err := parser.ParseBytes(src, parser.ParseComments)
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
	return yamlSpan(src, scalar.GetToken(), path)
}

// yamlSpan converts a scalar token into a source byte range.
//
// The byte range comes from the token's Line and Column, not its
// Position.Offset: Offset is measured against the token's Origin, which
// includes leading trivia for some token kinds and not others, so it
// disagrees with the source by a byte or two depending on how the scalar
// was written. Line and Column consistently point at the first character
// of the value itself, quotes included.
//
// The computed span is verified against the token's own Origin text before
// being returned. Splicing a tag over the wrong bytes would corrupt the
// file and, for the clean filter, commit a mangled secret — so a span that
// doesn't match what the lexer saw is an error, not something to paper
// over.
func yamlSpan(src []byte, tk *token.Token, path string) (Span, error) {
	literal := scalarText(tk.Origin)
	start := lineOffset(src, tk.Position.Line) + tk.Position.Column - 1

	if start < 0 || start+len(literal) > len(src) {
		return Span{}, fmt.Errorf("format: %q: scalar at line %d column %d is outside the source", path, tk.Position.Line, tk.Position.Column)
	}
	if got := string(src[start : start+len(literal)]); got != literal {
		return Span{}, fmt.Errorf("format: %q: located %q at line %d column %d but the lexer read %q", path, got, tk.Position.Line, tk.Position.Column, literal)
	}

	return Span{
		Start: start,
		End:   start + len(literal),
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
