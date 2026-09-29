// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package format

import (
	"bytes"
	"errors"
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
func (h yamlHandler) Locate(src []byte, path string) (Span, error) {
	steps, err := ParsePath(path)
	if err != nil {
		return Span{}, err
	}
	if err := checkUnambiguous(h, src, path); err != nil {
		return Span{}, err
	}

	m := newCRLFMap(src)

	file, err := parser.ParseBytes(m.norm, parser.ParseComments)
	if err != nil {
		return Span{}, fmt.Errorf("format: parsing YAML: %w", err)
	}
	if err := rejectMultiDocument(file); err != nil {
		return Span{}, err
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

	if _, isBlock := node.(*ast.LiteralNode); isBlock {
		return Span{}, fmt.Errorf("%w: %q", ErrBlockScalarUnsupported, path)
	}
	scalar, ok := node.(ast.ScalarNode)
	if !ok {
		return Span{}, fmt.Errorf("%w: %q is a %s", ErrNotScalar, path, node.Type())
	}
	return yamlSpan(src, m, scalar.GetToken(), path)
}

// ErrBlockScalarUnsupported is returned when a configured path resolves to
// a literal (|) or folded (>) block scalar.
//
// *ast.LiteralNode (go-yaml's AST type for both styles) wraps two tokens:
// a header token holding just the "|" or ">" indicator itself, and a
// separate Value token holding the actual decoded multi-line text.
// *ast.LiteralNode satisfies ast.ScalarNode, and its GetToken() returns
// only the header — so treating it as an ordinary scalar, as this handler
// did before this check existed, would locate and splice a ciphertext tag
// over the single header character, corrupting the document instead of
// protecting the secret underneath it. This was found while fixing P02,
// not part of the audit that motivated it; there is no format-side
// handling for these styles to fall back on, so refusing them outright is
// the safe behavior until they're properly supported.
var ErrBlockScalarUnsupported = errors.New("format: literal (|) and folded (>) block scalars are not supported as mode: value fields")

// ErrMultiDocumentUnsupported is returned when a YAML source contains more
// than one "---"-separated document.
//
// Locate and Leaves both used to operate on file.Docs[0] alone, silently
// ignoring every document after the first. A configured path matching a
// leaf only in a later document was never located, never encrypted, and
// never even reported as missing (audit 2026-09-29, P11) — full plaintext
// exposure with no error at all. Extending path resolution across
// documents raises its own unresolved ambiguity (the same path present in
// two documents: which one does a single Encrypt entry protect, and which
// does smudge restore into?), so this codebase refuses multi-document YAML
// outright for mode: value rules rather than guess.
var ErrMultiDocumentUnsupported = errors.New("format: multi-document YAML (\"---\"-separated) is not supported for mode: value fields")

// rejectMultiDocument reports ErrMultiDocumentUnsupported if file has more
// than one document, so Locate and Leaves fail loudly instead of silently
// looking only at file.Docs[0].
func rejectMultiDocument(file *ast.File) error {
	if len(file.Docs) > 1 {
		return fmt.Errorf("%w: found %d documents", ErrMultiDocumentUnsupported, len(file.Docs))
	}
	return nil
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
// surrounding whitespace, and — for a plain (unquoted) scalar only — any
// comment that follows the value on the same line.
//
// A quoted scalar's Origin is, verified empirically against goccy/go-yaml,
// always exactly the quoted literal verbatim (opening quote through
// closing quote), with no trailing trivia of any kind ever folded in —
// not a following comment, not trailing whitespace, regardless of what
// follows it in the source. Searching it for " #" would instead find one
// *inside* the quotes, wrongly truncating a value like `"abc # geheim"`
// to `"abc` and leaving the rest (`# geheim"`) as literal plaintext next
// to the encrypted tag (audit 2026-09-29, P02) — so a quoted scalar's
// trimmed Origin is returned as-is, unsearched.
//
// A plain scalar's Origin can never legitimately contain " #" as its own
// content in the first place: the YAML lexer itself treats " #" as the
// start of a comment and stops accumulating a plain scalar's Origin right
// there, whatever the author intended. The search below is therefore a
// no-op in practice for a well-formed plain scalar token; it is kept as
// the one non-quoted path through this function, rather than special-
// cased away, so a lexer that ever did fold trailing trivia in for some
// plain-scalar edge case would still be handled instead of silently
// trusted.
func scalarText(origin string) string {
	text := strings.TrimSpace(origin)
	if text == "" {
		return text
	}
	if text[0] == '"' || text[0] == '\'' {
		return text
	}
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
func (yamlHandler) Render(value string, t tag.Type) (string, error) {
	switch t {
	case tag.TypeInt, tag.TypeFloat, tag.TypeBool:
		return value, nil
	default:
		escaped, err := yamlEscapeDoubleQuoted(value)
		if err != nil {
			return "", err
		}
		return `"` + escaped + `"`, nil
	}
}

// ErrControlCharacterUnsupported is returned by Render when a decrypted
// string contains a control character this build cannot safely render
// into a YAML double-quoted scalar — see yamlEscapeDoubleQuoted.
var ErrControlCharacterUnsupported = errors.New("format: value contains a control character that cannot be safely rendered as YAML")

// yamlEscapeDoubleQuoted escapes value for a YAML double-quoted scalar.
//
// Beyond the backslash and closing quote a plain strings.Replacer used to
// handle alone, every control character must be escaped too: an
// unescaped, literal newline (or CR, tab, ...) spliced directly into a
// double-quoted scalar is not a syntax error — it parses back out under
// YAML's own line-folding rules, which silently turn a bare "\n" into a
// space on the next read (audit 2026-09-29, P10). Left unescaped, a
// decrypted value containing a real control character would change on
// every future decrypt/encrypt round trip that touches its field, without
// any error ever being raised.
//
// YAML defines single-character escapes for some, but not all, C0
// control codes: \0 \a \b \t \n \v \f \r \e cover x00, x07-x0D, and x1B.
// The natural fallback for the rest would be a "\xHH" hex escape — except
// that, verified empirically against the actual goccy/go-yaml parser this
// codebase uses, its lexer's Origin tracking is broken for *any* \x, \u,
// or \U escape (confirmed independent of the escaped value: even a
// harmless "\x41" comes back with a truncated Origin). yamlSpan's own
// consistency check would catch the resulting corruption and error out —
// but only the *next* time this exact field is cleaned, since Render's
// output here is spliced straight into the working tree without being
// re-parsed. That would make encrypting a value containing one of these
// rarer control characters appear to succeed, only to permanently jam on
// the next `git add`/`clean` of the same field. Refusing it immediately,
// here, is the same "fail loudly rather than corrupt" choice this
// package already makes for block scalars (ErrBlockScalarUnsupported).
func yamlEscapeDoubleQuoted(value string) (string, error) {
	var b strings.Builder
	for _, r := range value {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case 0x00:
			b.WriteString(`\0`)
		case 0x07:
			b.WriteString(`\a`)
		case 0x08:
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case 0x0B:
			b.WriteString(`\v`)
		case 0x0C:
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		case 0x1B:
			b.WriteString(`\e`)
		default:
			if r < 0x20 || r == 0x7f {
				return "", fmt.Errorf("%w: %U", ErrControlCharacterUnsupported, r)
			}
			b.WriteRune(r)
		}
	}
	return b.String(), nil
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
	if err := rejectMultiDocument(file); err != nil {
		return nil, err
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
		case *ast.LiteralNode:
			// A block scalar (|, >) is never offered: see
			// ErrBlockScalarUnsupported. This case must come before the
			// ast.ScalarNode one below, which *ast.LiteralNode also
			// satisfies but would report the wrong token.
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
