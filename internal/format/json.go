// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package format

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/MarwinMoellers/strucrypt/internal/tag"
)

type jsonHandler struct{}

// Locate streams the document with encoding/json's tokenizer, which
// reports byte offsets, and returns the span of the scalar at path.
//
// Streaming rather than unmarshalling is what makes byte-exactness
// possible: json.Unmarshal would discard the offsets, and re-marshalling
// would normalize key order, indentation and number formatting across the
// whole document.
func (jsonHandler) Locate(src []byte, path string) (Span, error) {
	steps, err := ParsePath(path)
	if err != nil {
		return Span{}, err
	}

	dec := json.NewDecoder(bytes.NewReader(src))
	dec.UseNumber()

	// descend consumes the value starting at the decoder's position,
	// returning the span of the scalar the remaining steps select.
	var descend func(steps []Step) (Span, error)
	descend = func(steps []Step) (Span, error) {
		before := dec.InputOffset()
		tk, err := dec.Token()
		if err != nil {
			return Span{}, fmt.Errorf("format: parsing JSON: %w", err)
		}

		if len(steps) == 0 {
			if delim, isDelim := tk.(json.Delim); isDelim {
				return Span{}, fmt.Errorf("%w: %q is a %s", ErrNotScalar, path, delimName(delim))
			}
			return jsonSpan(src, before, dec.InputOffset(), tk)
		}

		switch tk {
		case json.Delim('{'):
			return descendObject(dec, steps, descend)
		case json.Delim('['):
			return descendArray(dec, steps, descend)
		}
		return Span{}, ErrNotFound
	}

	span, err := descend(steps)
	if err != nil {
		if err == ErrNotFound {
			return Span{}, fmt.Errorf("%w: %q", ErrNotFound, path)
		}
		return Span{}, err
	}
	return span, nil
}

func descendObject(dec *json.Decoder, steps []Step, descend func([]Step) (Span, error)) (Span, error) {
	want := steps[0]
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return Span{}, fmt.Errorf("format: parsing JSON: %w", err)
		}
		if !want.IsIndex() && key == want.Key {
			return descend(steps[1:])
		}
		if err := skipValue(dec); err != nil {
			return Span{}, err
		}
	}
	return Span{}, ErrNotFound
}

func descendArray(dec *json.Decoder, steps []Step, descend func([]Step) (Span, error)) (Span, error) {
	want := steps[0]
	for i := 0; dec.More(); i++ {
		if want.IsIndex() && i == want.Index {
			return descend(steps[1:])
		}
		if err := skipValue(dec); err != nil {
			return Span{}, err
		}
	}
	return Span{}, ErrNotFound
}

// skipValue consumes one complete value, including a nested object or
// array, leaving the decoder positioned at the next one.
func skipValue(dec *json.Decoder) error {
	depth := 0
	for {
		tk, err := dec.Token()
		if err != nil {
			return fmt.Errorf("format: parsing JSON: %w", err)
		}
		switch tk {
		case json.Delim('{'), json.Delim('['):
			depth++
		case json.Delim('}'), json.Delim(']'):
			depth--
		}
		if depth == 0 {
			return nil
		}
	}
}

// jsonSpan trims what the decoder skipped before the token, so the span
// covers exactly the literal — including its quotes, for strings.
//
// InputOffset() before reading a value points just past the *previous*
// token, so the skipped run holds the "key":-style colon or the comma
// separating array elements, as well as any whitespace. None of those
// characters can begin a JSON value, so trimming them is unambiguous.
func jsonSpan(src []byte, before, after int64, tk json.Token) (Span, error) {
	if before < 0 || after > int64(len(src)) || before > after {
		return Span{}, fmt.Errorf("format: token offsets [%d:%d) are outside the source", before, after)
	}
	raw := string(src[before:after])
	lead := len(raw) - len(strings.TrimLeft(raw, " \t\n\r:,"))

	span := Span{Start: int(before) + lead, End: int(after)}
	switch v := tk.(type) {
	case string:
		span.Value, span.Type = v, tag.TypeStr
	case bool:
		span.Value, span.Type = fmt.Sprintf("%t", v), tag.TypeBool
	case json.Number:
		span.Value = v.String()
		span.Type = tag.TypeInt
		if strings.ContainsAny(v.String(), ".eE") {
			span.Type = tag.TypeFloat
		}
	case nil:
		return Span{}, fmt.Errorf("%w: null has no value to encrypt", ErrNotScalar)
	default:
		return Span{}, fmt.Errorf("%w: unexpected token %v", ErrNotScalar, tk)
	}
	return span, nil
}

// Render writes value as JSON source text. Unlike YAML there is no style
// to lose: JSON strings are always double-quoted, so a decrypted value is
// byte-identical to how it would have been written by hand.
func (jsonHandler) Render(value string, t tag.Type) string {
	switch t {
	case tag.TypeInt, tag.TypeFloat, tag.TypeBool:
		return value
	default:
		encoded, err := json.Marshal(value)
		if err != nil {
			// json.Marshal of a string fails only on invalid UTF-8, which
			// a decrypted JSON string cannot contain.
			return `""`
		}
		return string(encoded)
	}
}

func delimName(d json.Delim) string {
	if d == '{' {
		return "object"
	}
	return "array"
}

// Leaves walks the document collecting every scalar and the path that
// selects it.
func (jsonHandler) Leaves(src []byte) ([]Leaf, error) {
	dec := json.NewDecoder(bytes.NewReader(src))
	dec.UseNumber()

	var leaves []Leaf
	var walk func(path string) error
	walk = func(path string) error {
		before := dec.InputOffset()
		tk, err := dec.Token()
		if err != nil {
			return fmt.Errorf("format: parsing JSON: %w", err)
		}

		switch tk {
		case json.Delim('{'):
			for dec.More() {
				key, err := dec.Token()
				if err != nil {
					return fmt.Errorf("format: parsing JSON: %w", err)
				}
				name, ok := key.(string)
				if !ok {
					return fmt.Errorf("format: parsing JSON: object key is not a string")
				}
				if err := walk(joinPath(path, name)); err != nil {
					return err
				}
			}
			_, err := dec.Token() // closing brace
			return err
		case json.Delim('['):
			for i := 0; dec.More(); i++ {
				if err := walk(indexPath(path, i)); err != nil {
					return err
				}
			}
			_, err := dec.Token() // closing bracket
			return err
		}

		if path == "" {
			return nil // a bare scalar document has no addressable path
		}
		span, err := jsonSpan(src, before, dec.InputOffset(), tk)
		if err != nil {
			// null and other unencryptable scalars are simply not offered.
			return nil
		}
		leaves = append(leaves, Leaf{Path: path, Value: span.Value, Type: span.Type})
		return nil
	}

	if err := walk(""); err != nil {
		return nil, err
	}
	return leaves, nil
}
