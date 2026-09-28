// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

// Package tag encodes and decodes the inline ENC[...] marker used to store
// an encrypted value in place.
//
// Two forms share one parser:
//
//	ENC[AES256_SIV,key:<version>,data:<base64>]            whole file (spec 06)
//	ENC[AES256_SIV,key:<version>,data:<base64>,type:str]   one value (spec 03)
//
// key records which project key version (spec 04, spec 11) produced the
// ciphertext, so smudge can select the matching key from the local keyring
// regardless of which version is current. The type field records the
// original scalar type so smudge can restore `port: 5432` as an integer
// rather than the string "5432". A whole-file blob has no native scalar
// type, so it carries no type field — and must keep parsing without one,
// since that is the form already committed in every repository created
// before per-value mode existed.
//
// key is mandatory (AC-3.6): this is a breaking format change from the
// pre-rotation tag (no key field at all), landing alongside spec 11.
// There is no in-tool migration: the config's own canary is checked
// before any command (init, rotate, clean, smudge) runs, so a pre-rotation
// canary fails that check before `git add --renormalize` gets a chance to
// run. See README.md's "Upgrading from a pre-rotation repository" for the
// fix — two hand-edits to .nebel.yaml, then a renormalize; not per-blob
// surgery, since renormalize re-cleans from whatever the working tree
// already holds (plaintext, for an actively-used clone), not from the
// legacy ciphertext.
package tag

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// AlgoAES256SIV is the only algorithm identifier this build understands.
const AlgoAES256SIV = "AES256_SIV"

// Type is the native type of an encrypted scalar, recorded so decryption
// can restore it. TypeNone marks a whole-file tag, which has none.
type Type string

const (
	TypeNone  Type = ""
	TypeStr   Type = "str"
	TypeInt   Type = "int"
	TypeFloat Type = "float"
	TypeBool  Type = "bool"
)

// Valid reports whether t is a scalar type this build can restore.
func (t Type) Valid() bool {
	switch t {
	case TypeStr, TypeInt, TypeFloat, TypeBool:
		return true
	}
	return false
}

// Tag is a parsed ENC[...] marker.
type Tag struct {
	// Ciphertext is the raw sealed bytes from the data field.
	Ciphertext []byte

	// Version is the key version (spec 04, spec 11) that produced
	// Ciphertext, as declared by the tag's own key field.
	Version int

	// Type is the original scalar type, or TypeNone for a whole-file tag.
	Type Type
}

const (
	prefix = "ENC["
	suffix = "]"
)

var (
	// ErrMalformed is returned when a string starting with "ENC[" does not
	// parse as a well-formed tag.
	ErrMalformed = errors.New("tag: malformed ENC[...] tag")

	// ErrUnsupportedAlgo is returned when a well-formed tag names an
	// algorithm this build does not implement.
	ErrUnsupportedAlgo = errors.New("tag: unsupported algorithm")

	// ErrUnsupportedType is returned when a tag names a scalar type this
	// build cannot restore.
	ErrUnsupportedType = errors.New("tag: unsupported value type")
)

// IsEncrypted reports whether raw is already tagged as an encrypted value.
//
// Detection is prefix-only by design: it must be cheap enough to run on
// every value the clean/smudge filter sees, and it must agree with Decode on
// what counts as "this is ours" without needing a full parse first.
func IsEncrypted(raw []byte) bool {
	return strings.HasPrefix(string(raw), prefix)
}

// Encode wraps ciphertext produced for a whole file into an ENC[...] tag,
// recording version as the key version that produced it (spec 11).
//
// base64's standard alphabet is used deliberately: it contains neither ','
// nor ']', the tag's own delimiters, so Decode can always split the tag
// unambiguously regardless of ciphertext content. version's decimal digits
// are unambiguous for the same reason (AC-3.7).
func Encode(ciphertext []byte, version int) string {
	return fmt.Sprintf("%s%s,key:%d,data:%s%s", prefix, AlgoAES256SIV, version, base64.StdEncoding.EncodeToString(ciphertext), suffix)
}

// EncodeValue wraps ciphertext for a single scalar, recording the key
// version that produced it (spec 11) and the type the plaintext had so
// Decrypt can restore it (spec 03 AC-3.1, AC-3.2).
func EncodeValue(ciphertext []byte, version int, t Type) string {
	return fmt.Sprintf("%s%s,key:%d,data:%s,type:%s%s", prefix, AlgoAES256SIV, version, base64.StdEncoding.EncodeToString(ciphertext), t, suffix)
}

// Decode parses a tag and returns just the ciphertext, ignoring its
// declared version and any type field. Used by callers that already know
// (or don't need) which key version produced the ciphertext, such as the
// canary — which is always decrypted with the version's own key.
func Decode(raw string) ([]byte, error) {
	parsed, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	return parsed.Ciphertext, nil
}

// Parse parses either tag form. It never panics: malformed input,
// unsupported algorithms, and unsupported types are reported as errors.
//
// Parsing never needs to know which version is "current" (AC-3.9) — the
// tag names its own version explicitly, and the caller (spec 06) is
// responsible for finding the matching key in the local keyring.
func Parse(raw string) (Tag, error) {
	if !strings.HasPrefix(raw, prefix) || !strings.HasSuffix(raw, suffix) {
		return Tag{}, fmt.Errorf("%w: missing %q...%q delimiters", ErrMalformed, prefix, suffix)
	}
	inner := raw[len(prefix) : len(raw)-len(suffix)]

	// None of the field values below can themselves contain "," (AC-3.7:
	// base64's alphabet excludes it, and key/type are restricted
	// vocabularies), so splitting the whole tag body on "," is always
	// unambiguous.
	fields := strings.Split(inner, ",")
	if len(fields) < 2 || fields[0] == "" {
		return Tag{}, fmt.Errorf("%w: expected \"ALGO,key:<version>,data:<base64>\"", ErrMalformed)
	}
	algo := fields[0]
	if algo != AlgoAES256SIV {
		return Tag{}, fmt.Errorf("%w: %q", ErrUnsupportedAlgo, algo)
	}
	rest := fields[1:]

	keyField, rest := rest[0], rest[1:]
	keyValue, ok := strings.CutPrefix(keyField, "key:")
	if !ok {
		return Tag{}, fmt.Errorf("%w: expected a \"key:\" field, got %q", ErrMalformed, keyField)
	}
	version, err := strconv.Atoi(keyValue)
	if err != nil || version < 1 {
		return Tag{}, fmt.Errorf("%w: invalid key version %q", ErrMalformed, keyValue)
	}

	if len(rest) == 0 {
		return Tag{}, fmt.Errorf("%w: missing \"data:\" field", ErrMalformed)
	}
	dataField, rest := rest[0], rest[1:]
	b64, ok := strings.CutPrefix(dataField, "data:")
	if !ok {
		return Tag{}, fmt.Errorf("%w: missing \"data:\" field", ErrMalformed)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return Tag{}, fmt.Errorf("%w: invalid base64 in data field: %v", ErrMalformed, err)
	}

	parsed := Tag{Ciphertext: ciphertext, Version: version}

	// The type field is optional: its absence means a whole-file tag.
	if len(rest) > 0 {
		typeField, rest2 := rest[0], rest[1:]
		value, ok := strings.CutPrefix(typeField, "type:")
		if !ok {
			return Tag{}, fmt.Errorf("%w: expected a \"type:\" field, got %q", ErrMalformed, typeField)
		}
		if parsed.Type = Type(value); !parsed.Type.Valid() {
			return Tag{}, fmt.Errorf("%w: %q", ErrUnsupportedType, value)
		}
		rest = rest2
	}
	if len(rest) > 0 {
		return Tag{}, fmt.Errorf("%w: unexpected trailing field %q", ErrMalformed, rest[0])
	}
	return parsed, nil
}
