// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

// Package tag encodes and decodes the inline ENC[...] marker used to store
// an encrypted value in place.
//
// Three forms share one parser:
//
//	ENC[AES256_SIV,key:<version>,data:<base64>]               whole file (spec 06)
//	ENC[AES256_SIV,key:<version>,data:<base64>,type:str]      one value, legacy (spec 03)
//	ENC[AES256_SIV_TB,key:<version>,data:<base64>,type:str]   one value, type-bound (spec 03 AC-3.10)
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
// The two value forms differ in whether the type field is itself
// authenticated. AES256_SIV_TB folds it into the ciphertext's AAD (see
// internal/siv.AAD and internal/filterop's use of it), so changing
// type:str to type:bool on an unmodified ciphertext — which needs no key,
// since the type field sits next to the ciphertext as plaintext metadata,
// not inside it — fails authentication instead of silently changing how
// the decrypted value renders (audit 2026-09-29, P05). AES256_SIV plays
// that same role for a value tag only because it predates this fix: every
// tag EncodeValue produces now uses AES256_SIV_TB, but a legacy
// AES256_SIV value tag already committed before this change remains
// parseable and must keep authenticating exactly as it always did, so
// Parse still accepts it — TypeBound distinguishes the two for a caller
// deciding which AAD to reconstruct. There is no separate migration step
// beyond that: a value converges to the new form the next time anything
// re-encrypts it (an ordinary edit, or the eager re-encryption `nebel
// rotate` and `git add --renormalize` already perform for spec 11), the
// same way a value converges onto a new key version.
//
// That convergence closes P05 only for the current, committed tag —
// not for the field's history. A legacy ciphertext, once committed,
// stays a valid AES256_SIV tag forever: nothing about upgrading the
// current commit changes it, or the key version it names (spec 11
// AC-11.5 keeps every version's key registered indefinitely). An
// attacker with write access can resurrect that old blob from git
// history — or a stale branch, or another clone's reflog — with its
// type field re-flipped, and it authenticates exactly as it did the
// day it was committed, since Smudge picks the (unbound) legacy AAD
// for anything naming AES256_SIV. Reaching that ciphertext at all
// already requires the write access P05 assumes; validTypeLiteral
// (internal/filterop) additionally limits what a successful flip can
// render to a genuine literal of the new type, narrowing rather than
// closing the gap. Fully closing it would mean actively revoking the
// old key version — not merely superseding it — which spec 11's
// rotation does not do and is out of scope here.
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

// AlgoAES256SIV is the algorithm identifier for a whole-file tag, and for
// a legacy value tag produced before AlgoAES256SIVTypeBound existed (see
// Tag.TypeBound).
const AlgoAES256SIV = "AES256_SIV"

// AlgoAES256SIVTypeBound is the algorithm identifier EncodeValue now
// always produces: a value tag whose type field is bound into the
// ciphertext's AAD, so tampering with it fails authentication (spec 03
// AC-3.10, audit 2026-09-29 P05). See Tag.TypeBound.
const AlgoAES256SIVTypeBound = "AES256_SIV_TB"

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

	// TypeBound reports whether Type is itself part of what this tag's
	// ciphertext authenticates (AlgoAES256SIVTypeBound), as opposed to
	// separate, unauthenticated plaintext metadata sitting next to the
	// ciphertext (the legacy AlgoAES256SIV value form). Always false for
	// a whole-file tag, which carries no type field to bind in the first
	// place. A caller reconstructing the AAD a value's ciphertext was
	// encrypted under must include Type in it when this is true, and
	// must not when it's false — using the wrong one either way fails
	// authentication, since AAD mismatches are indistinguishable from a
	// wrong key or tampered ciphertext.
	TypeBound bool
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
//
// This makes it a safe fast-path *rejection* test (raw definitely isn't a
// tag if this is false) but not a safe basis for treating raw as
// already-encrypted plaintext to skip over: a plaintext value that merely
// starts with "ENC[" — e.g. a password containing that literal substring —
// also satisfies this check without being a well-formed tag at all (audit
// 2026-09-29, P08). A caller deciding whether something needs encrypting
// (clean's "already tagged, leave it alone" branches) must use
// LooksEncrypted instead; only a caller already committed to treating
// malformed input as corruption (smudge's AC-6.9 path) may use this bare
// prefix check as a pre-check before a full Parse.
func IsEncrypted(raw []byte) bool {
	return strings.HasPrefix(string(raw), prefix)
}

// LooksEncrypted reports whether raw is shaped like one of this package's
// ENC[...] tags: delimiters present, the first comma-separated field
// naming a recognized algorithm, a genuine "data:" field whose payload
// actually decodes as base64, and — for any other field present — a
// recognized field name with a syntactically valid value. Unlike Parse,
// the "key:" field is not required (see below), but every field that IS
// present must be well-formed; an unrecognized or malformed field, or the
// literal absence of any "data:" field at all, means raw is not a tag.
//
// This intentionally stops short of a full Parse in exactly one respect:
// a pre-rotation tag (this package's doc comment) has no "key:" field at
// all and fails Parse for that reason alone, yet is genuine,
// already-encrypted content with its own documented migration path
// (README's "Upgrading from a pre-rotation repository"), not plaintext to
// encrypt over. LooksEncrypted still recognizes it as "ours" so
// Clean/cleanValues leave it alone (AC-6.4) instead of double-wrapping it.
//
// Beyond that one deliberate exception, LooksEncrypted requires the same
// field shapes Parse does: a value merely starting with "ENC[" plus a
// recognized algorithm name, but otherwise malformed — e.g.
// "ENC[AES256_SIV,not-a-real-tag]", which has no "data:" field at all — is
// not treated as already-encrypted (audit 2026-09-30, R05). This is
// stricter than the bare prefix check IsEncrypted performs, which would
// also (wrongly) call a plaintext value that merely starts with "ENC["
// already-encrypted (audit 2026-09-29, P08).
func LooksEncrypted(raw []byte) bool {
	s := string(raw)
	if !strings.HasPrefix(s, prefix) || !strings.HasSuffix(s, suffix) {
		return false
	}
	inner := s[len(prefix) : len(s)-len(suffix)]
	fields := strings.Split(inner, ",")
	if len(fields) < 2 || fields[0] == "" {
		return false
	}
	switch fields[0] {
	case AlgoAES256SIV, AlgoAES256SIVTypeBound:
	default:
		return false
	}

	hasData := false
	for _, field := range fields[1:] {
		switch {
		case strings.HasPrefix(field, "key:"):
			version, err := strconv.Atoi(strings.TrimPrefix(field, "key:"))
			if err != nil || version < 1 {
				return false
			}
		case strings.HasPrefix(field, "data:"):
			if _, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(field, "data:")); err != nil {
				return false
			}
			hasData = true
		case strings.HasPrefix(field, "type:"):
			if !Type(strings.TrimPrefix(field, "type:")).Valid() {
				return false
			}
		default:
			return false
		}
	}
	return hasData
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
//
// Always uses AlgoAES256SIVTypeBound (spec 03 AC-3.10): every value tag
// this build produces binds its type field into the ciphertext's AAD.
// The caller must construct that AAD to match — see internal/siv.AAD and
// Tag.TypeBound's doc comment — or the ciphertext it just produced won't
// authenticate against its own tag.
func EncodeValue(ciphertext []byte, version int, t Type) string {
	return fmt.Sprintf("%s%s,key:%d,data:%s,type:%s%s", prefix, AlgoAES256SIVTypeBound, version, base64.StdEncoding.EncodeToString(ciphertext), t, suffix)
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
	var typeBound bool
	switch algo {
	case AlgoAES256SIV:
		typeBound = false
	case AlgoAES256SIVTypeBound:
		typeBound = true
	default:
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
		parsed.TypeBound = typeBound
		rest = rest2
	} else if typeBound {
		// AlgoAES256SIVTypeBound exists specifically to bind a type
		// field; a whole-file-shaped tag naming it anyway has nothing to
		// bind and is malformed, not something to quietly accept as if
		// it were the plain AlgoAES256SIV whole-file form.
		return Tag{}, fmt.Errorf("%w: %q requires a \"type:\" field", ErrMalformed, AlgoAES256SIVTypeBound)
	}
	if len(rest) > 0 {
		return Tag{}, fmt.Errorf("%w: unexpected trailing field %q", ErrMalformed, rest[0])
	}
	return parsed, nil
}
