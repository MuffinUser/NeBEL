// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package tag

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// AC-3.1 (whole-file form): encoding produces ENC[AES256_SIV,key:V,data:<base64>].
func TestEncodeFormat(t *testing.T) {
	got := Encode([]byte("ciphertext-bytes"), 3)
	want := "ENC[AES256_SIV,key:3,data:" + base64.StdEncoding.EncodeToString([]byte("ciphertext-bytes")) + "]"
	if got != want {
		t.Errorf("Encode() = %q, want %q", got, want)
	}
}

// AC-3.3: detection is a pure "ENC[" prefix check.
func TestIsEncrypted(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want bool
	}{
		{"tagged value", "ENC[AES256_SIV,key:1,data:aGVsbG8=]", true},
		{"plaintext", "hunter2", false},
		{"empty", "", false},
		{"almost a tag", "ENC(AES256_SIV,key:1,data:aGVsbG8=)", false},
		{"tag-like substring not at start", "prefix ENC[AES256_SIV,key:1,data:aGVsbG8=]", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsEncrypted([]byte(tt.raw)); got != tt.want {
				t.Errorf("IsEncrypted(%q) = %v, want %v", tt.raw, got, tt.want)
			}
		})
	}
}

// AC-3.4: a well-formed tag decodes back to the original ciphertext bytes.
func TestEncodeDecodeRoundTrip(t *testing.T) {
	tests := [][]byte{
		{},
		[]byte("short"),
		bytes.Repeat([]byte{0xFF, 0x00, 0x7E}, 100),
	}
	for _, ciphertext := range tests {
		encoded := Encode(ciphertext, 1)
		got, err := Decode(encoded)
		if err != nil {
			t.Fatalf("Decode(%q): %v", encoded, err)
		}
		if !bytes.Equal(got, ciphertext) {
			t.Errorf("round-trip mismatch:\n got  = %x\n want = %x", got, ciphertext)
		}
	}
}

// Every tag names its own key version explicitly (AC-3.9), independent of
// whichever version happens to be current.
func TestEncodeDecodeRoundTripPreservesVersion(t *testing.T) {
	for _, version := range []int{1, 2, 42} {
		encoded := Encode([]byte("ciphertext"), version)
		parsed, err := Parse(encoded)
		if err != nil {
			t.Fatalf("Parse(%q): %v", encoded, err)
		}
		if parsed.Version != version {
			t.Errorf("Version = %d, want %d", parsed.Version, version)
		}
	}
}

// AC-3.6: malformed tags are rejected with a clear error, never a panic.
// A missing or non-numeric key field is malformed (this is a breaking
// format change from the pre-rotation tag, which had no key field at all).
func TestDecodeRejectsMalformed(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want error
	}{
		{"missing prefix", "AES256_SIV,key:1,data:aGVsbG8=]", ErrMalformed},
		{"missing suffix", "ENC[AES256_SIV,key:1,data:aGVsbG8=", ErrMalformed},
		{"empty string", "", ErrMalformed},
		{"just delimiters", "ENC[]", ErrMalformed},
		{"missing comma", "ENC[AES256_SIVkey:1data:aGVsbG8=]", ErrMalformed},
		{"missing key field (pre-rotation tag)", "ENC[AES256_SIV,data:aGVsbG8=]", ErrMalformed},
		{"non-numeric key", "ENC[AES256_SIV,key:one,data:aGVsbG8=]", ErrMalformed},
		{"zero key version", "ENC[AES256_SIV,key:0,data:aGVsbG8=]", ErrMalformed},
		{"negative key version", "ENC[AES256_SIV,key:-1,data:aGVsbG8=]", ErrMalformed},
		{"missing data field", "ENC[AES256_SIV,key:1,aGVsbG8=]", ErrMalformed},
		{"wrong field name", "ENC[AES256_SIV,key:1,payload:aGVsbG8=]", ErrMalformed},
		{"invalid base64", "ENC[AES256_SIV,key:1,data:not-valid-base64!!]", ErrMalformed},
		{"unrecognized algo", "ENC[ROT13,key:1,data:aGVsbG8=]", ErrUnsupportedAlgo},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Decode(%q) panicked: %v", tt.raw, r)
				}
			}()
			_, err := Decode(tt.raw)
			if !errors.Is(err, tt.want) {
				t.Errorf("Decode(%q) error = %v, want %v", tt.raw, err, tt.want)
			}
		})
	}
}

// AC-3.7: the base64 alphabet used for data cannot contain the tag's own
// delimiter characters, so parsing is never ambiguous regardless of
// ciphertext content. key's value is decimal digits only, for the same
// reason.
func TestBase64AlphabetExcludesDelimiters(t *testing.T) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
	for _, delim := range []byte{',', ']'} {
		if bytes.IndexByte([]byte(alphabet), delim) != -1 {
			t.Errorf("base64 alphabet unexpectedly contains delimiter %q", delim)
		}
	}
}

// AC-3.8: an unsupported ALGO fails explicitly rather than being decoded
// anyway, even when the rest of the tag is well-formed.
func TestDecodeRejectsUnsupportedAlgo(t *testing.T) {
	raw := "ENC[FUTURE_ALGO_V2,key:1,data:" + base64.StdEncoding.EncodeToString([]byte("payload")) + "]"
	_, err := Decode(raw)
	if !errors.Is(err, ErrUnsupportedAlgo) {
		t.Errorf("Decode() error = %v, want %v", err, ErrUnsupportedAlgo)
	}
}

// AC-3.1: a value tag carries the scalar's original type alongside the
// ciphertext.
func TestEncodeValueRoundTrip(t *testing.T) {
	for _, typ := range []Type{TypeStr, TypeInt, TypeFloat, TypeBool} {
		t.Run(string(typ), func(t *testing.T) {
			encoded := EncodeValue([]byte("ciphertext"), 2, typ)

			parsed, err := Parse(encoded)
			if err != nil {
				t.Fatalf("Parse(%q): %v", encoded, err)
			}
			if string(parsed.Ciphertext) != "ciphertext" {
				t.Errorf("Ciphertext = %q, want %q", parsed.Ciphertext, "ciphertext")
			}
			if parsed.Version != 2 {
				t.Errorf("Version = %d, want 2", parsed.Version)
			}
			if parsed.Type != typ {
				t.Errorf("Type = %q, want %q", parsed.Type, typ)
			}
		})
	}
}

// A whole-file tag has no type field and must keep parsing without one:
// that form is already committed in every repository created before
// per-value mode existed.
func TestParseWholeFileTagHasNoType(t *testing.T) {
	parsed, err := Parse(Encode([]byte("ciphertext"), 1))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if parsed.Type != TypeNone {
		t.Errorf("Type = %q, want TypeNone", parsed.Type)
	}
	if parsed.TypeBound {
		t.Error("TypeBound = true for a whole-file tag, want false")
	}
}

// Regression test for the 2026-09-29 audit's P05: EncodeValue must always
// produce a type-bound tag (AlgoAES256SIVTypeBound), so a caller
// reconstructing the AAD for it knows to include the type — otherwise
// Type sits next to the ciphertext as unauthenticated plaintext metadata,
// changeable without the key.
func TestEncodeValueUsesTypeBoundAlgo(t *testing.T) {
	encoded := EncodeValue([]byte("ciphertext"), 1, TypeStr)
	if !strings.HasPrefix(encoded, "ENC["+AlgoAES256SIVTypeBound+",") {
		t.Errorf("EncodeValue() = %q, want it to start with \"ENC[%s,\"", encoded, AlgoAES256SIVTypeBound)
	}
	parsed, err := Parse(encoded)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !parsed.TypeBound {
		t.Error("TypeBound = false, want true")
	}
}

// A value tag from before this fix — AlgoAES256SIV, not
// AlgoAES256SIVTypeBound — must still parse: there is no in-tool
// migration, so every already-committed tag of this form must keep
// working (see the package doc comment). TypeBound must come back false
// for it, so a caller reconstructs the AAD it was actually encrypted
// under (without the type), not the new formula.
func TestParseLegacyValueTagIsNotTypeBound(t *testing.T) {
	parsed, err := Parse("ENC[AES256_SIV,key:1,data:AAAA,type:str]")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if parsed.Type != TypeStr {
		t.Errorf("Type = %q, want %q", parsed.Type, TypeStr)
	}
	if parsed.TypeBound {
		t.Error("TypeBound = true for a legacy AES256_SIV value tag, want false")
	}
}

// AlgoAES256SIVTypeBound exists to bind a type field; naming it on a
// whole-file-shaped tag (no type field) has nothing to bind and is
// malformed, not silently equivalent to plain AlgoAES256SIV.
func TestParseRejectsTypeBoundWithoutType(t *testing.T) {
	if _, err := Parse("ENC[AES256_SIV_TB,key:1,data:AAAA]"); !errors.Is(err, ErrMalformed) {
		t.Errorf("Parse() error = %v, want %v", err, ErrMalformed)
	}
}

// AC-3.8, extended to the type field: a tag naming a type this build can't
// restore is refused rather than guessed at.
func TestParseRejectsUnsupportedType(t *testing.T) {
	if _, err := Parse("ENC[AES256_SIV,key:1,data:AAAA,type:date]"); !errors.Is(err, ErrUnsupportedType) {
		t.Errorf("Parse() error = %v, want %v", err, ErrUnsupportedType)
	}
	if _, err := Parse("ENC[AES256_SIV,key:1,data:AAAA,flavour:str]"); !errors.Is(err, ErrMalformed) {
		t.Errorf("Parse() error = %v, want %v", err, ErrMalformed)
	}
}
