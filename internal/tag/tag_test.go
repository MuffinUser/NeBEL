package tag

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"
)

// AC-3.1 (whole-file form): encoding produces ENC[AES256_SIV,data:<base64>].
func TestEncodeFormat(t *testing.T) {
	got := Encode([]byte("ciphertext-bytes"))
	want := "ENC[AES256_SIV,data:" + base64.StdEncoding.EncodeToString([]byte("ciphertext-bytes")) + "]"
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
		{"tagged value", "ENC[AES256_SIV,data:aGVsbG8=]", true},
		{"plaintext", "hunter2", false},
		{"empty", "", false},
		{"almost a tag", "ENC(AES256_SIV,data:aGVsbG8=)", false},
		{"tag-like substring not at start", "prefix ENC[AES256_SIV,data:aGVsbG8=]", false},
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
		encoded := Encode(ciphertext)
		got, err := Decode(encoded)
		if err != nil {
			t.Fatalf("Decode(%q): %v", encoded, err)
		}
		if !bytes.Equal(got, ciphertext) {
			t.Errorf("round-trip mismatch:\n got  = %x\n want = %x", got, ciphertext)
		}
	}
}

// AC-3.6: malformed tags are rejected with a clear error, never a panic.
func TestDecodeRejectsMalformed(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want error
	}{
		{"missing prefix", "AES256_SIV,data:aGVsbG8=]", ErrMalformed},
		{"missing suffix", "ENC[AES256_SIV,data:aGVsbG8=", ErrMalformed},
		{"empty string", "", ErrMalformed},
		{"just delimiters", "ENC[]", ErrMalformed},
		{"missing comma", "ENC[AES256_SIVdata:aGVsbG8=]", ErrMalformed},
		{"missing data field", "ENC[AES256_SIV,aGVsbG8=]", ErrMalformed},
		{"wrong field name", "ENC[AES256_SIV,payload:aGVsbG8=]", ErrMalformed},
		{"invalid base64", "ENC[AES256_SIV,data:not-valid-base64!!]", ErrMalformed},
		{"unrecognized algo", "ENC[ROT13,data:aGVsbG8=]", ErrUnsupportedAlgo},
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
// ciphertext content.
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
	raw := "ENC[FUTURE_ALGO_V2,data:" + base64.StdEncoding.EncodeToString([]byte("payload")) + "]"
	_, err := Decode(raw)
	if !errors.Is(err, ErrUnsupportedAlgo) {
		t.Errorf("Decode() error = %v, want %v", err, ErrUnsupportedAlgo)
	}
}
