// Package tag encodes and decodes the inline ENC[...] marker used to store
// an encrypted value in place.
//
// MVP scope: only the whole-file form, ENC[AES256_SIV,data:<base64>] — no
// type field, since a whole-file blob has no native scalar type to
// preserve. Per-value encoding (spec 03's type-preserving form) is deferred.
package tag

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// AlgoAES256SIV is the only algorithm identifier this build understands.
const AlgoAES256SIV = "AES256_SIV"

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
)

// IsEncrypted reports whether raw is already tagged as an encrypted value.
//
// Detection is prefix-only by design: it must be cheap enough to run on
// every value the clean/smudge filter sees, and it must agree with Decode on
// what counts as "this is ours" without needing a full parse first.
func IsEncrypted(raw []byte) bool {
	return strings.HasPrefix(string(raw), prefix)
}

// Encode wraps ciphertext produced for a whole file into an ENC[...] tag.
//
// base64's standard alphabet is used deliberately: it contains neither ','
// nor ']', the tag's own delimiters, so Decode can always split the tag
// unambiguously regardless of ciphertext content.
func Encode(ciphertext []byte) string {
	return fmt.Sprintf("%s%s,data:%s%s", prefix, AlgoAES256SIV, base64.StdEncoding.EncodeToString(ciphertext), suffix)
}

// Decode parses a whole-file ENC[...] tag and returns the raw ciphertext.
// It never panics: malformed input and unsupported algorithms are reported
// as errors.
func Decode(raw string) ([]byte, error) {
	if !strings.HasPrefix(raw, prefix) || !strings.HasSuffix(raw, suffix) {
		return nil, fmt.Errorf("%w: missing %q...%q delimiters", ErrMalformed, prefix, suffix)
	}
	inner := raw[len(prefix) : len(raw)-len(suffix)]

	algo, dataField, ok := strings.Cut(inner, ",")
	if !ok {
		return nil, fmt.Errorf("%w: expected \"ALGO,data:<base64>\"", ErrMalformed)
	}
	if algo != AlgoAES256SIV {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedAlgo, algo)
	}

	b64, ok := strings.CutPrefix(dataField, "data:")
	if !ok {
		return nil, fmt.Errorf("%w: missing \"data:\" field", ErrMalformed)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid base64 in data field: %v", ErrMalformed, err)
	}
	return ciphertext, nil
}
