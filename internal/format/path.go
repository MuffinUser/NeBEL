// Package format locates scalar values inside structured files so a single
// value can be replaced in place, leaving every other byte untouched.
//
// Handlers never re-serialize the document. They parse only far enough to
// find the byte span the target scalar occupies, and the caller splices a
// replacement into the original bytes. Re-serializing would satisfy the
// letter of "replace this value" while quietly rewriting comments, quoting
// and indentation elsewhere in the file (spec 05 AC-5.1) — and would show
// up as spurious git diffs on lines nobody edited.
package format

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrBadPath is returned when a configured path is not valid dot notation.
var ErrBadPath = errors.New("format: invalid value path")

// Step is one component of a dot-notation path: either a mapping key or a
// sequence index.
type Step struct {
	// Key is the mapping key, when Index is negative.
	Key string

	// Index is the sequence index, or -1 when this step is a Key.
	Index int
}

// IsIndex reports whether this step selects a sequence element.
func (s Step) IsIndex() bool { return s.Index >= 0 }

// ParsePath splits dot notation into steps: "api.keys[0]" becomes the key
// "api", the key "keys", then index 0.
//
// A dot inside a key cannot be escaped. That is a deliberate limitation:
// the alternative is an escaping scheme users have to learn, for keys that
// are rare in the config formats this tool targets. Line-based formats
// (.env, .properties), where dotted keys are common, match the whole key
// literally instead and never call this.
func ParsePath(path string) ([]Step, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: path is empty", ErrBadPath)
	}

	var steps []Step
	for _, segment := range strings.Split(path, ".") {
		name, brackets, indexed := strings.Cut(segment, "[")
		if name == "" {
			return nil, fmt.Errorf("%w: %q has an empty key", ErrBadPath, path)
		}
		steps = append(steps, Step{Key: name, Index: -1})

		if indexed && brackets == "" {
			return nil, fmt.Errorf("%w: %q has an unclosed \"[\"", ErrBadPath, path)
		}
		// Everything after the first "[" is a run of "[n]" indices.
		for brackets != "" {
			digits, rest, closed := strings.Cut(brackets, "]")
			if !closed {
				return nil, fmt.Errorf("%w: %q has an unclosed \"[\"", ErrBadPath, path)
			}
			index, err := strconv.Atoi(digits)
			if err != nil || index < 0 {
				return nil, fmt.Errorf("%w: %q has a non-numeric index %q", ErrBadPath, path, digits)
			}
			steps = append(steps, Step{Index: index})

			if rest != "" && !strings.HasPrefix(rest, "[") {
				return nil, fmt.Errorf("%w: %q has trailing text %q after an index", ErrBadPath, path, rest)
			}
			brackets = strings.TrimPrefix(rest, "[")
		}
	}
	return steps, nil
}
