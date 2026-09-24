// Package filterop implements the clean/smudge transforms git's filter
// driver invokes on stage and checkout, ties together specs 01-04.
//
// MVP scope: mode: file rules only (config.Validate already rejects mode:
// value configs, so Clean/Smudge never see one).
package filterop

import (
	"fmt"

	"github.com/MarwinMoellers/strucrypt/internal/config"
	"github.com/MarwinMoellers/strucrypt/internal/siv"
	"github.com/MarwinMoellers/strucrypt/internal/tag"
)

// Clean encrypts input if filePath matches a mode: file rule; otherwise (no
// matching rule, or the value is already encrypted) it returns input
// unchanged.
//
// filePath must be the file's path relative to the repository root — it is
// both the rule-matching key and part of the AAD binding the ciphertext to
// this location.
func Clean(cfg *config.Config, key []byte, filePath string, input []byte) ([]byte, error) {
	rule, ok := cfg.MatchRule(filePath)
	if !ok || rule.Mode != config.ModeFile {
		return input, nil
	}
	if tag.IsEncrypted(input) {
		// Already encrypted: leave it alone (AC-6.4). Re-encrypting here
		// would still be deterministic and produce the same bytes, but
		// skipping it avoids ever decrypting-then-recrypting content this
		// process doesn't need to touch.
		return input, nil
	}

	ciphertext, err := siv.Encrypt(key, input, siv.AAD(siv.ModeFile, filePath, ""))
	if err != nil {
		return nil, fmt.Errorf("filterop: clean %s: %w", filePath, err)
	}
	return []byte(tag.Encode(ciphertext)), nil
}

// Smudge reverses Clean: it decrypts input if filePath matches a mode: file
// rule and input is a well-formed ENC[...] tag. A value that isn't tagged
// at all passes through unchanged (AC-6.7 — e.g. a file not yet migrated).
// A value that *is* tagged but fails to parse or authenticate is a genuine
// corruption or tampering signal and is reported as an error rather than
// smudged into a wrong-but-plausible plaintext (AC-6.9).
func Smudge(cfg *config.Config, key []byte, filePath string, input []byte) ([]byte, error) {
	rule, ok := cfg.MatchRule(filePath)
	if !ok || rule.Mode != config.ModeFile {
		return input, nil
	}
	if !tag.IsEncrypted(input) {
		return input, nil
	}

	ciphertext, err := tag.Decode(string(input))
	if err != nil {
		return nil, fmt.Errorf("filterop: smudge %s: malformed ciphertext tag: %w", filePath, err)
	}
	plaintext, err := siv.Decrypt(key, ciphertext, siv.AAD(siv.ModeFile, filePath, ""))
	if err != nil {
		return nil, fmt.Errorf("filterop: smudge %s: %w", filePath, err)
	}
	return plaintext, nil
}
