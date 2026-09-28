// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

// Package filterop implements the clean/smudge transforms git's filter
// driver invokes on stage and checkout, tying together specs 01-05.
//
// Two rule modes are handled: mode: file seals the whole file as one blob,
// mode: value replaces only the configured scalars and leaves the rest of
// the document readable and diffable in git.
package filterop

import (
	"errors"
	"fmt"

	"github.com/MuffinUser/nebel/internal/config"
	"github.com/MuffinUser/nebel/internal/format"
	"github.com/MuffinUser/nebel/internal/siv"
	"github.com/MuffinUser/nebel/internal/tag"
)

// Keyring maps a key version to the derived key registered for it on this
// machine (internal/localkey). clean always looks up the config's current
// version (AC-6.12); smudge looks up whatever version a value's own tag
// names (AC-6.13), so a file whose fields span several versions decrypts
// correctly as long as the keyring holds all of them.
type Keyring map[int][]byte

// ErrKeyVersionMissing is returned when an operation needs a key version
// this machine's keyring does not hold.
var ErrKeyVersionMissing = errors.New("filterop: key version not registered locally")

// Clean encrypts input if filePath matches a mode: file rule; otherwise (no
// matching rule, or the value is already encrypted) it returns input
// unchanged.
//
// filePath must be the file's path relative to the repository root — it is
// both the rule-matching key and part of the AAD binding the ciphertext to
// this location.
//
// clean always encrypts under the config's current key version (AC-6.12),
// regardless of what version the value previously carried. `nebel rotate`
// (spec 11) relies on this to eagerly re-encrypt everything it can onto
// the version it just minted; anything it can't reach (this process
// never decrypted it, so it's still tagged rather than plaintext here)
// converges the same way the next time it's naturally edited.
func Clean(cfg *config.Config, keyring Keyring, filePath string, input []byte) ([]byte, error) {
	rule, ok := cfg.MatchRule(filePath)
	if !ok {
		return input, nil
	}
	version := cfg.CurrentVersion()
	key, ok := keyring[version]
	if !ok {
		return nil, fmt.Errorf("%w: current version %d — run `nebel init`", ErrKeyVersionMissing, version)
	}
	if rule.Mode == config.ModeValue {
		return cleanValues(rule, version, key, filePath, input)
	}
	if tag.IsEncrypted(input) {
		// Already encrypted: leave it alone (AC-6.4). Re-encrypting here
		// would still be deterministic and produce the same bytes, but
		// skipping it avoids ever decrypting-then-recrypting content this
		// process doesn't need to touch. It's also the safety net for a
		// value this clone can't decrypt because its key version is
		// missing locally: it stays as-is rather than getting
		// double-wrapped.
		return input, nil
	}

	ciphertext, err := siv.Encrypt(key, input, siv.AAD(siv.ModeFile, filePath, ""))
	if err != nil {
		return nil, fmt.Errorf("filterop: clean %s: %w", filePath, err)
	}
	return []byte(tag.Encode(ciphertext, version)), nil
}

// Smudge reverses Clean: it decrypts input if filePath matches a mode: file
// rule and input is a well-formed ENC[...] tag. A value that isn't tagged
// at all passes through unchanged (AC-6.7 — e.g. a file not yet migrated).
// A value that *is* tagged but fails to parse or authenticate is a genuine
// corruption or tampering signal and is reported as an error rather than
// smudged into a wrong-but-plausible plaintext (AC-6.9).
//
// Unlike Clean, Smudge selects its key by the value's own tag-declared
// version (AC-6.13), not the config's current version — a value tagged
// with a version the keyring doesn't hold fails clearly (AC-6.11) rather
// than passing through or guessing.
func Smudge(cfg *config.Config, keyring Keyring, filePath string, input []byte) ([]byte, error) {
	rule, ok := cfg.MatchRule(filePath)
	if !ok {
		return input, nil
	}
	if rule.Mode == config.ModeValue {
		return smudgeValues(rule, keyring, filePath, input)
	}
	if !tag.IsEncrypted(input) {
		return input, nil
	}

	parsed, err := tag.Parse(string(input))
	if err != nil {
		return nil, fmt.Errorf("filterop: smudge %s: malformed ciphertext tag: %w", filePath, err)
	}
	key, ok := keyring[parsed.Version]
	if !ok {
		return nil, fmt.Errorf("%w: needs key version %d — run `nebel init --version %d`", ErrKeyVersionMissing, parsed.Version, parsed.Version)
	}
	plaintext, err := siv.Decrypt(key, parsed.Ciphertext, siv.AAD(siv.ModeFile, filePath, ""))
	if err != nil {
		return nil, fmt.Errorf("filterop: smudge %s: %w", filePath, err)
	}
	return plaintext, nil
}

// cleanValues encrypts each configured scalar in place (spec 06 AC-6.2).
//
// A field that is already tagged is left alone, so a partially encrypted
// file converges instead of double-encrypting (AC-6.4). A field the config
// names but the file doesn't contain is an error: skipping it silently
// would report success while committing that secret in plaintext (AC-5.2).
//
// Every field is encrypted under version (the config's current version,
// AC-6.12), regardless of what version it previously carried.
func cleanValues(rule config.Rule, version int, key []byte, filePath string, input []byte) ([]byte, error) {
	handler, err := format.For(filePath)
	if err != nil {
		return nil, fmt.Errorf("filterop: clean %s: %w", filePath, err)
	}

	var edits []format.Edit
	for _, field := range rule.Encrypt {
		span, err := handler.Locate(input, field)
		if err != nil {
			return nil, fmt.Errorf("filterop: clean %s: %w", filePath, err)
		}
		if tag.IsEncrypted([]byte(span.Value)) {
			continue
		}

		ciphertext, err := siv.Encrypt(key, []byte(span.Value), siv.AAD(siv.ModeValue, filePath, field))
		if err != nil {
			return nil, fmt.Errorf("filterop: clean %s at %s: %w", filePath, field, err)
		}
		// The tag is a string whatever the scalar's original type was, so
		// it is rendered as one; the type travels inside the tag.
		edits = append(edits, format.Edit{
			Span: span,
			Text: handler.Render(tag.EncodeValue(ciphertext, version, span.Type), tag.TypeStr),
		})
	}
	return splice(input, edits, "clean", filePath)
}

// smudgeValues reverses cleanValues, restoring each scalar's original type
// from its tag. An untagged field passes through unchanged (AC-6.7); a
// tagged one that fails to parse or authenticate is reported rather than
// written out as wrong-but-plausible plaintext (AC-6.9). Each field selects
// its key by its own tag-declared version (AC-6.13), not the config's
// current version.
func smudgeValues(rule config.Rule, keyring Keyring, filePath string, input []byte) ([]byte, error) {
	handler, err := format.For(filePath)
	if err != nil {
		return nil, fmt.Errorf("filterop: smudge %s: %w", filePath, err)
	}

	var edits []format.Edit
	for _, field := range rule.Encrypt {
		span, err := handler.Locate(input, field)
		if err != nil {
			return nil, fmt.Errorf("filterop: smudge %s: %w", filePath, err)
		}
		if !tag.IsEncrypted([]byte(span.Value)) {
			continue
		}

		parsed, err := tag.Parse(span.Value)
		if err != nil {
			return nil, fmt.Errorf("filterop: smudge %s at %s: %w", filePath, field, err)
		}
		if parsed.Type == tag.TypeNone {
			// A whole-file blob sitting in a value slot: restoring it
			// would guess at a type the tag never recorded.
			return nil, fmt.Errorf("filterop: smudge %s at %s: value tag has no type field", filePath, field)
		}
		key, ok := keyring[parsed.Version]
		if !ok {
			return nil, fmt.Errorf("%w: %s at %s needs key version %d — run `nebel init --version %d`", ErrKeyVersionMissing, filePath, field, parsed.Version, parsed.Version)
		}

		plaintext, err := siv.Decrypt(key, parsed.Ciphertext, siv.AAD(siv.ModeValue, filePath, field))
		if err != nil {
			return nil, fmt.Errorf("filterop: smudge %s at %s: %w", filePath, field, err)
		}
		edits = append(edits, format.Edit{Span: span, Text: handler.Render(string(plaintext), parsed.Type)})
	}
	return splice(input, edits, "smudge", filePath)
}

func splice(input []byte, edits []format.Edit, op, filePath string) ([]byte, error) {
	out, err := format.Splice(input, edits)
	if err != nil {
		return nil, fmt.Errorf("filterop: %s %s: %w", op, filePath, err)
	}
	return out, nil
}
