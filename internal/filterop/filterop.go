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
	"fmt"

	"github.com/MarwinMoellers/nebel/internal/config"
	"github.com/MarwinMoellers/nebel/internal/format"
	"github.com/MarwinMoellers/nebel/internal/siv"
	"github.com/MarwinMoellers/nebel/internal/tag"
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
	if !ok {
		return input, nil
	}
	if rule.Mode == config.ModeValue {
		return cleanValues(rule, key, filePath, input)
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
	if !ok {
		return input, nil
	}
	if rule.Mode == config.ModeValue {
		return smudgeValues(rule, key, filePath, input)
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

// cleanValues encrypts each configured scalar in place (spec 06 AC-6.2).
//
// A field that is already tagged is left alone, so a partially encrypted
// file converges instead of double-encrypting (AC-6.4). A field the config
// names but the file doesn't contain is an error: skipping it silently
// would report success while committing that secret in plaintext (AC-5.2).
func cleanValues(rule config.Rule, key []byte, filePath string, input []byte) ([]byte, error) {
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
			Text: handler.Render(tag.EncodeValue(ciphertext, span.Type), tag.TypeStr),
		})
	}
	return splice(input, edits, "clean", filePath)
}

// smudgeValues reverses cleanValues, restoring each scalar's original type
// from its tag. An untagged field passes through unchanged (AC-6.7); a
// tagged one that fails to parse or authenticate is reported rather than
// written out as wrong-but-plausible plaintext (AC-6.9).
func smudgeValues(rule config.Rule, key []byte, filePath string, input []byte) ([]byte, error) {
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
