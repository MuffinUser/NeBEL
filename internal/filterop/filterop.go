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
//
// The current version's key is only required when something actually
// needs encrypting. A path whose content is already fully tagged (a file
// this process passed straight through as ciphertext because it never
// held the key for whatever version smudged it — spec 06 AC-6.11's
// passthrough) must stay clean-able with no key at all: git re-invokes
// clean for all sorts of routine, filter-required reasons (refreshing a
// racily-clean index entry, `git add -u`, `git status`) that have nothing
// to do with actually writing new ciphertext, and none of those may hard
// fail just because this clone hasn't caught up to a rotation yet.
func Clean(cfg *config.Config, keyring Keyring, filePath string, input []byte) ([]byte, error) {
	rule, ok := cfg.MatchRule(filePath)
	if !ok {
		return input, nil
	}
	version := cfg.CurrentVersion()
	key, haveKey := keyring[version]
	if rule.Mode == config.ModeValue {
		return cleanValues(rule, version, key, haveKey, filePath, input)
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
	if !haveKey {
		return nil, fmt.Errorf("%w: current version %d — run `nebel init`", ErrKeyVersionMissing, version)
	}

	ciphertext, err := siv.Encrypt(key, input, siv.AAD(siv.ModeFile, filePath, ""))
	if err != nil {
		return nil, fmt.Errorf("filterop: clean %s: %w", filePath, err)
	}
	return []byte(tag.Encode(ciphertext, version)), nil
}

// Skipped names one value or whole file Smudge left as ciphertext
// passthrough because the local keyring doesn't hold the version its tag
// names — routine right after a `nebel rotate` (spec 11) this clone
// hasn't caught up to yet: the version simply isn't registered locally,
// as opposed to a malformed tag or a failed decryption, both of which are
// genuine corruption signals and still hard errors (AC-6.9). Field is ""
// for a mode: file rule's whole-file tag.
type Skipped struct {
	Field   string
	Version int
}

// Smudge reverses Clean: it decrypts input if filePath matches a mode: file
// rule and input is a well-formed ENC[...] tag. A value that isn't tagged
// at all passes through unchanged (AC-6.7 — e.g. a file not yet migrated).
// A value that *is* tagged but fails to parse or authenticate is a genuine
// corruption or tampering signal and is reported as an error rather than
// smudged into a wrong-but-plausible plaintext (AC-6.9).
//
// Unlike Clean, Smudge selects its key by the value's own tag-declared
// version (AC-6.13), not the config's current version. A well-formed tag
// naming a version the keyring doesn't hold (AC-6.11) is not an error: it
// passes through unchanged, exactly like AC-6.6's empty-keyring case,
// and is reported back via the returned []Skipped so the caller can warn
// about it — this is what lets a plain `git pull` after someone else's
// rotation succeed instead of aborting the whole git operation, leaving
// the affected content as ciphertext until `nebel init` registers the
// version it needs.
func Smudge(cfg *config.Config, keyring Keyring, filePath string, input []byte) ([]byte, []Skipped, error) {
	rule, ok := cfg.MatchRule(filePath)
	if !ok {
		return input, nil, nil
	}
	if rule.Mode == config.ModeValue {
		return smudgeValues(rule, keyring, filePath, input)
	}
	if !tag.IsEncrypted(input) {
		return input, nil, nil
	}

	parsed, err := tag.Parse(string(input))
	if err != nil {
		return nil, nil, fmt.Errorf("filterop: smudge %s: malformed ciphertext tag: %w", filePath, err)
	}
	key, ok := keyring[parsed.Version]
	if !ok {
		return input, []Skipped{{Version: parsed.Version}}, nil
	}
	plaintext, err := siv.Decrypt(key, parsed.Ciphertext, siv.AAD(siv.ModeFile, filePath, ""))
	if err != nil {
		return nil, nil, fmt.Errorf("filterop: smudge %s: %w", filePath, err)
	}
	return plaintext, nil, nil
}

// cleanValues encrypts each configured scalar in place (spec 06 AC-6.2).
//
// A field that is already tagged is left alone, so a partially encrypted
// file converges instead of double-encrypting (AC-6.4). A field the config
// names but the file doesn't contain is an error: skipping it silently
// would report success while committing that secret in plaintext (AC-5.2).
//
// Every field is encrypted under version (the config's current version,
// AC-6.12), regardless of what version it previously carried. haveKey
// reports whether key actually holds that version's key; it's consulted
// only once a field that still needs encrypting is found; a file whose
// every configured field is already tagged never needs it at all (see
// Clean's doc comment for why that matters).
func cleanValues(rule config.Rule, version int, key []byte, haveKey bool, filePath string, input []byte) ([]byte, error) {
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
		if !haveKey {
			return nil, fmt.Errorf("%w: current version %d — run `nebel init`", ErrKeyVersionMissing, version)
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
// current version — one the keyring doesn't hold is left tagged, as-is,
// and named in the returned []Skipped (AC-6.11), independently of every
// other field in the same document.
func smudgeValues(rule config.Rule, keyring Keyring, filePath string, input []byte) ([]byte, []Skipped, error) {
	handler, err := format.For(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("filterop: smudge %s: %w", filePath, err)
	}

	var edits []format.Edit
	var skipped []Skipped
	for _, field := range rule.Encrypt {
		span, err := handler.Locate(input, field)
		if err != nil {
			return nil, nil, fmt.Errorf("filterop: smudge %s: %w", filePath, err)
		}
		if !tag.IsEncrypted([]byte(span.Value)) {
			continue
		}

		parsed, err := tag.Parse(span.Value)
		if err != nil {
			return nil, nil, fmt.Errorf("filterop: smudge %s at %s: %w", filePath, field, err)
		}
		if parsed.Type == tag.TypeNone {
			// A whole-file blob sitting in a value slot: restoring it
			// would guess at a type the tag never recorded.
			return nil, nil, fmt.Errorf("filterop: smudge %s at %s: value tag has no type field", filePath, field)
		}
		key, ok := keyring[parsed.Version]
		if !ok {
			skipped = append(skipped, Skipped{Field: field, Version: parsed.Version})
			continue
		}

		plaintext, err := siv.Decrypt(key, parsed.Ciphertext, siv.AAD(siv.ModeValue, filePath, field))
		if err != nil {
			return nil, nil, fmt.Errorf("filterop: smudge %s at %s: %w", filePath, field, err)
		}
		edits = append(edits, format.Edit{Span: span, Text: handler.Render(string(plaintext), parsed.Type)})
	}
	out, err := splice(input, edits, "smudge", filePath)
	return out, skipped, err
}

func splice(input []byte, edits []format.Edit, op, filePath string) ([]byte, error) {
	out, err := format.Splice(input, edits)
	if err != nil {
		return nil, fmt.Errorf("filterop: %s %s: %w", op, filePath, err)
	}
	return out, nil
}
