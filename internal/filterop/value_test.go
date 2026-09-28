// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package filterop

import (
	"bytes"
	"strings"
	"testing"

	"github.com/MarwinMoellers/nebel/internal/config"
	"github.com/MarwinMoellers/nebel/internal/tag"
)

const valueDoc = `# Staging configuration.
database:
  host: db.internal      # not a secret
  password: "s3cr3t"
  port: 5432

api:
  token: alpha
`

func valueConfig(fields ...string) *config.Config {
	if len(fields) == 0 {
		fields = []string{"database.password"}
	}
	return &config.Config{Rules: []config.Rule{
		{Files: "config/*.yaml", Mode: config.ModeValue, Encrypt: fields},
	}}
}

// AC-6.2: clean on a mode: value rule encrypts only the configured
// scalars, leaving the rest of the document readable.
func TestCleanValuesEncryptsOnlyConfiguredFields(t *testing.T) {
	got, err := Clean(valueConfig(), testKey, "config/staging.yaml", []byte(valueDoc))
	if err != nil {
		t.Fatalf("Clean: %v", err)
	}

	if strings.Contains(string(got), "s3cr3t") {
		t.Errorf("the secret survived clean:\n%s", got)
	}
	for _, kept := range []string{"# Staging configuration.", "host: db.internal      # not a secret", "port: 5432", "token: alpha"} {
		if !strings.Contains(string(got), kept) {
			t.Errorf("clean disturbed content it should not touch (%q):\n%s", kept, got)
		}
	}
	if !strings.Contains(string(got), `password: "ENC[AES256_SIV,`) {
		t.Errorf("encrypted field is not a quoted ENC[...] tag:\n%s", got)
	}
}

// AC-6.5 / AC-5.1 for per-value mode: everything the rule does not name
// survives a clean/smudge round trip byte for byte — comments, spacing,
// key order, and unrelated values.
func TestValueRoundTripLeavesUntouchedBytesExact(t *testing.T) {
	cfg := valueConfig("database.password", "database.port")

	cleaned, err := Clean(cfg, testKey, "config/staging.yaml", []byte(valueDoc))
	if err != nil {
		t.Fatalf("Clean: %v", err)
	}
	smudged, err := Smudge(cfg, testKey, "config/staging.yaml", cleaned)
	if err != nil {
		t.Fatalf("Smudge: %v", err)
	}
	if string(smudged) != valueDoc {
		t.Errorf("round trip changed the file:\n got  = %q\n want = %q", smudged, valueDoc)
	}
}

// Known limitation (spec 05 AC-5.6): a string written as a plain scalar
// comes back double-quoted, because the tag records the value's type but
// not the style it was written in. The ciphertext is derived from the
// value, so the re-quoted scalar still cleans to an identical blob and
// git shows no diff — the drift is confined to the working tree, once.
func TestValueRoundTripNormalizesPlainStringQuoting(t *testing.T) {
	cfg := valueConfig("api.token")

	cleaned, err := Clean(cfg, testKey, "config/staging.yaml", []byte(valueDoc))
	if err != nil {
		t.Fatalf("Clean: %v", err)
	}
	smudged, err := Smudge(cfg, testKey, "config/staging.yaml", cleaned)
	if err != nil {
		t.Fatalf("Smudge: %v", err)
	}
	if !strings.Contains(string(smudged), `token: "alpha"`) {
		t.Errorf("plain string was not normalized to double-quoted:\n%s", smudged)
	}

	// The drift must not compound: cleaning the re-quoted document has to
	// reproduce the same blob, or every checkout would dirty the file.
	recleaned, err := Clean(cfg, testKey, "config/staging.yaml", smudged)
	if err != nil {
		t.Fatalf("re-clean: %v", err)
	}
	if !bytes.Equal(recleaned, cleaned) {
		t.Errorf("re-cleaning the restored file changed the blob:\n got  = %s\n want = %s", recleaned, cleaned)
	}
}

// AC-3.2: a non-string scalar comes back as its original type, so
// `port: 5432` stays an integer rather than becoming the string "5432".
func TestValueRoundTripPreservesType(t *testing.T) {
	cfg := valueConfig("database.port")

	cleaned, err := Clean(cfg, testKey, "config/staging.yaml", []byte(valueDoc))
	if err != nil {
		t.Fatalf("Clean: %v", err)
	}
	if !strings.Contains(string(cleaned), "type:int") {
		t.Errorf("the integer's type was not recorded in the tag:\n%s", cleaned)
	}
	smudged, err := Smudge(cfg, testKey, "config/staging.yaml", cleaned)
	if err != nil {
		t.Fatalf("Smudge: %v", err)
	}
	if !strings.Contains(string(smudged), "port: 5432") {
		t.Errorf("integer was not restored unquoted:\n%s", smudged)
	}
}

// AC-6.3: clean is deterministic, so re-staging an unchanged file produces
// no diff.
func TestCleanValuesIsDeterministic(t *testing.T) {
	first, err := Clean(valueConfig(), testKey, "config/staging.yaml", []byte(valueDoc))
	if err != nil {
		t.Fatalf("first clean: %v", err)
	}
	second, err := Clean(valueConfig(), testKey, "config/staging.yaml", []byte(valueDoc))
	if err != nil {
		t.Fatalf("second clean: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Error("clean output differs between runs")
	}
}

// AC-6.4: a field that is already tagged is left exactly as it is, rather
// than encrypted a second time.
func TestCleanValuesSkipsAlreadyEncrypted(t *testing.T) {
	once, err := Clean(valueConfig(), testKey, "config/staging.yaml", []byte(valueDoc))
	if err != nil {
		t.Fatalf("first clean: %v", err)
	}
	twice, err := Clean(valueConfig(), testKey, "config/staging.yaml", once)
	if err != nil {
		t.Fatalf("second clean: %v", err)
	}
	if !bytes.Equal(once, twice) {
		t.Errorf("re-cleaning an encrypted file changed it:\n once  = %s\n twice = %s", once, twice)
	}
}

// AC-6.7: a file whose fields are still plaintext (staged before the
// filter was registered) passes through smudge untouched.
func TestSmudgeValuesTolerantOfPlaintext(t *testing.T) {
	got, err := Smudge(valueConfig(), testKey, "config/staging.yaml", []byte(valueDoc))
	if err != nil {
		t.Fatalf("Smudge: %v", err)
	}
	if string(got) != valueDoc {
		t.Errorf("Smudge changed an unencrypted file:\n%s", got)
	}
}

// AC-5.2: a configured field the file doesn't contain is an error. Silently
// skipping it would report success while committing that secret in clear.
func TestCleanValuesMissingFieldFails(t *testing.T) {
	_, err := Clean(valueConfig("database.nope"), testKey, "config/staging.yaml", []byte(valueDoc))
	if err == nil {
		t.Fatal("Clean with a missing field: want an error, got nil")
	}
	if !strings.Contains(err.Error(), "database.nope") {
		t.Errorf("error does not name the missing field: %v", err)
	}
}

// AC-6.9: a tampered tag is reported, never smudged into plausible-looking
// plaintext.
func TestSmudgeValuesSurfacesTampering(t *testing.T) {
	cleaned, err := Clean(valueConfig(), testKey, "config/staging.yaml", []byte(valueDoc))
	if err != nil {
		t.Fatalf("Clean: %v", err)
	}
	// Flip a byte inside the base64 payload.
	idx := bytes.Index(cleaned, []byte("data:")) + len("data:") + 2
	tampered := bytes.Clone(cleaned)
	tampered[idx] ^= 1

	if _, err := Smudge(valueConfig(), testKey, "config/staging.yaml", tampered); err == nil {
		t.Error("Smudge on a tampered tag: want an error, got nil")
	}
}

// A value sealed for one field must not decrypt in another: the AAD binds
// each ciphertext to its own location, so a tag cannot be copy-pasted.
func TestValueTagIsBoundToItsField(t *testing.T) {
	cleaned, err := Clean(valueConfig("database.password"), testKey, "config/staging.yaml", []byte(valueDoc))
	if err != nil {
		t.Fatalf("Clean: %v", err)
	}
	// Move the tag from database.password to api.token.
	tagText := string(cleaned[bytes.Index(cleaned, []byte(`"ENC[`)) : bytes.Index(cleaned, []byte("]\""))+2])
	moved := strings.Replace(valueDoc, "token: alpha", "token: "+tagText, 1)

	if _, err := Smudge(valueConfig("api.token"), testKey, "config/staging.yaml", []byte(moved)); err == nil {
		t.Error("a tag moved to another field still decrypted")
	}
}

// A file matching a mode: value rule in a format with no handler is an
// error at filter time, not a silent passthrough that would commit the
// secret in clear.
func TestValuesUnsupportedFormatFails(t *testing.T) {
	cfg := &config.Config{Rules: []config.Rule{
		{Files: "config/*.toml", Mode: config.ModeValue, Encrypt: []string{"database.password"}},
	}}
	if _, err := Clean(cfg, testKey, "config/staging.toml", []byte("password = 's3cr3t'")); err == nil {
		t.Error("Clean on an unsupported format: want an error, got nil")
	}
}

// A whole-file blob pasted into a value slot has no type to restore;
// guessing one would silently change the document's shape.
func TestSmudgeValuesRejectsUntypedTag(t *testing.T) {
	doc := strings.Replace(valueDoc, `password: "s3cr3t"`, `password: "`+tag.Encode([]byte("whatever"))+`"`, 1)
	if _, err := Smudge(valueConfig(), testKey, "config/staging.yaml", []byte(doc)); err == nil {
		t.Error("Smudge on an untyped tag: want an error, got nil")
	}
}
