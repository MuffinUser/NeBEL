// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package config

import (
	"errors"
	"github.com/MuffinUser/nebel/internal/format"
	"os"
	"path/filepath"
	"testing"
)

// AC-4.1: the documented top-level fields parse correctly.
func TestLoadSchema(t *testing.T) {
	path := writeTempConfig(t, `
salt: c3RydWNyeXB0LXRlc3Qtc2FsdC0xNg==
canary: "ENC[AES256_SIV,data:aGVsbG8=]"
rules:
  - files: "secrets/*.pem"
    mode: file
  - files: "**/*.env"
    mode: file
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Salt == "" {
		t.Error("Salt not parsed")
	}
	if cfg.Canary == "" {
		t.Error("Canary not parsed")
	}
	if len(cfg.Rules) != 2 {
		t.Fatalf("len(Rules) = %d, want 2", len(cfg.Rules))
	}
	if cfg.Rules[0].Files != "secrets/*.pem" || cfg.Rules[0].Mode != ModeFile {
		t.Errorf("Rules[0] = %+v", cfg.Rules[0])
	}
}

// AC-4.2: glob semantics are doublestar (github.com/bmatcuk/doublestar/v4):
// a bare pattern matches only at the depth it's written at; "**/" is needed
// to match at any depth. This test enumerates both matching and
// non-matching paths per pattern, documenting the exact behavior chosen.
func TestMatchRuleGlobSemantics(t *testing.T) {
	cfg := &Config{Rules: []Rule{
		{Files: "secrets/*.pem", Mode: ModeFile},
		{Files: "**/*.env", Mode: ModeFile},
	}}

	tests := []struct {
		path string
		want bool
	}{
		{"secrets/prod.pem", true},
		{"secrets/sub/prod.pem", false}, // "*" does not cross "/"
		{"other/prod.pem", false},
		{".env", true},
		{"prod.env", true},
		{"config/staging.env", true}, // "**/*.env" matches any depth
		{"a/b/c/deep.env", true},
		{"prod.env.bak", false},
		{"README.md", false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			_, got := cfg.MatchRule(tt.path)
			if got != tt.want {
				t.Errorf("MatchRule(%q) matched = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// AC-4.3: when multiple rules' globs match the same path, the first rule in
// file order wins.
func TestMatchRulePrecedence(t *testing.T) {
	first := Rule{Files: "secrets/*.pem", Mode: ModeFile}
	second := Rule{Files: "**/*.pem", Mode: ModeFile}
	cfg := &Config{Rules: []Rule{first, second}}

	got, ok := cfg.MatchRule("secrets/prod.pem")
	if !ok {
		t.Fatal("expected a match")
	}
	if got.Files != first.Files {
		t.Errorf("MatchRule() returned %q, want the first matching rule %q", got.Files, first.Files)
	}
}

// AC-4.4: a mode outside {file, value} fails to load with a clear error.
func TestLoadRejectsInvalidMode(t *testing.T) {
	path := writeTempConfig(t, `
salt: c3RydWNyeXB0LXRlc3Qtc2FsdC0xNg==
canary: "ENC[AES256_SIV,data:aGVsbG8=]"
rules:
  - files: "secrets/*.pem"
    mode: bogus
`)
	_, err := Load(path)
	if !errors.Is(err, ErrInvalidMode) {
		t.Errorf("Load() error = %v, want %v", err, ErrInvalidMode)
	}
}

// A mode: value rule now loads, with its field list parsed.
func TestLoadModeValue(t *testing.T) {
	path := writeTempConfig(t, `
salt: c3RydWNyeXB0LXRlc3Qtc2FsdC0xNg==
canary: "ENC[AES256_SIV,data:aGVsbG8=]"
rules:
  - files: "config/*.yaml"
    mode: value
    encrypt: ["database.password", "api.keys[0]"]
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	rule, ok := cfg.MatchRule("config/staging.yaml")
	if !ok {
		t.Fatal("MatchRule did not match config/staging.yaml")
	}
	if rule.Mode != ModeValue {
		t.Errorf("Mode = %q, want %q", rule.Mode, ModeValue)
	}
	if len(rule.Encrypt) != 2 {
		t.Errorf("Encrypt = %v, want 2 fields", rule.Encrypt)
	}
}

// A rule that protects nothing is a config mistake, not a valid document:
// mode: value with no fields, or mode: file with fields it would ignore.
func TestLoadRejectsMismatchedFieldLists(t *testing.T) {
	tests := []struct {
		name string
		rule string
		want error
	}{
		{"value without fields", `
  - files: "config/*.yaml"
    mode: value`, ErrNoFields},
		{"file with fields", `
  - files: "secrets/*.pem"
    mode: file
    encrypt: ["database.password"]`, ErrFieldsOnFileRule},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTempConfig(t, `
salt: c3RydWNyeXB0LXRlc3Qtc2FsdC0xNg==
canary: "ENC[AES256_SIV,data:aGVsbG8=]"
rules:`+tt.rule+`
`)
			if _, err := Load(path); !errors.Is(err, tt.want) {
				t.Errorf("Load() error = %v, want %v", err, tt.want)
			}
		})
	}
}

// A malformed field path is caught when the repository is opened, not
// silently on whichever machine first stages a matching file.
func TestLoadRejectsBadFieldPath(t *testing.T) {
	path := writeTempConfig(t, `
salt: c3RydWNyeXB0LXRlc3Qtc2FsdC0xNg==
canary: "ENC[AES256_SIV,data:aGVsbG8=]"
rules:
  - files: "config/*.yaml"
    mode: value
    encrypt: ["database..password"]
`)
	if _, err := Load(path); !errors.Is(err, format.ErrBadPath) {
		t.Errorf("Load() error = %v, want %v", err, format.ErrBadPath)
	}
}

// AC-4.7: a config file written by hand (plain YAML, no tool-specific
// serialization) loads correctly.
func TestLoadHandWrittenConfig(t *testing.T) {
	path := writeTempConfig(t, `
# A hand-written config, not produced by `+"`nebel add`"+`.
salt: "c3RydWNyeXB0LXRlc3Qtc2FsdC0xNg=="
canary: "ENC[AES256_SIV,data:aGVsbG8=]"
rules:
  - files: secrets/*.pem
    mode: file
`)
	if _, err := Load(path); err != nil {
		t.Errorf("Load() of a hand-written config: %v", err)
	}
}

// AC-4.8: the canary is a valid spec-03 ENC[...] tag over CanaryPlaintext,
// bound with AAD = CanaryAAD, and a correct key decrypts it while an
// incorrect key does not.
func TestCanaryRoundTrip(t *testing.T) {
	key := make([]byte, 64)
	for i := range key {
		key[i] = byte(i)
	}
	wrongKey := make([]byte, 64)
	for i := range wrongKey {
		wrongKey[i] = byte(255 - i)
	}

	canaryTag, err := NewCanary(key)
	if err != nil {
		t.Fatalf("NewCanary: %v", err)
	}

	cfg := &Config{Canary: canaryTag}
	if err := cfg.VerifyCanary(key); err != nil {
		t.Errorf("VerifyCanary() with the correct key: %v", err)
	}
	if err := cfg.VerifyCanary(wrongKey); err == nil {
		t.Error("VerifyCanary() with the wrong key: want an error, got nil")
	}
}

func writeTempConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), FileName)
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("writing temp config: %v", err)
	}
	return path
}
