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

// AC-4.2: glob semantics follow .gitattributes. A pattern without a "/"
// matches a base name at any depth, one with a "/" matches the path from
// the repository root, and a leading "/" anchors. Segment syntax is
// doublestar's (github.com/bmatcuk/doublestar/v4). This test enumerates
// matching and non-matching paths per pattern.
func TestMatchRuleGlobSemantics(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		want    bool
	}{
		{"secrets/*.pem", "secrets/prod.pem", true},
		{"secrets/*.pem", "secrets/sub/prod.pem", false}, // "*" does not cross "/"
		{"secrets/*.pem", "other/secrets/prod.pem", false},
		{"*.env", "prod.env", true},
		{"*.env", "config/staging.env", true}, // a bare pattern matches at any depth
		{"*.env", "a/b/c/deep.env", true},
		{"*.env", "prod.env.bak", false},
		{".env.local", "svc/.env.local", true},
		{".env.local", "svc/x.env.local", false},
		{"/root.env", "root.env", true},
		{"/root.env", "sub/root.env", false}, // a leading "/" anchors
		{"**/*.env", "a/b/prod.env", true},
		{"**/*.env", "README.md", false},
	}
	for _, tt := range tests {
		t.Run(tt.pattern+"|"+tt.path, func(t *testing.T) {
			cfg := &Config{Rules: []Rule{{Files: tt.pattern, Mode: ModeFile}}}
			if _, got := cfg.MatchRule(tt.path); got != tt.want {
				t.Errorf("MatchRule(%q) with pattern %q matched = %v, want %v", tt.path, tt.pattern, got, tt.want)
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

// AC-4.3: a bare pattern's any-depth match is tried only after no rule
// matched the whole path. Bare patterns used to match root files only, so
// this keeps every file on the rule it had before: config/prod.env stays
// on "config/*.env", and config/app.yaml stays on "**", which always
// matched at any depth.
func TestMatchRuleWholePathMatchesBeforeBaseNameMatches(t *testing.T) {
	bare := Rule{Files: "*.env", Mode: ModeFile}
	nested := Rule{Files: "config/*.env", Mode: ModeValue, Encrypt: []string{"KEY"}}
	anchored := Rule{Files: "/prod.env", Mode: ModeValue, Encrypt: []string{"KEY"}}
	cfg := &Config{Rules: []Rule{bare, nested, anchored}}
	for path, want := range map[string]string{
		"config/prod.env": nested.Files,
		"svc/prod.env":    bare.Files,
		"prod.env":        bare.Files,
	} {
		got, ok := cfg.MatchRule(path)
		if !ok || got.Files != want {
			t.Errorf("MatchRule(%q) = %q (matched %v), want %q", path, got.Files, ok, want)
		}
	}

	everything := Rule{Files: "**", Mode: ModeFile}
	yamlRule := Rule{Files: "config/*.yaml", Mode: ModeValue, Encrypt: []string{"password"}}
	cfg = &Config{Rules: []Rule{everything, yamlRule}}
	for path, want := range map[string]string{
		"config/app.yaml": everything.Files,
	} {
		got, ok := cfg.MatchRule(path)
		if !ok || got.Files != want {
			t.Errorf("MatchRule(%q) = %q (matched %v), want %q", path, got.Files, ok, want)
		}
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

// A malformed glob pattern is caught when the repository is opened, not
// silently treated by MatchRule as "never matches" — MatchRule's bool-only
// signature discards doublestar.Match's error, so an invalid pattern that
// slipped past this check would be a silent, permanent bypass for that
// rule (audit 2026-09-29, P07 sub-issue 3).
func TestLoadRejectsInvalidGlobPattern(t *testing.T) {
	path := writeTempConfig(t, `
salt: c3RydWNyeXB0LXRlc3Qtc2FsdC0xNg==
canary: "ENC[AES256_SIV,data:aGVsbG8=]"
rules:
  - files: "secrets/[.pem"
    mode: file
`)
	if _, err := Load(path); !errors.Is(err, ErrInvalidPattern) {
		t.Errorf("Load() error = %v, want %v", err, ErrInvalidPattern)
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

	canaryTag, err := NewCanary(key, 1)
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

// AC-4.11: an encrypt entry is checked with the key syntax of the format
// its rule's glob names. Literal .env/.properties keys that aren't valid
// dot notation must load, also under a glob naming no single format.
func TestLoadValidatesKeysByFormat(t *testing.T) {
	for _, tt := range []struct {
		name, files, key string
		ok               bool
	}{
		{"properties dotted key", "*.properties", "a..b", true},
		{"properties bracket", "**/*.properties", "foo[", true},
		{"properties escaped space", "app.properties", "my key", true},
		{"env literal", "*.env", "DATABASE_PASSWORD", true},
		{"env.* glob", ".env.*", "API.KEY", true},
		{"env with space", "*.env", "A B", false},
		{"env with equals", "*.env", "A=B", false},
		{"properties control char", "*.properties", "a\tb", false},
		{"yaml dot path", "**/*.yaml", "database.password", true},
		{"yaml bad path", "**/*.yaml", "a..b", false},
		{"unknown glob dot path", "config/*", "database.password", true},
		{"unknown glob literal key", "config/*", "a..b", true},
		{"brace glob literal key", "**/*.{env,properties}", "FOO[", true},
		{"prefix glob literal key", ".env*", "a..b", true},
		{"unknown glob control char", "config/*", "a\tb", false},
		{"unknown glob empty", "config/*", "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{Rules: []Rule{{Files: tt.files, Mode: ModeValue, Encrypt: []string{tt.key}}}}
			err := cfg.Validate()
			if tt.ok && err != nil {
				t.Errorf("Validate() = %v, want nil", err)
			}
			if !tt.ok && !errors.Is(err, format.ErrBadPath) {
				t.Errorf("Validate() = %v, want %v", err, format.ErrBadPath)
			}
		})
	}
}
