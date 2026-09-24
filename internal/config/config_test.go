package config

import (
	"errors"
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

// mode: value is schema-valid but not implemented in this build; loading it
// must fail clearly rather than silently doing nothing at filter time.
func TestLoadRejectsModeValue(t *testing.T) {
	path := writeTempConfig(t, `
salt: c3RydWNyeXB0LXRlc3Qtc2FsdC0xNg==
canary: "ENC[AES256_SIV,data:aGVsbG8=]"
rules:
  - files: "config/*.yaml"
    mode: value
    encrypt: ["database.password"]
`)
	_, err := Load(path)
	if !errors.Is(err, ErrModeUnsupported) {
		t.Errorf("Load() error = %v, want %v", err, ErrModeUnsupported)
	}
}

// AC-4.7: a config file written by hand (plain YAML, no tool-specific
// serialization) loads correctly.
func TestLoadHandWrittenConfig(t *testing.T) {
	path := writeTempConfig(t, `
# A hand-written config, not produced by `+"`strucrypt add`"+`.
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
