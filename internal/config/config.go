// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

// Package config parses and writes the committed .nebel.yaml rules
// file: the salt, canary, and file-selection rules every clone shares.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/MuffinUser/nebel/internal/format"
	"github.com/bmatcuk/doublestar/v4"
	"github.com/goccy/go-yaml"
)

// FileName is the name of the committed config file, resolved relative to
// the repository root.
const FileName = ".nebel.yaml"

// Mode is the encryption granularity a rule applies to matching files.
type Mode string

const (
	// ModeFile encrypts a whole file as one blob. The only mode this build
	// implements.
	ModeFile Mode = "file"

	// ModeValue encrypts selected values within a structured file,
	// leaving the rest readable and diffable.
	ModeValue Mode = "value"
)

// Rule is one file-selection rule: which files it applies to, and how.
type Rule struct {
	// Files is a glob pattern matched the way .gitattributes matches the
	// filter line `nebel add` writes for it, so git and nebel agree on
	// which files a rule covers. A pattern without a "/" matches a file's
	// base name at any depth ("*.env" matches "prod.env" and
	// "config/prod.env"). A pattern with a "/" matches the whole path
	// relative to the repository root, and a leading "/" only anchors it
	// ("/prod.env" matches the root file alone). Segment syntax is
	// doublestar's (github.com/bmatcuk/doublestar/v4); see MatchRule for
	// precedence.
	Files string `yaml:"files"`

	// Mode selects whole-file (ModeFile) or per-value (ModeValue) handling.
	Mode Mode `yaml:"mode"`

	// Encrypt lists the values to encrypt, for mode: value rules: dot
	// paths for YAML/JSON ("database.password", "api.keys[0]"), literal
	// keys for .env/.properties ("DATABASE_PASSWORD"). Unused by mode: file.
	Encrypt []string `yaml:"encrypt,omitempty"`
}

// Config is the parsed contents of .nebel.yaml.
type Config struct {
	// KeyVersion is the current key version (spec 11): Salt and Canary
	// below are this version's. clean always encrypts under this version;
	// an older version an existing value still carries is looked up via
	// its own tag (spec 03) instead.
	KeyVersion int `yaml:"key_version"`

	// Salt is the Argon2id salt for KeyVersion, base64-encoded. Not secret.
	Salt string `yaml:"salt"`

	// Canary is an ENC[...] tag (spec 03) over CanaryPlaintext for
	// KeyVersion, encrypted with AAD = CanaryAAD. It lets Init verify a
	// candidate password is correct before trusting it.
	Canary string `yaml:"canary"`

	// Rules are matched against a file's path in order; the first match
	// wins (see MatchRule).
	Rules []Rule `yaml:"rules"`
}

var (
	// ErrInvalidMode is returned when a rule's mode is neither "file" nor
	// "value".
	ErrInvalidMode = errors.New("config: invalid mode")

	// ErrNoFields is returned when a mode: value rule lists no paths to
	// encrypt. Such a rule silently protects nothing, which is worse than
	// refusing to load it.
	ErrNoFields = errors.New("config: mode: value rule encrypts no fields")

	// ErrFieldsOnFileRule is returned when a mode: file rule carries an
	// encrypt list, which it would ignore — a sign the author expected
	// per-value behaviour and would not get it.
	ErrFieldsOnFileRule = errors.New("config: mode: file rule must not list fields")

	// ErrInvalidPattern is returned when a rule's Files glob is not valid
	// doublestar syntax. Rejecting it here, rather than at match time,
	// matters because MatchRule discards doublestar.Match's error (its
	// bool-only signature has no room for one) — an invalid pattern that
	// slipped past this check would silently behave as "never matches"
	// instead of surfacing the typo.
	ErrInvalidPattern = errors.New("config: invalid glob pattern")
)

// SaltBytes decodes Salt from base64.
func (c *Config) SaltBytes() ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(c.Salt)
	if err != nil {
		return nil, fmt.Errorf("config: decoding salt: %w", err)
	}
	return b, nil
}

// CurrentVersion returns c.KeyVersion, defaulting to 1 when it is unset —
// Go's zero value for an absent yaml field is 0, which is otherwise never a
// valid version (AC-4.10: bootstrap always starts at 1).
func (c *Config) CurrentVersion() int {
	if c.KeyVersion == 0 {
		return 1
	}
	return c.KeyVersion
}

// Validate checks every rule's mode and field list. Called automatically
// by Load.
//
// Field paths are parsed here rather than at clean time so a typo in a
// committed config fails when the repository is opened, not silently on
// the one machine that happens to stage that file.
func (c *Config) Validate() error {
	for _, r := range c.Rules {
		if !doublestar.ValidatePattern(r.Files) {
			return fmt.Errorf("%w: rule %q", ErrInvalidPattern, r.Files)
		}
		switch r.Mode {
		case ModeFile:
			if len(r.Encrypt) > 0 {
				return fmt.Errorf("%w: rule %q lists %d field(s); use mode: value to encrypt fields", ErrFieldsOnFileRule, r.Files, len(r.Encrypt))
			}
		case ModeValue:
			if len(r.Encrypt) == 0 {
				return fmt.Errorf("%w: rule %q", ErrNoFields, r.Files)
			}
			// The key syntax depends on the format, which a glob only
			// reveals through its last segment ("*.env", "**/*.properties").
			// A glob that doesn't name one ("config/*", "**/*.{env,yaml}")
			// may match several formats, so it gets the loosest check, the
			// .properties literal key; Locate still rejects a key that's
			// invalid for the file actually matched (AC-4.11).
			kind, detected := format.Detect(path.Base(r.Files))
			if !detected {
				kind = format.KindProperties
			}
			for _, field := range r.Encrypt {
				if err := format.ValidKey(kind, field); err != nil {
					return fmt.Errorf("config: rule %q: %w", r.Files, err)
				}
			}
		default:
			return fmt.Errorf("%w: rule %q: mode must be \"file\" or \"value\", got %q", ErrInvalidMode, r.Files, r.Mode)
		}
	}
	return nil
}

// MatchRule returns the rule for path, a slash-separated path relative to
// the repository root. The first rule in file order whose pattern matches
// the whole path wins. Only if none does is a bare pattern (no "/") tried
// against the base name, again in file order. So "config/*.env" keeps
// config/prod.env even when "*.env" is listed first.
//
// The first pass is how rules matched before bare patterns matched at any
// depth, so every file that had a rule then still resolves to the same
// one, and ciphertext already committed under it decrypts the same way.
func (c *Config) MatchRule(filePath string) (Rule, bool) {
	for _, r := range c.Rules {
		if matchPath(r.Files, filePath) {
			return r, true
		}
	}
	base := path.Base(filePath)
	for _, r := range c.Rules {
		if !pathPattern(r.Files) && matchPath(r.Files, base) {
			return r, true
		}
	}
	return Rule{}, false
}

// pathPattern reports whether pattern names a path rather than a base
// name, by the .gitattributes rule: it contains a "/".
func pathPattern(pattern string) bool {
	return strings.Contains(pattern, "/")
}

// matchPath matches pattern against name, treating a leading "/" as an
// anchor to the repository root rather than a literal character.
// doublestar.Match's error is dropped because Validate already rejected
// invalid patterns.
func matchPath(pattern, name string) bool {
	ok, _ := doublestar.Match(strings.TrimPrefix(pattern, "/"), name)
	return ok
}

// Load reads and parses path, then validates it.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: reading %s: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: parsing %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Save serializes c as YAML and writes it to path.
//
// MVP limitation: this marshals the whole struct fresh each time, so
// hand-added comments in an existing file are not preserved across a Save
// (spec 08 AC-8.6 wants full formatting preservation — deferred along with
// the rest of `nebel add`'s comment-preserving edit).
func (c *Config) Save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("config: marshaling: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("config: writing %s: %w", path, err)
	}
	return nil
}

// Exists reports whether a config file is already present at path.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
