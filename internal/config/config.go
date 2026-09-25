// Package config parses and writes the committed .strucrypt.yaml rules
// file: the salt, canary, and file-selection rules every clone shares.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"

	"github.com/MarwinMoellers/strucrypt/internal/format"
	"github.com/bmatcuk/doublestar/v4"
	"github.com/goccy/go-yaml"
)

// FileName is the name of the committed config file, resolved relative to
// the repository root.
const FileName = ".strucrypt.yaml"

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
	// Files is a doublestar glob pattern (github.com/bmatcuk/doublestar/v4),
	// matched against the file's path relative to the repository root.
	// Unlike .gitattributes, a pattern without a leading "**/" matches only
	// at the depth it's written at — "*.env" matches "prod.env" but not
	// "config/prod.env"; use "**/*.env" to match at any depth.
	Files string `yaml:"files"`

	// Mode selects whole-file (ModeFile) or per-value (ModeValue) handling.
	Mode Mode `yaml:"mode"`

	// Encrypt lists the dot-notation paths to encrypt, for mode: value
	// rules — "database.password", "api.keys[0]". Unused by mode: file.
	Encrypt []string `yaml:"encrypt,omitempty"`
}

// Config is the parsed contents of .strucrypt.yaml.
type Config struct {
	// Salt is the Argon2id salt, base64-encoded. Not secret.
	Salt string `yaml:"salt"`

	// Canary is an ENC[...] tag (spec 03) over CanaryPlaintext, encrypted
	// with AAD = CanaryAAD. It lets Init verify a candidate password is
	// correct before trusting it.
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
)

// SaltBytes decodes Salt from base64.
func (c *Config) SaltBytes() ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(c.Salt)
	if err != nil {
		return nil, fmt.Errorf("config: decoding salt: %w", err)
	}
	return b, nil
}

// Validate checks every rule's mode and field list. Called automatically
// by Load.
//
// Field paths are parsed here rather than at clean time so a typo in a
// committed config fails when the repository is opened, not silently on
// the one machine that happens to stage that file.
func (c *Config) Validate() error {
	for _, r := range c.Rules {
		switch r.Mode {
		case ModeFile:
			if len(r.Encrypt) > 0 {
				return fmt.Errorf("%w: rule %q lists %d field(s); use mode: value to encrypt fields", ErrFieldsOnFileRule, r.Files, len(r.Encrypt))
			}
		case ModeValue:
			if len(r.Encrypt) == 0 {
				return fmt.Errorf("%w: rule %q", ErrNoFields, r.Files)
			}
			for _, field := range r.Encrypt {
				if _, err := format.ParsePath(field); err != nil {
					return fmt.Errorf("config: rule %q: %w", r.Files, err)
				}
			}
		default:
			return fmt.Errorf("%w: rule %q: mode must be \"file\" or \"value\", got %q", ErrInvalidMode, r.Files, r.Mode)
		}
	}
	return nil
}

// MatchRule returns the first rule, in file order, whose Files glob matches
// path. Rule order in the file is therefore the resolution order: the first
// matching pattern wins, and later rules for an already-matched file are
// never consulted.
func (c *Config) MatchRule(path string) (Rule, bool) {
	for _, r := range c.Rules {
		if ok, _ := doublestar.Match(r.Files, path); ok {
			return r, true
		}
	}
	return Rule{}, false
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
// the rest of `strucrypt add`'s comment-preserving edit).
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
