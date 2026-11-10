// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package filterop

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/MuffinUser/nebel/internal/config"
	"github.com/MuffinUser/nebel/internal/format"
	"github.com/MuffinUser/nebel/internal/siv"
	"github.com/MuffinUser/nebel/internal/tag"
)

const envFile = `# Application settings
APP_NAME=nebel
export DATABASE_PASSWORD="p@ss \"word\""   # rotate quarterly
API_TOKEN=tok_live#1
EMPTY=
`

const propertiesFile = `# Application settings
database.url=jdbc:postgresql://db/app
database.password = caf\u00e9 s3cr3t  
api.token:tok_live
`

func lineConfig(version int) *config.Config {
	return &config.Config{KeyVersion: version, Rules: []config.Rule{
		{Files: "**/*.env", Mode: config.ModeValue, Encrypt: []string{"DATABASE_PASSWORD", "API_TOKEN", "EMPTY"}},
		{Files: "**/*.properties", Mode: config.ModeValue, Encrypt: []string{"database.password", "api.token"}},
	}}
}

var lineFiles = map[string]string{
	"config/prod.env":       envFile,
	"config/app.properties": propertiesFile,
}

// AC-6.14 with AC-6.2, AC-6.3, AC-6.5: only the configured keys are
// encrypted, quotes and comments stay, clean is deterministic, and smudge
// restores the file byte for byte, in LF and CRLF.
func TestLineFormatsRoundTrip(t *testing.T) {
	cfg := lineConfig(1)
	for path, doc := range lineFiles {
		for name, src := range map[string]string{"LF": doc, "CRLF": strings.ReplaceAll(doc, "\n", "\r\n")} {
			t.Run(path+"/"+name, func(t *testing.T) {
				cleaned, err := Clean(cfg, testKeyring, path, []byte(src))
				if err != nil {
					t.Fatalf("Clean: %v", err)
				}
				for _, secret := range []string{"p@ss", "tok_live", "s3cr3t"} {
					if strings.Contains(string(cleaned), secret) {
						t.Errorf("secret %q survived clean:\n%s", secret, cleaned)
					}
				}
				again, err := Clean(cfg, testKeyring, path, []byte(src))
				if err != nil || !bytes.Equal(again, cleaned) {
					t.Errorf("clean is not deterministic (err %v)", err)
				}
				smudged, _, err := Smudge(cfg, testKeyring, path, cleaned)
				if err != nil {
					t.Fatalf("Smudge: %v", err)
				}
				if string(smudged) != src {
					t.Errorf("round trip changed the file:\n got  = %q\n want = %q", smudged, src)
				}
			})
		}
	}
}

func TestLineFormatsKeepQuotesAndComments(t *testing.T) {
	cleaned, err := Clean(lineConfig(1), testKeyring, "config/prod.env", []byte(envFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"APP_NAME=nebel\n", `export DATABASE_PASSWORD="ENC[AES256_SIV_TB,key:1,`, `,type:str]"   # rotate quarterly`, "API_TOKEN=ENC[", "EMPTY=ENC["} {
		if !strings.Contains(string(cleaned), want) {
			t.Errorf("cleaned file lacks %q:\n%s", want, cleaned)
		}
	}
}

// AC-6.14: the AAD's field component is the literal key, so a dotted
// .properties key is bound as-is, not as a parsed path.
func TestLineFormatsBindLiteralKey(t *testing.T) {
	cleaned, err := Clean(lineConfig(1), testKeyring, "config/app.properties", []byte(propertiesFile))
	if err != nil {
		t.Fatal(err)
	}
	h, _ := format.For("config/app.properties")
	span, err := h.Locate(cleaned, "api.token")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := tag.Parse(span.Value)
	if err != nil {
		t.Fatal(err)
	}
	got, err := siv.Decrypt(testKey, parsed.Ciphertext, siv.AAD(siv.ModeValue, "config/app.properties", "api.token", string(tag.TypeStr)))
	if err != nil || string(got) != "tok_live" {
		t.Errorf("Decrypt with literal-key AAD = %q, %v; want tok_live", got, err)
	}
}

// AC-6.13: fields under different key versions in one file each decrypt
// with their own version.
func TestLineFormatsMixedVersions(t *testing.T) {
	path := "config/app.properties"
	v1, err := Clean(lineConfig(1), testKeyring, path, []byte(propertiesFile))
	if err != nil {
		t.Fatal(err)
	}
	// Re-encrypt only database.password under v2, as an edit after a
	// rotation would.
	h, _ := format.For(path)
	span, _ := h.Locate(v1, "database.password")
	partial, _ := format.Splice(v1, []format.Edit{{Span: span, Text: `caf\u00e9 s3cr3t  `}})
	keyring := Keyring{1: testKey, 2: v2Key}
	mixed, err := Clean(lineConfig(2), keyring, path, partial)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mixed), "key:1,") || !strings.Contains(string(mixed), "key:2,") {
		t.Fatalf("expected one field per version:\n%s", mixed)
	}
	smudged, _, err := Smudge(lineConfig(2), keyring, path, mixed)
	if err != nil {
		t.Fatalf("Smudge: %v", err)
	}
	if string(smudged) != propertiesFile {
		t.Errorf("mixed-version smudge:\n got  = %q\n want = %q", smudged, propertiesFile)
	}
}

// AC-6.16: the quotes around a .env value are bound into its AAD, so
// re-quoting a tag after clean fails authentication rather than smudging
// the same raw literal into a context where it means something else.
func TestLineFormatsSmudgeRejectsChangedQuotes(t *testing.T) {
	path := "a.env"
	cfg := &config.Config{Rules: []config.Rule{{Files: "*.env", Mode: config.ModeValue, Encrypt: []string{"V"}}}}
	for _, tt := range []struct {
		name, src string
		requote   *strings.Replacer
	}{
		{"double to single", "V=\"a\\nb$HOME\"\n", strings.NewReplacer(`"`, `'`)},
		{"single to double", "V='a\\nb$HOME'\n", strings.NewReplacer(`'`, `"`)},
		{"bare to double", "V=a\\nb\n", strings.NewReplacer(`=ENC`, `="ENC`, "]\n", "]\"\n")},
		{"single to bare", "V='a b'\n", strings.NewReplacer(`'`, ``)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cleaned, err := Clean(cfg, testKeyring, path, []byte(tt.src))
			if err != nil {
				t.Fatal(err)
			}
			requoted := tt.requote.Replace(string(cleaned))
			if requoted == string(cleaned) {
				t.Fatal("test setup: quotes not replaced")
			}
			if _, _, err := Smudge(cfg, testKeyring, path, []byte(requoted)); !errors.Is(err, siv.ErrAuth) {
				t.Errorf("Smudge(%q) error = %v, want %v", requoted, err, siv.ErrAuth)
			}
		})
	}
}

// AC-6.16: only quoting is bound. Whitespace before a bare .env value and
// the .properties separator don't change the value, so editing them after
// clean still smudges.
func TestLineFormatsUnboundSyntaxStillSmudges(t *testing.T) {
	for _, tt := range []struct {
		path, key, src string
		edit           *strings.Replacer
		want           string
	}{
		{"a.env", "V", "V=secret\n", strings.NewReplacer("V=", "V= "), "V= secret\n"},
		{"a.properties", "v", "v=secret\n", strings.NewReplacer("v=", "v : "), "v : secret\n"},
	} {
		t.Run(tt.path, func(t *testing.T) {
			cfg := &config.Config{Rules: []config.Rule{{Files: "a.*", Mode: config.ModeValue, Encrypt: []string{tt.key}}}}
			cleaned, err := Clean(cfg, testKeyring, tt.path, []byte(tt.src))
			if err != nil {
				t.Fatal(err)
			}
			got, _, err := Smudge(cfg, testKeyring, tt.path, []byte(tt.edit.Replace(string(cleaned))))
			if err != nil || string(got) != tt.want {
				t.Errorf("Smudge = %q, %v; want %q", got, err, tt.want)
			}
		})
	}
}

// AC-6.16: line formats never had legacy value tags, so one is refused on
// clean (git add) and on smudge (checkout) instead of decrypting without
// the quote binding.
func TestLineFormatsRefuseLegacyTags(t *testing.T) {
	path := "a.env"
	cfg := &config.Config{Rules: []config.Rule{{Files: "*.env", Mode: config.ModeValue, Encrypt: []string{"V"}}}}
	ciphertext, err := siv.Encrypt(testKey, []byte("x"), siv.AAD(siv.ModeValue, path, "V"))
	if err != nil {
		t.Fatal(err)
	}
	legacy := strings.Replace(tag.EncodeValue(ciphertext, 1, tag.TypeStr), tag.AlgoAES256SIVTypeBound+",", tag.AlgoAES256SIV+",", 1)
	doc := []byte("V=\"" + legacy + "\"\n")
	if _, err := Clean(cfg, testKeyring, path, doc); !errors.Is(err, errLegacyLineTag) {
		t.Errorf("Clean error = %v, want %v", err, errLegacyLineTag)
	}
	if _, _, err := Smudge(cfg, testKeyring, path, doc); !errors.Is(err, errLegacyLineTag) {
		t.Errorf("Smudge error = %v, want %v", err, errLegacyLineTag)
	}
}

// AC-6.15: a correctly bound .env value that still doesn't fit its quotes
// (only possible from a crafted tag) is refused by the context guard.
func TestLineFormatsSmudgeRejectsCraftedEnvLiteral(t *testing.T) {
	path := "a.env"
	cfg := &config.Config{Rules: []config.Rule{{Files: "*.env", Mode: config.ModeValue, Encrypt: []string{"V"}}}}
	for name, plaintext := range map[string]string{"line break": "x\nADMIN=true", "closing quote": `x" ADMIN="true`} {
		t.Run(name, func(t *testing.T) {
			ciphertext, err := siv.Encrypt(testKey, []byte(plaintext), siv.AAD(siv.ModeValue, path, "V", string(tag.TypeStr), "env:double"))
			if err != nil {
				t.Fatal(err)
			}
			doc := "V=\"" + tag.EncodeValue(ciphertext, 1, tag.TypeStr) + "\"\n"
			if _, _, err := Smudge(cfg, testKeyring, path, []byte(doc)); !errors.Is(err, format.ErrLiteralContext) {
				t.Errorf("Smudge error = %v, want %v", err, format.ErrLiteralContext)
			}
		})
	}
}

// AC-6.15: a validly encrypted value containing a line break (only
// possible from a crafted tag) is refused rather than injecting lines.
func TestLineFormatsSmudgeRejectsLineBreak(t *testing.T) {
	path := "config/app.properties"
	ciphertext, err := siv.Encrypt(testKey, []byte("x\nadmin=true"), siv.AAD(siv.ModeValue, path, "api.token", string(tag.TypeStr)))
	if err != nil {
		t.Fatal(err)
	}
	doc := "api.token=" + tag.EncodeValue(ciphertext, 1, tag.TypeStr) + "\ndatabase.password=x\n"
	_, _, err = Smudge(lineConfig(1), testKeyring, path, []byte(doc))
	if !errors.Is(err, format.ErrLiteralContext) {
		t.Errorf("Smudge error = %v, want %v", err, format.ErrLiteralContext)
	}
}

// Duplicates and multi-line values fail clean (spec 05 AC-5.19, 5.20)
// rather than leaving the effective value in plaintext.
func TestLineFormatsCleanRefusals(t *testing.T) {
	for name, tt := range map[string]struct {
		path, src string
		want      error
	}{
		"duplicate":  {"a.env", "API_TOKEN=1\nDATABASE_PASSWORD=x\nEMPTY=\nAPI_TOKEN=2\n", format.ErrDuplicateKey},
		"multi-line": {"a.properties", "database.password=a \\\n b\napi.token=t\n", format.ErrMultiline},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Clean(lineConfig(1), testKeyring, tt.path, []byte(tt.src)); !errors.Is(err, tt.want) {
				t.Errorf("Clean error = %v, want %v", err, tt.want)
			}
		})
	}
}
