// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package format

import (
	"errors"
	"strings"
	"testing"

	"github.com/MuffinUser/nebel/internal/tag"
)

// Every construct the .env grammar accepts, once.
const envDoc = `# Application settings
APP_NAME=nebel

export DATABASE_PASSWORD=s3cr3t
API_TOKEN="tok \"quoted\" value"   # inline comment after quotes
SINGLE='raw $HOME "x"'
SPACED = with spaces   # trailing comment
HASH=abc#def
EMPTY=
EMPTY_COMMENT= # nothing here
EMPTY_QUOTED=""
export=not-a-prefix
	INDENTED=yes
MULTI="line one
line two"
DOTTED.KEY=dots-are-literal
`

// AC-5.9, AC-5.10, AC-5.22, AC-5.26-5.28: each key's span covers exactly
// the raw literal, quotes and comments outside it.
func TestEnvLocate(t *testing.T) {
	h, err := For("prod.env")
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct{ key, want string }{
		{"APP_NAME", "nebel"},
		{"DATABASE_PASSWORD", "s3cr3t"},
		{"API_TOKEN", `tok \"quoted\" value`},
		{"SINGLE", `raw $HOME "x"`},
		{"SPACED", "with spaces"},
		{"HASH", "abc#def"},
		{"EMPTY", ""},
		{"EMPTY_COMMENT", ""},
		{"EMPTY_QUOTED", ""},
		{"export", "not-a-prefix"},
		{"INDENTED", "yes"},
		{"DOTTED.KEY", "dots-are-literal"},
	} {
		t.Run(tt.key, func(t *testing.T) {
			span, err := h.Locate([]byte(envDoc), tt.key)
			if err != nil {
				t.Fatalf("Locate(%q): %v", tt.key, err)
			}
			if got := envDoc[span.Start:span.End]; got != tt.want {
				t.Errorf("span covers %q, want %q", got, tt.want)
			}
			if span.Value != tt.want || span.Type != tag.TypeStr {
				t.Errorf("Value, Type = %q, %q; want %q, str", span.Value, span.Type, tt.want)
			}
		})
	}
}

// A shell would concatenate two adjacent quoted strings, but dotenv
// doesn't: text after the closing quote is malformed.
func TestEnvRejectsTextAfterClosingQuote(t *testing.T) {
	h, _ := For("prod.env")
	for _, src := range []string{"A='it''s'\n", "A=\"x\"y\n"} {
		if _, err := h.Locate([]byte(src), "A"); !errors.Is(err, ErrMalformed) {
			t.Errorf("Locate in %q error = %v, want %v", src, err, ErrMalformed)
		}
	}
}

// AC-5.1: replacing every locatable value with a tag and back leaves the
// file byte-identical, in LF and CRLF.
func TestEnvSpliceRoundTrip(t *testing.T) {
	for name, src := range map[string]string{"LF": envDoc, "CRLF": strings.ReplaceAll(envDoc, "\n", "\r\n")} {
		t.Run(name, func(t *testing.T) {
			h, _ := For("prod.env")
			leaves, err := h.Leaves([]byte(src))
			if err != nil {
				t.Fatal(err)
			}

			var edits []Edit
			for _, leaf := range leaves {
				span, err := h.Locate([]byte(src), leaf.Path)
				if err != nil {
					t.Fatalf("Locate(%q): %v", leaf.Path, err)
				}
				edits = append(edits, Edit{Span: span, Text: mustRender(t, h, "ENC[AES256_SIV,key:1,data:QUJD+/==,type:str]", tag.TypeStr)})
			}
			cleaned, err := Splice([]byte(src), edits)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(cleaned), `API_TOKEN="ENC[`) || !strings.Contains(string(cleaned), `SINGLE='ENC[`) ||
				!strings.Contains(string(cleaned), "EMPTY_COMMENT=ENC[AES256_SIV,key:1,data:QUJD+/==,type:str] # nothing here") {
				t.Errorf("quotes or comments not preserved around tags:\n%s", cleaned)
			}

			// Reverse: each tag must be found again and give back the
			// original literal at the same key.
			edits = nil
			for _, leaf := range leaves {
				span, err := h.Locate(cleaned, leaf.Path)
				if err != nil {
					t.Fatalf("Locate(%q) after clean: %v", leaf.Path, err)
				}
				if !tag.IsEncrypted([]byte(span.Value)) {
					t.Fatalf("%s: tag not found after clean, got %q", leaf.Path, span.Value)
				}
				if err := h.CheckLiteral(span, leaf.Value); err != nil {
					t.Errorf("%s: CheckLiteral(%q): %v", leaf.Path, leaf.Value, err)
				}
				edits = append(edits, Edit{Span: span, Text: mustRender(t, h, leaf.Value, tag.TypeStr)})
			}
			restored, err := Splice(cleaned, edits)
			if err != nil {
				t.Fatal(err)
			}
			if string(restored) != src {
				t.Errorf("round trip changed the file:\n got  = %q\n want = %q", restored, src)
			}
		})
	}
}

// AC-5.19, AC-5.20, AC-5.21, AC-5.29: refusals.
func TestEnvLocateErrors(t *testing.T) {
	for _, tt := range []struct {
		name, src, key string
		want           error
	}{
		{"missing", "A=1\n", "B", ErrNotFound},
		{"duplicate", "A=1\nB=2\nA=3\n", "A", ErrDuplicateKey},
		{"duplicate via export", "A=1\nexport A=2\n", "A", ErrDuplicateKey},
		{"multi-line quoted", "A=\"x\ny\"\n", "A", ErrMultiline},
		{"unterminated quote", "A='x\n", "A", ErrMalformed},
		{"no equals", "A 1\n", "A", ErrMalformed},
		{"no key", "=1\n", "A", ErrMalformed},
		{"export without assignment", "export A\n", "A", ErrMalformed},
		{"lone CR", "A=1\rB=2\n", "A", ErrMalformed},
		{"garbage line hides nothing", "A=1\nthis is not an entry\n", "A", ErrMalformed},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h, _ := For("prod.env")
			if _, err := h.Locate([]byte(tt.src), tt.key); !errors.Is(err, tt.want) {
				t.Errorf("Locate(%q) error = %v, want %v", tt.key, err, tt.want)
			}
		})
	}
}

// AC-5.20: a KEY= line inside a multi-line quoted value isn't an entry
// here, but a reader without multi-line quotes takes it for one, and its
// value would win over the encrypted one. So it counts as a duplicate,
// and a key found only there can't be located. Other inner lines, like a
// PEM body, are ignored.
func TestEnvMultilineInnerLines(t *testing.T) {
	for _, tt := range []struct {
		name, src, key string
		want           error
	}{
		{"hidden after real", "PASSWORD=outer\nKEY='\nPASSWORD=inner\n'\n", "PASSWORD", ErrDuplicateKey},
		{"hidden before real", "KEY=\"-----BEGIN-----\nexport PASSWORD=inner\n-----END-----\"\nPASSWORD=outer\n", "PASSWORD", ErrDuplicateKey},
		{"only hidden", "KEY=\"\nPASSWORD=inner\n\"\n", "PASSWORD", ErrMultiline},
		{"PEM body ignored", "KEY=\"-----BEGIN-----\nMIIBIjAN BgkqhkiG9w0BAQ==\n-----END-----\"\nPASSWORD=outer\n", "PASSWORD", nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h, _ := For("prod.env")
			if _, err := h.Locate([]byte(tt.src), tt.key); !errors.Is(err, tt.want) {
				t.Errorf("Locate(%q) error = %v, want %v", tt.key, err, tt.want)
			}
		})
	}
}

// AC-5.19: environment variable names are case-insensitive on Windows, so
// keys differing only in case are duplicates, and the picker skips both.
func TestEnvCaseInsensitiveDuplicates(t *testing.T) {
	src := []byte("SECRET=a\nsecret=b\nOTHER=c\n")
	h, _ := For(".env")
	_, err := h.Locate(src, "SECRET")
	if !errors.Is(err, ErrDuplicateKey) || !strings.Contains(err.Error(), `"SECRET", "secret"`) {
		t.Errorf("Locate error = %v, want %v naming both spellings", err, ErrDuplicateKey)
	}
	leaves, err := h.Leaves(src)
	if err != nil || len(leaves) != 1 || leaves[0].Path != "OTHER" {
		t.Errorf("Leaves = %+v, %v; want only OTHER", leaves, err)
	}
}

// AC-5.18: a BOM is not part of the first key, and survives.
func TestEnvBOM(t *testing.T) {
	src := "\xEF\xBB\xBFA=1\n"
	h, _ := For(".env")
	span, err := h.Locate([]byte(src), "A")
	if err != nil {
		t.Fatalf("Locate: %v", err)
	}
	if src[span.Start:span.End] != "1" {
		t.Errorf("span covers %q", src[span.Start:span.End])
	}
}

// AC-5.24: Leaves lists locatable entries only, in source order.
func TestEnvLeaves(t *testing.T) {
	src := "A=1\nB=2\nB=3\nC=\"x\ny\"\nD='four'\n"
	h, _ := For(".env.local")
	leaves, err := h.Leaves([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, l := range leaves {
		got = append(got, l.Path+"="+l.Value)
	}
	if strings.Join(got, ",") != "A=1,D=four" {
		t.Errorf("Leaves() = %v, want [A=1 D=four]", got)
	}
}

// AC-5.25: a literal that doesn't fit the quoting its tag now sits in is
// refused instead of being written out as a different value.
func TestEnvCheckLiteral(t *testing.T) {
	h, _ := For("prod.env")
	locate := func(src string) Span {
		t.Helper()
		span, err := h.Locate([]byte(src), "A")
		if err != nil {
			t.Fatal(err)
		}
		return span
	}
	bare, spaced, single, double := locate("A=x\n"), locate("A= x\n"), locate("A='x'\n"), locate("A=\"x\"\n")

	for _, tt := range []struct {
		name  string
		span  Span
		value string
		ok    bool
	}{
		{"bare plain", bare, "p$ss#word", true},
		{"bare empty", bare, "", true},
		{"bare newline", bare, "a\nB=injected", false},
		{"bare CR", bare, "a\rb", false},
		{"bare comment", bare, "a #b", false},
		{"bare leading quote", bare, "'a'", false},
		{"bare surrounding space", bare, " a", false},
		{"bare leading hash ok", bare, "#a", true},
		{"spaced leading hash", spaced, "#a", false},
		{"single plain", single, `a "b" \c`, true},
		{"single quote", single, "it's", false},
		{"double escaped", double, `a \"b\"`, true},
		{"double unescaped", double, `a "b"`, false},
		{"double trailing backslash", double, `a\`, false},
		{"double comment ok", double, "a #b", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := h.CheckLiteral(tt.span, tt.value)
			if tt.ok && err != nil {
				t.Errorf("CheckLiteral(%q) = %v, want nil", tt.value, err)
			}
			if !tt.ok && !errors.Is(err, ErrLiteralContext) {
				t.Errorf("CheckLiteral(%q) = %v, want %v", tt.value, err, ErrLiteralContext)
			}
		})
	}
}

func mustRender(t *testing.T, h Handler, value string, typ tag.Type) string {
	t.Helper()
	out, err := h.Render(value, typ)
	if err != nil {
		t.Fatalf("Render(%q): %v", value, err)
	}
	return out
}

// AC-5.34: whitespace inside the quotes is part of the value, so around a
// tag it is refused rather than encrypting the tag text on the next clean.
func TestEnvWhitespaceAroundQuotedTag(t *testing.T) {
	h, _ := For(".env")
	tagged := "ENC[AES256_SIV_TB,key:1,data:" + strings.Repeat("A", 44) + ",type:str]"
	for _, src := range []string{`PW="` + tagged + ` "`, `PW=' ` + tagged + `'`} {
		if _, err := h.Locate([]byte(src+"\n"), "PW"); !errors.Is(err, ErrMalformed) {
			t.Errorf("Locate(%s) error = %v, want %v", src, err, ErrMalformed)
		}
	}
	if _, err := h.Locate([]byte("PW=\" secret \"\n"), "PW"); err != nil {
		t.Errorf("whitespace in a quoted plaintext value: %v", err)
	}
}
