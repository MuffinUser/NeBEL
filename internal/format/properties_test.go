// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package format

import (
	"errors"
	"strings"
	"testing"

	"github.com/MuffinUser/nebel/internal/tag"
)

// Every construct the .properties syntax accepts, once.
const propertiesDoc = `# Application settings
! also a comment
database.url=jdbc:postgresql://db/app
database.password = s3cr3t
api.token:tok_live
spaced   value with spaces
trailing=keeps trailing   
escaped=café \t tab
my\ key=escaped key
a..b=dotted
empty=
blank.sep 
   indented=yes
long=first \
     second
`

// AC-5.11, AC-5.12, AC-5.22, AC-5.30-5.32: each key's span covers exactly
// the raw literal; separators and leading whitespace stay outside it.
func TestPropertiesLocate(t *testing.T) {
	h, err := For("app.properties")
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct{ key, want string }{
		{"database.url", "jdbc:postgresql://db/app"},
		{"database.password", "s3cr3t"},
		{"api.token", "tok_live"},
		{"spaced", "value with spaces"},
		{"trailing", "keeps trailing   "},
		{"escaped", `café \t tab`},
		{"my key", "escaped key"},
		{"a..b", "dotted"},
		{"empty", ""},
		{"blank.sep", ""},
		{"indented", "yes"},
	} {
		t.Run(tt.key, func(t *testing.T) {
			span, err := h.Locate([]byte(propertiesDoc), tt.key)
			if err != nil {
				t.Fatalf("Locate(%q): %v", tt.key, err)
			}
			if got := propertiesDoc[span.Start:span.End]; got != tt.want {
				t.Errorf("span covers %q, want %q", got, tt.want)
			}
			if span.Value != tt.want || span.Type != tag.TypeStr {
				t.Errorf("Value, Type = %q, %q; want %q, str", span.Value, span.Type, tt.want)
			}
		})
	}
}

// AC-5.1: every locatable value replaced by a tag and back leaves the file
// byte-identical, with LF, CRLF and lone-CR line endings.
func TestPropertiesSpliceRoundTrip(t *testing.T) {
	for name, src := range map[string]string{
		"LF":   propertiesDoc,
		"CRLF": strings.ReplaceAll(propertiesDoc, "\n", "\r\n"),
		"CR":   strings.ReplaceAll(propertiesDoc, "\n", "\r"),
	} {
		t.Run(name, func(t *testing.T) {
			h, _ := For("app.properties")
			leaves, err := h.Leaves([]byte(src))
			if err != nil {
				t.Fatal(err)
			}
			if len(leaves) != 11 {
				t.Fatalf("Leaves() found %d entries, want 11: %+v", len(leaves), leaves)
			}

			const enc = "ENC[AES256_SIV,key:1,data:QUJD+/==,type:str]"
			var edits []Edit
			for _, leaf := range leaves {
				span, err := h.Locate([]byte(src), leaf.Path)
				if err != nil {
					t.Fatalf("Locate(%q): %v", leaf.Path, err)
				}
				edits = append(edits, Edit{Span: span, Text: mustRender(t, h, enc, tag.TypeStr)})
			}
			cleaned, err := Splice([]byte(src), edits)
			if err != nil {
				t.Fatal(err)
			}

			edits = nil
			for _, leaf := range leaves {
				span, err := h.Locate(cleaned, leaf.Path)
				if err != nil {
					t.Fatalf("Locate(%q) after clean: %v", leaf.Path, err)
				}
				if span.Value != enc {
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

// AC-5.13, AC-5.19, AC-5.20, AC-5.31, AC-5.33: refusals.
func TestPropertiesLocateErrors(t *testing.T) {
	for _, tt := range []struct {
		name, src, key string
		want           error
	}{
		{"missing", "a=1\n", "b", ErrNotFound},
		{"duplicate", "a=1\nb=2\na=3\n", "a", ErrDuplicateKey},
		{"duplicate via escape", "ab=1\na\\u0062=2\n", "ab", ErrDuplicateKey},
		{"duplicate via continued key", "a=1\na\\\n  =2\n", "a", ErrDuplicateKey},
		{"continuation", "a=one \\\n  two\n", "a", ErrMultiline},
		{"backslash at end of file", "a=one \\", "a", ErrMultiline},
		{"key only", "a\n", "a", ErrMalformed},
		{"bad unicode escape", "a\\u00zz=1\n", "a", ErrMalformed},
		{"lone CR splits entries", "a=1\rb=2\ra=3\n", "a", ErrDuplicateKey},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h, _ := For("app.properties")
			if _, err := h.Locate([]byte(tt.src), tt.key); !errors.Is(err, tt.want) {
				t.Errorf("Locate(%q) error = %v, want %v", tt.key, err, tt.want)
			}
		})
	}
}

// AC-5.20, AC-5.30: a continuation line is never read as an entry of its
// own, even when it looks like one; a comment line never continues.
func TestPropertiesContinuationAndComments(t *testing.T) {
	src := "note=see \\\n  password=inner\npassword=outer\n# comment \\\nother=1\n"
	h, _ := For("app.properties")
	span, err := h.Locate([]byte(src), "password")
	if err != nil {
		t.Fatalf("Locate: %v", err)
	}
	if span.Value != "outer" {
		t.Errorf("Value = %q, want %q", span.Value, "outer")
	}
	if _, err := h.Locate([]byte(src), "other"); err != nil {
		t.Errorf("a comment ending in a backslash swallowed the next line: %v", err)
	}
}

// AC-5.18: a BOM is not part of the first key.
func TestPropertiesBOM(t *testing.T) {
	h, _ := For("app.properties")
	if _, err := h.Locate([]byte("\xEF\xBB\xBFa=1\n"), "a"); err != nil {
		t.Errorf("Locate: %v", err)
	}
}

// AC-5.25: a literal Java would read back differently is refused.
func TestPropertiesCheckLiteral(t *testing.T) {
	h, _ := For("app.properties")
	locate := func(src string) Span {
		t.Helper()
		span, err := h.Locate([]byte(src), "a")
		if err != nil {
			t.Fatal(err)
		}
		return span
	}
	explicit, blank := locate("a=x\n"), locate("a x\n")

	for _, tt := range []struct {
		name  string
		span  Span
		value string
		ok    bool
	}{
		{"plain", explicit, `p#ss!wérd  `, true},
		{"empty", explicit, "", true},
		{"newline", explicit, "x\nb=injected", false},
		{"CR", explicit, "x\rb=injected", false},
		{"leading space", explicit, " x", false},
		{"trailing backslash", explicit, `x\`, false},
		{"even trailing backslashes", explicit, `x\\`, true},
		{"leading equals after =", explicit, "=x", true},
		{"leading equals after blank", blank, "=x", false},
		{"leading colon after blank", blank, ":x", false},
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

// AC-5.19: Java reads a key under the file's charset with escapes
// resolved, so spellings that differ in bytes can be one key at runtime.
// Each is a duplicate of the other, or the effective value could stay in
// plaintext.
func TestPropertiesCharsetAndEscapeDuplicates(t *testing.T) {
	for _, tt := range []struct {
		name, src, key string
	}{
		{"escape vs ISO-8859-1 byte", "p\\u00e4ss=one\np\xe4ss=two\n", "päss"},
		{"escape vs UTF-8 bytes", "p\\u00e4ss=one\npäss=two\n", "päss"},
		{"surrogate pair vs UTF-8 bytes", "\\uD83D\\uDE00=one\n😀=two\n", "😀"},
		{"escaped vs plain ASCII", "my\\ key=one\nmy\\u0020key=two\n", "my key"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h, _ := For("app.properties")
			if _, err := h.Locate([]byte(tt.src), tt.key); !errors.Is(err, ErrDuplicateKey) {
				t.Errorf("Locate(%q) error = %v, want %v", tt.key, err, ErrDuplicateKey)
			}
			if leaves, _ := h.Leaves([]byte(tt.src)); len(leaves) != 0 {
				t.Errorf("Leaves = %+v, want none", leaves)
			}
		})
	}
}

// AC-5.31: a key is found under the spelling Java reads, whatever the
// file's charset, and distinct keys stay distinct.
func TestPropertiesKeySpellings(t *testing.T) {
	h, _ := For("app.properties")
	for _, tt := range []struct {
		name, src, key string
	}{
		{"ISO-8859-1 byte", "p\xe4ss=one\n", "päss"},
		{"UTF-8 bytes", "päss=one\n", "päss"},
		{"surrogate pair escape", "\\uD83D\\uDE00=one\n", "😀"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			span, err := h.Locate([]byte(tt.src), tt.key)
			if err != nil || span.Value != "one" {
				t.Errorf("Locate(%q) = %q, %v; want \"one\"", tt.key, span.Value, err)
			}
		})
	}

	// Different lone surrogates aren't both U+FFFD, so they aren't
	// mistaken for duplicates.
	leaves, err := h.Leaves([]byte("\\uD800=one\n\\uD801=two\n"))
	if err != nil || len(leaves) != 2 {
		t.Errorf("Leaves = %+v, %v; want two distinct keys", leaves, err)
	}
}
